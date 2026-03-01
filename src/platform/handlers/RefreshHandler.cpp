#include <handlers/RefreshHandler.h>
#include <Utils.h>

#include <Poco/StreamCopier.h>
#include <Poco/JSON/Parser.h>
#include <Poco/Util/Application.h>

namespace RGT::Auth 
{

void RefreshHandler::requestPreprocessing(Poco::Net::HTTPServerRequest & request)
{
    HTTPRequestHandler::checkContentLength(request, cfg_.getUInt32("max_request_body_size"));
}

std::any RefreshHandler::extractPayloadFromRequest(Poco::Net::HTTPServerRequest & request)
{
    std::shared_ptr<Poco::JSON::Object::Ptr> ppJsonObject = std::make_shared<Poco::JSON::Object::Ptr>(
        nullptr
    );

    // Извлекаем из запроса refresh-токен
    std::string refreshToken = HTTPRequestHandler::extractRefreshFromRequest(request, ppJsonObject);

    // Извлекаем из запроса UA. Читаем только из заголовка
    const std::string & userAgent = HTTPRequestHandler::extractValueFromHeaders(request, "User-Agent");

    // Извлекаем из запроса fingerprint
    std::string fingerprint = HTTPRequestHandler::extractFingerprintFromRequest(request, ppJsonObject);

    return RequiredPayload
    {
        .refreshToken = refreshToken,
        .userAgent = userAgent,
        .fingerprint = fingerprint
    };
}

void RefreshHandler::requestProcessing(Poco::Net::HTTPServerRequest & request, Poco::Net::HTTPServerResponse & response)
{
    RequiredPayload requiredPayload = std::any_cast<RequiredPayload>(payload_);
    
    std::string hashedRefreshToken = Auth::Utils::hashRefreshToken(requiredPayload.refreshToken);

    Poco::Redis::Array cmd;
    cmd << "EXISTS" << std::format("rtk:{}", hashedRefreshToken);
    Poco::Int64 int64ResultOfCmd; 
    {
        Poco::Redis::PooledConnection pc(redisPool_, cfg_.getUInt16("pooled_connection_timeout"));
        int64ResultOfCmd = static_cast<Poco::Redis::Client::Ptr>(pc)->execute<Poco::Int64>(cmd);
    }

    if (int64ResultOfCmd == 0) {
        throw RGT::Devkit::RGTException(std::format("Bad refresh token"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    // Сравниваем ua и fingerprint
    cmd.clear();
    cmd << "HMGET" << std::format("rtk:{}", hashedRefreshToken) << "fingerprint" << "ua" << "user_id";

    // TODO try catch ?
    Poco::Redis::Client::Ptr prcp = redisPool_.borrowObject(cfg_.getUInt16("pooled_connection_timeout"));
    Poco::Redis::Array rtkFileds = prcp->execute<Poco::Redis::Array>(cmd);
    redisPool_.returnObject(prcp);

    // Удаляем hash refresh-токена из ZSET и HSET
    Poco::UInt64 userId = std::stoull(rtkFileds.get<Poco::Redis::BulkString>(2).value());
    Auth::Utils::deleteRefreshFromRedis(redisPool_, hashedRefreshToken, userId);
    
    if (rtkFileds.get<Poco::Redis::BulkString>(0).value() != requiredPayload.fingerprint
        or rtkFileds.get<Poco::Redis::BulkString>(1).value() != requiredPayload.userAgent) 
    {
        throw RGT::Devkit::RGTException(std::format("Refresh token used from unauthorized device"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    std::string userRole;
    {
        Poco::Data::Session session = sessionPool_.get();
        Poco::Data::Statement stmt(session);
            
        stmt << "SELECT role FROM users WHERE id = $1",
            Poco::Data::Keywords::use(userId),
            Poco::Data::Keywords::into(userRole);
        
        if (stmt.execute() == 0) {
            throw RGT::Devkit::RGTException(std::format("Internal server error. Try repeating the request"), 
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
    }

    // Формируем полезную нагрузку для access-токена
    Poco::UInt16 accessTokenValidityPeriod = 
        Poco::Util::Application::instance().config().getUInt16("access_token_validity_period");
    RGT::Devkit::JWTPayload jwtPayload =
    {
        .sub = userId,
        .role = userRole,
        .exp = std::chrono::duration_cast<std::chrono::seconds>
        (
            (
                std::chrono::system_clock::now() + 
                std::chrono::seconds(accessTokenValidityPeriod)
            ).time_since_epoch()
        )
    };

    // Генерируем access и refresh токены
    std::string accessToken = Auth::Utils::createAccessToken(jwtPayload);
    std::string refreshToken = Auth::Utils::createRefreshToken();

    Auth::Utils::addRefreshToRedis(redisPool_, refreshToken, userId, requiredPayload.fingerprint, requiredPayload.userAgent);

    Poco::JSON::Object resultJson;
    resultJson.set("access_token", accessToken);
    resultJson.set("refresh_token", refreshToken);

    Poco::Net::HTTPCookie cookie("X-Refresh-token", refreshToken);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/"); // TODO наверное не стоит делать /
    cookie.setSameSite(Poco::Net::HTTPCookie::SAME_SITE_STRICT);

    response.addCookie(cookie);

    resultJson.stringify(response.send());
}

} // namespace RGT::Auth
