#include <handlers/RefreshHandler.h>
#include <Utils.h>

#include <Poco/StreamCopier.h>
#include <Poco/JSON/Parser.h>

namespace RGT::Auth 
{

void RefreshHandler::handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) 
try
{
    // Пробуем получить refresh token из куки
    Poco::Net::NameValueCollection cookies;
    req.getCookies(cookies); 

    std::string refreshToken;
    try {
        refreshToken = cookies["X-Refresh-token"]; 
    }
    catch (Poco::Exception & e)
    {
        if (req.getContentType().find("application/json") == std::string::npos) {
            throw RGT::Devkit::RGTException("Content-Type must be application/json",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }

        std::string jsonBody;
        Poco::StreamCopier::copyToString(req.stream(), jsonBody);
        
        Poco::JSON::Parser parser;
        Poco::Dynamic::Var result = parser.parse(jsonBody);
        Poco::JSON::Object::Ptr jsonObject = result.extract<Poco::JSON::Object::Ptr>();
        
        if (not jsonObject->has("refresh_token")) {
            throw RGT::Devkit::RGTException("Expected to receive refresh token "
                "in the cookie/request body",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }

        refreshToken = (jsonObject->get("refresh_token")).convert<std::string>();
    }

    /* ua читаем только из заголовка */
    if (not req.has("User-Agent")) {
        throw RGT::Devkit::RGTException(std::format("User-Agent header was not received"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
    std::string userAgent = req.get("User-Agent");

    /* Если заголовок Fingerprint пуст, пытаемся считать fingerprint из тела запроса */
    Poco::JSON::Object::Ptr jsonObject = Auth::Utils::extractJsonObjectFromRequest(req);
    std::string fingerprint;
    if (not req.has("X-Fingerprint"))
    {
        if (not jsonObject->has("fingerprint")) {
            throw RGT::Devkit::RGTException(std::format("Expected fingerprint from json body or X-Fingerprint header"), 
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
        fingerprint = (jsonObject->get("fingerprint")).extract<std::string>();
    }
    else {
        fingerprint = req.get("X-Fingerprint");
    }
    
    std::string hashedRefreshToken = Auth::Utils::hashRefreshToken(refreshToken);

    Poco::Redis::Array cmd;
    cmd << "EXISTS" << std::format("rtk:{}", hashedRefreshToken);
    Poco::Int64 int64ResultOfCmd; 
    {
        Poco::Redis::PooledConnection pc(redisPool_, cfg_.getUInt16("pooled_connection_timeout", 500));
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
    Poco::Redis::Client::Ptr prcp = redisPool_.borrowObject(cfg_.getUInt16("pooled_connection_timeout", 500));
    Poco::Redis::Array rtkFileds = prcp->execute<Poco::Redis::Array>(cmd);
    redisPool_.returnObject(prcp);

    // Удаляем hash refresh-токена из ZSET и HSET
    Poco::UInt64 userId = std::stoull(rtkFileds.get<Poco::Redis::BulkString>(2).value());
    Auth::Utils::deleteRefreshFromRedis(redisPool_, hashedRefreshToken, userId);
    
    if (rtkFileds.get<Poco::Redis::BulkString>(0).value() != fingerprint
        or rtkFileds.get<Poco::Redis::BulkString>(1).value() != userAgent) 
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
    Devkit::Tokens::Payload jwtPayload =
    {
        .sub = userId,
        .role = userRole,
        .exp = std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + 
            Auth::Utils::access_token_validity_period).time_since_epoch())
    };

    // Генерируем access и refresh токены
    std::string accessToken = Auth::Utils::createAccessToken(jwtPayload);
    refreshToken = Auth::Utils::createRefreshToken();

    Auth::Utils::addRefreshToRedis(redisPool_, refreshToken, userId, fingerprint, userAgent);

    Poco::JSON::Object resultJson;
    resultJson.set("access_token", accessToken);
    resultJson.set("refresh_token", refreshToken);

    Poco::Net::HTTPCookie cookie("X-Refresh-token", refreshToken);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/"); // TODO наверное не стоит делать /
    cookie.setSameSite(Poco::Net::HTTPCookie::SAME_SITE_STRICT);

    res.addCookie(cookie);

    resultJson.stringify(res.send());
}
catch (const RGT::Devkit::RGTException & e)
{
    res.setStatusAndReason(e.status());
    RGT::Devkit::sendJsonResponse(res, "error", e.what());
}
catch (...)
{
    res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    RGT::Devkit::sendJsonResponse(res, "error", "Internal server error");
}

} // namespace RGT::Auth
