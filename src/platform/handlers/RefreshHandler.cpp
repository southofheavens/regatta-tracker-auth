#include <handlers/RefreshHandler.h>
#include <Utils.h>

#include <Poco/StreamCopier.h>
#include <Poco/JSON/Parser.h>

namespace
{

// Структура для содержимого запроса (заголовки + тело), которое
// необходимо для обработки запроса
struct RequestPayload
{
    std::string refreshToken;
    std::string userAgent;
    std::string fingerprint;
};

/// @brief Валидирует запрос и извлекает из него RequestPayload
/// @param req ссылка на запрос
/// @return RequestPayload
/// @throw RGT::Devkit::RGTException при ошибке (отсутствует заголовок, 
///        отсутствует поле в запросе и т.д.)
RequestPayload validateRequestAndExtractPayload(Poco::Net::HTTPServerRequest & req, Poco::Util::LayeredConfiguration & cfg)
{
    Poco::JSON::Object::Ptr jsonObject = nullptr;

    if (req.getContentLength64() > cfg.getUInt32("max_request_body_size", 1024 * 1024)) {
        throw RGT::Devkit::RGTException("Content size must not exceed 1 megabyte",
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    // Пытаемся извлечь из запроса refresh-токен
    Poco::Net::NameValueCollection cookies;
    req.getCookies(cookies); 

    std::string refreshToken;
    try {
        refreshToken = cookies["X-Refresh-token"]; 
    }
    catch (Poco::Exception & e)
    {
        if (req.getContentType().find("application/json") == std::string::npos) {
            throw RGT::Devkit::RGTException("Refresh token missing in headers; request body is not application/json",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }

        jsonObject = RGT::Auth::Utils::extractJsonObjectFromRequest(req);
        
        try {
            refreshToken = jsonObject->get("refresh_token").extract<std::string>();
        }
        catch (...) {
            throw RGT::Devkit::RGTException("Expected to receive refresh token in the cookie/request body",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
    }

    // Пытаемся извлечь из запроса UA. Читаем только из заголовка
    std::string userAgent;
    try {
        userAgent = req.get("User-Agent");
    }
    catch (...) {
        throw RGT::Devkit::RGTException(std::format("User-Agent header was not received"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    // Пытаемся извлечь из запроса fingerprint
    std::string fingerprint;
    try {
        fingerprint = req.get("X-Fingerprint");
    }
    catch (...) 
    {
        if (req.getContentType().find("application/json") == std::string::npos) {
            throw RGT::Devkit::RGTException("Fingerprint missing in headers; request body is not application/json",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }

        if (jsonObject.isNull()) {
            jsonObject = RGT::Auth::Utils::extractJsonObjectFromRequest(req);
        }

        try {
            fingerprint = jsonObject->get("fingerprint").extract<std::string>();
        }
        catch (...) {
            throw RGT::Devkit::RGTException("Expected to receive fingerprint in the headers/request body",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
    }

    return RequestPayload
    {
        .refreshToken = refreshToken,
        .userAgent = userAgent,
        .fingerprint = fingerprint
    };
}

} // namespace

namespace RGT::Auth 
{

void RefreshHandler::handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) 
try
{
    RequestPayload rp = validateRequestAndExtractPayload(req, cfg_);
    
    std::string hashedRefreshToken = Auth::Utils::hashRefreshToken(rp.refreshToken);

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
    
    if (rtkFileds.get<Poco::Redis::BulkString>(0).value() != rp.fingerprint
        or rtkFileds.get<Poco::Redis::BulkString>(1).value() != rp.userAgent) 
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
    std::string refreshToken = Auth::Utils::createRefreshToken();

    Auth::Utils::addRefreshToRedis(redisPool_, refreshToken, userId, rp.fingerprint, rp.userAgent);

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
#ifdef __RGT_DEBUG__
catch (const std::exception & e)
{
    RGT::Devkit::sendJsonResponse(res, "error", e.what());
}
#endif
catch (...)
{
    res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    RGT::Devkit::sendJsonResponse(res, "error", "Internal server error");
}

} // namespace RGT::Auth
