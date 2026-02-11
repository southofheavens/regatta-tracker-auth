#include <handlers/LoginHandler.h>
#include <Utils.h>

namespace
{

// Структура для содержимого запроса (заголовки + тело), которое
// необходимо для обработки запроса
struct RequestPayload
{
    std::string userAgent;
    std::string fingerprint;
    std::string login;
    std::string password;
};

/// @brief Валидирует запрос и извлекает содержимое, необходимое для его обработки
/// @param req ссылка на запрос
/// @return RequestPayload
/// @throw RGT::Devkit::RGTException при ошибке (отсутствует заголовок, 
///        отсутствует поле в запросе и т.д.)
RequestPayload validateRequestAndExtractPayload(Poco::Net::HTTPServerRequest & req, Poco::Util::LayeredConfiguration & cfg)
{
    Poco::JSON::Object::Ptr jsonObject = RGT::Auth::Utils::extractJsonObjectFromRequest(req);

    if (req.getContentLength64() > cfg.getUInt32("max_request_body_size", 1024 * 1024)) {
        throw RGT::Devkit::RGTException("Content size must not exceed 1 megabyte",
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    if (req.getContentLength() == 0) {
        throw RGT::Devkit::RGTException("Empty request body", 
            Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    if (req.getContentType().find("application/json") == std::string::npos) {
        throw RGT::Devkit::RGTException("Content-Type must be application/json", 
            Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
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

        try {
            fingerprint = jsonObject->get("fingerprint").extract<std::string>();
        }
        catch (...) {
            throw RGT::Devkit::RGTException("Expected to receive fingerprint in the headers/request body",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
    }

    std::map<std::string, Poco::Dynamic::Var> expectedKeysAndPotentialValues = 
    {
        {"login", {}},
        {"password", {}}
    };
    RGT::Auth::Utils::fillRequiredFieldsFromJson(jsonObject, expectedKeysAndPotentialValues);

    std::string login, password;
    try 
    {
        login = expectedKeysAndPotentialValues["login"].extract<std::string>();
        password = expectedKeysAndPotentialValues["password"].extract<std::string>();
    }
    catch (...) {
        throw RGT::Devkit::RGTException("Login and password must be presented in string format",
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    return RequestPayload
    {
        .userAgent = userAgent,
        .fingerprint = fingerprint,
        .login = login,
        .password = password
    };
}

} // namespace

namespace RGT::Auth
{

void LoginHandler::handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res)
try
{
    RequestPayload rp = validateRequestAndExtractPayload(req, cfg_);

    /// Смотрим, есть ли пользователь с таким логином && правильно ли введён пароль,
    /// если пользователь с таким логином существует    
    std::string hashedPassword, userRole;
    uint64_t userId;
    {
        Poco::Data::Session session = sessionPool_.get();
        Poco::Data::Statement stmt(session);

        stmt << "SELECT password, role, id FROM users WHERE login = $1",
            Poco::Data::Keywords::use(rp.login),
            Poco::Data::Keywords::into(hashedPassword),
            Poco::Data::Keywords::into(userRole),
            Poco::Data::Keywords::into(userId);

        if (stmt.execute() == 0) {
            throw RGT::Devkit::RGTException("Incorrect login or password", Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
        }
    }

    if (not Auth::Utils::verifyPassword(rp.password, hashedPassword)) {
        throw RGT::Devkit::RGTException("Incorrect login or password", Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    /* Проверяем, существует ли для данных UA и fingerprint refresh-токен */
    if (std::optional<std::string> potentionalRefreshHash
            = Auth::Utils::getHashRefreshTokenByUserData(redisPool_, userId, rp.fingerprint, rp.userAgent);
        potentionalRefreshHash.has_value()) 
    {
        // Удаляем хэш refresh-токена из Redis (т.к. дальше для данных UA и fingerprint
        // будет создан новый refresh-токен, а уже существующий мы не можем использовать
        // потому, что в Redis хранится хэш, а не сам токен)
        Auth::Utils::deleteRefreshFromRedis(redisPool_, potentionalRefreshHash.value(), userId);
    }

    /**
     * Формируем полезную нагрузку для access-токена
     */
    Devkit::Tokens::Payload jwtPayload =
    {
        .sub = userId,
        .role = userRole,
        .exp = std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + 
            Auth::Utils::access_token_validity_period).time_since_epoch())
    };

    /* Генерируем access и refresh токены */
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
catch (...)
{
    res.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
    RGT::Devkit::sendJsonResponse(res, "error", "Internal server error");
}

} // namespace RGT::Auth 
