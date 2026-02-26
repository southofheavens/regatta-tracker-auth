#include <handlers/LoginHandler.h>
#include <Utils.h>
#include <Poco/Util/Application.h>
#include <rgt/devkit/RequestProcessing.h>

namespace
{

/// @brief Примитивная валидация запроса
/// @param req ссылка на запрос
/// @param cfg ссылка на конфиг
/// @throw RGT::Devkit::RGTException если запрос некорректен
void primitiveRequestValidate(Poco::Net::HTTPServerRequest & req, Poco::Util::LayeredConfiguration & cfg)
{
    RGT::Devkit::checkContentLength(req, cfg.getUInt32("max_request_body_size", 1024 * 1024));
    RGT::Devkit::checkContentLengthIsNull(req);
    RGT::Devkit::checkContentType(req, "application/json");
}

// Структура для содержимого запроса (заголовки + тело), которое
// необходимо для обработки запроса
struct RequestPayload
{
    std::string userAgent;
    std::string fingerprint;
    std::string login;
    std::string password;
};

/// @brief Извлекает из запроса содержимое, необходимое для его обработки
/// @param req ссылка на запрос
/// @param cfg ссылка на конфиг
/// @return RequestPayload
/// @throw RGT::Devkit::RGTException при ошибке (отсутствует заголовок, 
///        отсутствует поле в запросе и т.д.)
RequestPayload extractPayloadFromRequest(Poco::Net::HTTPServerRequest & req, Poco::Util::LayeredConfiguration & cfg)
{
    Poco::JSON::Object::Ptr jsonObject = RGT::Auth::Utils::extractJsonObjectFromRequest(req);

    // Пытаемся извлечь из запроса UA. Читаем только из заголовка
    const std::string & userAgent = RGT::Devkit::extractValueFromHeaders(req, "User-Agent");
    
    // Пытаемся извлечь из запроса fingerprint
    std::string fingerprint;
    try {
        fingerprint = RGT::Devkit::extractValueFromHeaders(req, "X-Fingerprint");
    }
    catch (...) 
    {
        Poco::Dynamic::Var dynamicVarFingerprint = RGT::Devkit::extractValueFromJson(jsonObject, "fingerprint");
        try {
            fingerprint = dynamicVarFingerprint.extract<std::string>();
        }
        catch (...) {
            throw RGT::Devkit::RGTException("Fingerprint type is not equal string", 
                Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST); 
        }
    }

    Poco::Dynamic::Var dvLogin = RGT::Devkit::extractValueFromJson(jsonObject, "login");
    Poco::Dynamic::Var dvPassword = RGT::Devkit::extractValueFromJson(jsonObject, "password");

    std::string login, password;
    try 
    {
        login = dvLogin.extract<std::string>();
        password = dvLogin.extract<std::string>();
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
    // Проводим примитивную валидацию запроса 
    primitiveRequestValidate(req, cfg_);
    // Извлекаем из запроса содержимое, необходимое для его обработки
    RequestPayload rp = extractPayloadFromRequest(req, cfg_);

    /// Смотрим, есть ли пользователь с таким логином && правильно ли введён пароль,
    /// если пользователь с таким логином существует    
    std::string hashedPassword, userRole;
    uint64_t userId;
    {
        Poco::Data::Session session = sessionPool_.get();
        Poco::Data::Statement stmt(session);

        stmt << "SELECT password_hash, role, id FROM users WHERE login = $1",
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

    // Проверяем, существует ли для данных UA и fingerprint refresh-токен
    if (std::optional<std::string> potentionalRefreshHash
            = Auth::Utils::getHashRefreshTokenByUserData(redisPool_, userId, rp.fingerprint, rp.userAgent);
        potentionalRefreshHash.has_value()) 
    {
        // Удаляем хэш refresh-токена из Redis (т.к. дальше для данных UA и fingerprint
        // будет создан новый refresh-токен, а уже существующий мы не можем использовать
        // потому, что в Redis хранится хэш, а не сам токен)
        Auth::Utils::deleteRefreshFromRedis(redisPool_, potentionalRefreshHash.value(), userId);
    }

    // Формируем полезную нагрузку для access-токена
    Poco::UInt16 accessTokenValidityPeriod = 
        Poco::Util::Application::instance().config().getUInt16("access_token_validity_period", 900);
    Devkit::Tokens::Payload jwtPayload =
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
    res.setContentType("application/json");

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
