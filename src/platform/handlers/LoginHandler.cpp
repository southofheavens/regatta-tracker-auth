#include <handlers/LoginHandler.h>
#include <Utils.h>
#include <Poco/Util/Application.h>

namespace RGT::Auth
{

void LoginHandler::requestPreprocessing(Poco::Net::HTTPServerRequest & request)
{
    HTTPRequestHandler::checkContentLength(request, cfg_.getUInt32("max_request_body_size"));
    HTTPRequestHandler::checkContentLengthIsNull(request);
    HTTPRequestHandler::checkContentType(request, "application/json");
}

std::any LoginHandler::extractPayloadFromRequest(Poco::Net::HTTPServerRequest & request)
{
    std::shared_ptr<Poco::JSON::Object::Ptr> ppJsonObject = std::make_shared<Poco::JSON::Object::Ptr>(
        HTTPRequestHandler::extractJsonObjectFromRequest(request)
    );

    // Извлекаем из запроса UA. Читаем только из заголовка
    const std::string & userAgent = HTTPRequestHandler::extractValueFromHeaders(request, "User-Agent");
    
    // Извлекаем из запроса fingerprint
    std::string fingerprint = HTTPRequestHandler::extractFingerprintFromRequest(request, ppJsonObject);

    Poco::Dynamic::Var dvLogin = HTTPRequestHandler::extractValueFromJson(*ppJsonObject, "login");
    Poco::Dynamic::Var dvPassword = HTTPRequestHandler::extractValueFromJson(*ppJsonObject, "password");

    std::string login, password;
    try 
    {
        login = dvLogin.extract<std::string>();
        password = dvPassword.extract<std::string>();
    }
    catch (...) {
        throw RGT::Devkit::RGTException("Login and password must be presented in string format",
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    return RequiredPayload
    {
        .userAgent = userAgent,
        .fingerprint = fingerprint,
        .login = login,
        .password = password
    };
}

void LoginHandler::requestProcessing(Poco::Net::HTTPServerRequest & request, Poco::Net::HTTPServerResponse & response)
{
    RequiredPayload requiredPayload = std::any_cast<RequiredPayload>(payload_);

    /// Смотрим, есть ли пользователь с таким логином && правильно ли введён пароль,
    /// если пользователь с таким логином существует    
    std::string hashedPassword, userRole;
    uint64_t userId;
    {
        Poco::Data::Session session = sessionPool_.get();
        Poco::Data::Statement stmt(session);

        stmt << "SELECT password_hash, role, id FROM users WHERE login = $1",
            Poco::Data::Keywords::use(requiredPayload.login),
            Poco::Data::Keywords::into(hashedPassword),
            Poco::Data::Keywords::into(userRole),
            Poco::Data::Keywords::into(userId);

        if (stmt.execute() == 0) {
            throw RGT::Devkit::RGTException("Incorrect login or password", 
                Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
        }
    }

    if (not Auth::Utils::verifyPassword(requiredPayload.password, hashedPassword)) {
        throw RGT::Devkit::RGTException("Incorrect login or password", 
            Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
    }

    // Проверяем, существует ли для данных UA и fingerprint refresh-токен
    if 
    (
        std::optional<std::string> potentionalRefreshHash
            = Auth::Utils::getHashRefreshTokenByUserData(redisPool_, userId, requiredPayload.fingerprint, 
                requiredPayload.userAgent);
        potentionalRefreshHash.has_value()
    ) 
    {
        // Удаляем хэш refresh-токена из Redis (т.к. дальше для данных UA и fingerprint
        // будет создан новый refresh-токен, а уже существующий мы не можем использовать
        // потому, что в Redis хранится хэш, а не сам токен)
        Auth::Utils::deleteRefreshFromRedis(redisPool_, potentionalRefreshHash.value(), userId);
    }

    // Формируем полезную нагрузку для access-токена
    Poco::UInt16 accessTokenValidityPeriod = cfg_.getUInt16("access_token_validity_period");
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

    Auth::Utils::addRefreshToRedis(redisPool_, refreshToken, userId, 
        requiredPayload.fingerprint, requiredPayload.userAgent);

    Poco::JSON::Object resultJson;
    resultJson.set("access_token", accessToken);
    resultJson.set("refresh_token", refreshToken);

    Poco::Net::HTTPCookie cookie("X-Refresh-token", refreshToken);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/"); // TODO наверное не стоит делать /
    cookie.setSameSite(Poco::Net::HTTPCookie::SAME_SITE_STRICT);

    response.addCookie(cookie);
    response.setContentType("application/json");

    resultJson.stringify(response.send());
}

} // namespace RGT::Auth 
