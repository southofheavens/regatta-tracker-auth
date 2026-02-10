#include <handlers/RegisterHandler.h>
#include <Utils.h>

namespace
{

// Структура для содержимого запроса (заголовки + тело), которое
// необходимо для обработки запроса
struct RequestPayload
{
    std::string userAgent;
    std::string fingerprint;
    std::string name;
    std::string surname;
    std::string role;
    std::string login;
    std::string password;
};

/// @brief Валидирует запрос и извлекает из него RequestPayload
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
        {"name", {}},
        {"surname", {}},
        {"role", {}},
        {"login", {}},
        {"password", {}}
    };
    RGT::Auth::Utils::fillRequiredFieldsFromJson(jsonObject, expectedKeysAndPotentialValues);

    auto extractString = [](const std::map<std::string, Poco::Dynamic::Var> & map)
    {
        std::map<std::string, std::string> result;
        for (const auto & [key, value] : map)
        {
            try {
                result[key] = value.extract<std::string>();
            }
            catch (...) {
                throw RGT::Devkit::RGTException(std::format("Field {} must be presented in string format", key),
                    Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            }
        }

        return result;
    };

    std::map<std::string, std::string> keysAndStringValues = extractString(expectedKeysAndPotentialValues);

    return RequestPayload
    {
        .userAgent = userAgent,
        .fingerprint = fingerprint,
        .name = keysAndStringValues["name"],
        .surname = keysAndStringValues["surname"],
        .role = keysAndStringValues["role"],
        .login = keysAndStringValues["login"],
        .password = keysAndStringValues["password"]
    };
}

} // namespace

namespace RGT::Auth
{

void RegisterHandler::handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res)
try
{
    RequestPayload rp = validateRequestAndExtractPayload(req, cfg_);

    if (rp.role != Auth::Utils::userRoles[0] and rp.role != Auth::Utils::userRoles[1]) {
        throw RGT::Devkit::RGTException(std::format("Invalid role. Correct roles is 'Participant' and 'Judge'"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    Poco::Data::Session session = sessionPool_.get();

    Poco::Data::Statement stmt(session);

    // Проверим существует ли пользователь с переданным логином

    int userExists = 0;
    stmt << "SELECT COUNT(*) FROM users WHERE login = $1",
        Poco::Data::Keywords::use(rp.login),
        Poco::Data::Keywords::into(userExists);
    stmt.execute();
    
    if (userExists != 0) {
        throw Poco::Exception("User already exists");
    }

    // Добавляем данные пользователя в БД
    std::string hashedPassword = Auth::Utils::hashPassword(rp.password);
    stmt.reset();
    stmt << "INSERT INTO users (name, surname, role, login, password)"
        << "VALUES ($1, $2, $3 , $4, $5)",
        Poco::Data::Keywords::use(rp.name),
        Poco::Data::Keywords::use(rp.surname),
        Poco::Data::Keywords::use(rp.role),
        Poco::Data::Keywords::use(rp.login),
        Poco::Data::Keywords::use(hashedPassword);
    stmt.execute();

    RGT::Devkit::sendJsonResponse(res, "OK", "OK");
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
