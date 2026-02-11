#include <handlers/RegisterHandler.h>
#include <Utils.h>
#include <cctype>

namespace
{

/// Минимально допустимая длина логина
constexpr uint8_t minimum_login_length = 3;
/// Минимально допустимая длина пароля
constexpr uint8_t minimum_password_length = 8;

/// @brief Результат валидации логина
enum class ValidateLoginResult : uint8_t 
{
    CORRECT,           // Логин удовлетворяет требованиям
    INVALID_CHARACTER, // Обнаружен недопустимый символ
    INVALID_LENGTH     // Логин слишком короткий. Допустим логин от 3 символов
};

/// @brief Проверка удовлетворяет ли логин требованиям
/// @param login логин
/// @return ValidateLoginResult
/// @note Требования к логину:
/// @note - обязан содержать буквы латинского алфавита и может содержать цифры
/// @note - минимально допустимая длина - 3 символа
/// @details Чувствителен к регистру
ValidateLoginResult validateLogin(const std::string & login)
{
    if (login.length() < minimum_login_length) {
        return ValidateLoginResult::INVALID_LENGTH;
    }

    for (const unsigned char & c : login)
    {
        if (not std::isalnum(c)) {
            return ValidateLoginResult::INVALID_CHARACTER;
        }
    }
    return ValidateLoginResult::CORRECT;
}

/// @brief Результат валидации пароля
enum class ValidatePasswordResult : uint8_t 
{
    CORRECT,                // Пароль удовлетворяет требованиям
    INVALID_CHARACTER,      // Обнаружен недопустимый символ
    INVALID_LENGTH,         // Пароль слишком короткий. Допустим пароль от 8 символов
    MISSING_CAPITAL_LETTER, // Отсутствует заглавная буква
    MISSING_SPECIAL_CHAR    // Отсутствует спецсимвол
};

/// @brief Проверка удовлетворяет ли пароль требованиям 
/// @param password пароль
/// @return ValidatePasswordResult
/// @note Требования к паролю:
/// @note - может состоять из букв латинского алфавита, цифр и спецсимволов (~, !, @, #, $, &, *, -, _)
/// @note - обязан содержать хотя бы одну заглавную букву и хотя бы один спецсимвол
/// @note - минимально допустимая длина - 8 символов
ValidatePasswordResult validatePassword(const std::string & password)
{
    static std::unordered_set<char> specialCharacters = 
    {
        '~', '!', '@', '#', '$', '&', '*', '-', '_'
    };
    
    if (password.length() < minimum_password_length) {
        return ValidatePasswordResult::INVALID_LENGTH;
    }

    bool hasCapital = false;
    bool hasSpecialChar = false;
    for (const unsigned char & c : password)
    {
        if (isalpha(c))
        {
            if (isupper(c)) {
                hasCapital = true;
            }
        }
        else if (isdigit(c)) {
            continue;
        }
        else 
        {
            if (specialCharacters.find(c) != specialCharacters.end()) {
                hasSpecialChar = true;
            }
            else {
                return ValidatePasswordResult::INVALID_CHARACTER;
            }
        }
    }

    if (not hasCapital) {
        return ValidatePasswordResult::MISSING_CAPITAL_LETTER;
    }
    if (not hasSpecialChar) {
        return ValidatePasswordResult::MISSING_SPECIAL_CHAR;
    }
    return ValidatePasswordResult::CORRECT;
}

// Структура для содержимого запроса (заголовки + тело), которое
// необходимо для обработки запроса
struct RequestPayload
{
    std::string name;
    std::string surname;
    std::string role;
    std::string login;
    std::string password;
};

/// @brief Извлекает из запроса содержимое, необходимое для его обработки
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
    // Извлекаем из запроса содержимое, необходимое для его обработки
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
        throw RGT::Devkit::RGTException(std::format("User with login '{}' already exists", rp.login), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
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
