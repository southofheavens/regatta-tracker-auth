#include <handlers/RegisterHandler.h>
#include <Utils.h>
#include <cctype>

namespace
{

/// @brief Проверка удовлетворяет ли логин требованиям
/// @param login логин
/// @note Требования к логину:
/// @note - обязан содержать буквы латинского алфавита и может содержать цифры
/// @note - минимально допустимая длина - 3 символа
/// @throw RGT::Devkit::RGTException если логин не удовлетворяет требованиям
/// @details Логин чувствителен к регистру
void validateLogin(const std::string & login)
{
    /// Минимально допустимая длина логина
    static constexpr uint8_t minimum_login_length = 3;

    if (login.length() < minimum_login_length) {
        throw RGT::Devkit::RGTException(std::format("The minimum login length is {} characters", minimum_login_length),
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    for (const char & c : login)
    {
        if (not std::isalnum(static_cast<unsigned char>(c))) {
            throw RGT::Devkit::RGTException("The login contains an invalid character",
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
    }
}

/// @brief Проверка удовлетворяет ли пароль требованиям 
/// @param password пароль
/// @note Требования к паролю:
/// @note - может состоять из букв латинского алфавита, цифр и спецсимволов (~, !, @, #, $, &, *, -, _)
/// @note - обязан содержать хотя бы одну заглавную букву и хотя бы один спецсимвол
/// @note - минимально допустимая длина - 8 символов
/// @throw RGT::Devkit::RGTException если пароль не удовлетворяет требованиям
void validatePassword(const std::string & password)
{
    /// Минимально допустимая длина пароля
    static constexpr uint8_t minimum_password_length = 8;

    static std::unordered_set<char> specialCharacters = 
    {
        '~', '!', '@', '#', '$', '&', '*', '-', '_'
    };
    
    if (password.length() < minimum_password_length) {
        throw RGT::Devkit::RGTException(std::format("The minimum password length is {} characters", 
            minimum_password_length), Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    bool hasCapital = false;
    bool hasSpecialChar = false;
    for (const char & c : password)
    {
        unsigned char unsig_c = static_cast<unsigned char>(c);
        if (isalpha(unsig_c))
        {
            if (isupper(unsig_c)) {
                hasCapital = true;
            }
        }
        else if (isdigit(unsig_c)) {
            continue;
        }
        else 
        {
            if (specialCharacters.find(unsig_c) != specialCharacters.end()) {
                hasSpecialChar = true;
            }
            else {
                throw RGT::Devkit::RGTException("The password contains an invalid character",
                    Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
            }
        }
    }

    if (not hasCapital) {
        throw RGT::Devkit::RGTException("The password is missing a capital letter",
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
    if (not hasSpecialChar) {
        throw RGT::Devkit::RGTException("The password is missing a special character",
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
}

/// @brief Проверка удовлетворяет ли роль требованиям 
/// @param role роль
/// @note Требования к роли:
/// @note - роль может быть либо 'Participant' (участник), либо 'Judge' (судья)
/// @throw RGT::Devkit::RGTException если роль не удовлетворяет требованиям
void validateRole(const std::string & role)
{
    static const std::array<std::string, 2> userRoles = {"Participant", "Judge"};

    if (role != userRoles[0] and role != userRoles[1]) {
        throw RGT::Devkit::RGTException(std::format("Invalid role. Correct roles is 'Participant' and 'Judge'"), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }
}

} // namespace

namespace RGT::Auth
{

void RegisterHandler::requestPreprocessing(Poco::Net::HTTPServerRequest & request)
{
    HTTPRequestHandler::checkContentLength(request, cfg_.getUInt32("max_request_body_size"));
    HTTPRequestHandler::checkContentLengthIsNull(request);
    HTTPRequestHandler::checkContentType(request, "application/json");
}

std::any RegisterHandler::extractPayloadFromRequest(Poco::Net::HTTPServerRequest & request)
{
    Poco::JSON::Object::Ptr jsonObject = HTTPRequestHandler::extractJsonObjectFromRequest(request);

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

    return RequiredPayload
    {
        .name = keysAndStringValues["name"],
        .surname = keysAndStringValues["surname"],
        .role = keysAndStringValues["role"],
        .login = keysAndStringValues["login"],
        .password = keysAndStringValues["password"]
    };
}
 
void RegisterHandler::requestProcessing(Poco::Net::HTTPServerRequest & request, Poco::Net::HTTPServerResponse & response)
{
    RequiredPayload requiredPayload = std::any_cast<RequiredPayload>(payload_);

    // Валидация данных, полученных от пользователя
    validateLogin(requiredPayload.login);
    validatePassword(requiredPayload.password);
    validateRole(requiredPayload.role);

    Poco::Data::Session session = sessionPool_.get();

    Poco::Data::Statement stmt(session);

    // Проверим существует ли пользователь с переданным логином

    int userExists = 0;
    stmt << "SELECT COUNT(*) FROM users WHERE login = $1",
        Poco::Data::Keywords::use(requiredPayload.login),
        Poco::Data::Keywords::into(userExists);
    stmt.execute();
    
    if (userExists != 0) {
        throw RGT::Devkit::RGTException(std::format("User with login '{}' already exists", requiredPayload.login), 
            Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
    }

    // Добавляем данные пользователя в БД
    std::string hashedPassword = Auth::Utils::hashPassword(requiredPayload.password);
    stmt.reset();
    stmt << "INSERT INTO users (name, surname, role, login, password_hash)"
        << "VALUES ($1, $2, $3 , $4, $5)",
        Poco::Data::Keywords::use(requiredPayload.name),
        Poco::Data::Keywords::use(requiredPayload.surname),
        Poco::Data::Keywords::use(requiredPayload.role),
        Poco::Data::Keywords::use(requiredPayload.login),
        Poco::Data::Keywords::use(hashedPassword);
    stmt.execute();

    HTTPRequestHandler::sendJsonResponse(response, "OK", "OK");
}

} // namespace RGT::Auth
