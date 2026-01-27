#ifndef __UTILS_H__
#define __UTILS_H__

#include <string>
#include <array>
#include <chrono>

#include <Poco/JSON/Object.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Redis/Client.h>

#include <fqw-devkit/lib/Tokens.h>
#include <fqw-devkit/lib/General.h>

namespace FQW::Auth::Utils
{

// Лимит refresh-токенов на одного пользователя
constexpr uint8_t                refresh_tokens_limit          = 5;
// Время действия access-токена
constexpr std::chrono::seconds   access_token_validity_period  = std::chrono::seconds(15 * 60);
// Время действия refresh-токена
constexpr std::chrono::seconds   refresh_token_validity_period = std::chrono::seconds(30 * 24 * 60 * 60);
// Секретный ключ для подписи 
const     std::string            key                           = "secret_key";
// 
const std::array<std::string, 2> userRoles = {"Participant", "Judge"};



/**
 * @brief Хэширует пароль используя Argon2 алгоритм
 * @param password Пароль для хэширования
 * @return std::string Хэшированный пароль в формате libsodium
 * @throw std::runtime_error если хэширование не удалось
 */
std::string hashPassword(const std::string & password);

/**
 * @brief Верификация пароля
 * @param password Пароль для проверки
 * @param hash Хэш из базы данных
 * @return bool true если пароль корректный, false в противном случае
 * @throw std::runtime_error если проверка не удалась (системная ошибка)
 */
bool verifyPassword(const std::string & password, const std::string & hash);

/**
 * @brief Генерирует access токен, который представляет из себя JWT
 * @param p Полезная нагрузка
 * @return Токен
 */
std::string createAccessToken(const FQW::Devkit::Tokens::Payload & p);

/**
 * @brief Генерирует refresh токен, представляющий из себя UUID
 * @return Токен
 */
std::string createRefreshToken();

/**
 * Хэширует refresh-токен используя алгоритм SHA256 и возвращает хэш
 */
std::string hashRefreshToken(const std::string & token);

/**
 * Верификация refresh-токена
 */
bool verifyRefreshToken(const std::string & token, const std::string & hash);

/**
 * Удаляет хэш рефреш-токена из Redis (из ZSET + из HSET)
 */
void deleteRefreshFromRedis(Poco::Redis::Client & redisClient, const std::string & hashedRefreshToken, uint64_t userId);

/**
 * Хэширует рефреш-токен и добавляет хэш в Redis (в ZSET + в HSET). Если превышен лимит рефреш-токенов на
 * пользователя, то удаляет самый старый рефреш-токен 
 */
void addRefreshToRedis(Poco::Redis::Client & redisClient, std::string & refreshToken, uint64_t userId,
    std::string & fingerprint, std::string & userAgent);

/**
 * Извлекает из json'а значения для всех ключей, перечисленных в контейнере pairs, который хранит пары, и
 * присваивает каждому ключу соответствующее значение. Если хотя бы одно поле отсутствует в json, 
 * будет выброшено исключение FQWException.
 */
inline void fillRequiredFieldsFromJson(Poco::JSON::Object::Ptr jsonObject, auto & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (not jsonObject->has(key)) {
            throw FQW::Devkit::FQWException(std::format("Field {} was not received", key), 
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
        value = jsonObject->get(key);
    }
}

/** 
 * Пытается извлечь из JSON-объекта значения для ключей, перечисленных в контейнере pairs.
 * Для каждого ключа из pairs, присутствующего в JSON, соответствующее значение обновляется.
 * Если ключ отсутствует в JSON, значение, соответствующее данному ключу, не обновляется.
 * Исключение не выбрасывается.
 */
inline void tryFillRequiredFieldsFromJson(Poco::JSON::Object::Ptr jsonObject, auto & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (jsonObject->has(key)) {
            value = jsonObject->get(key);
        }
    }
}

/** 
 * Извлекает из запроса значения для всех ключей (имён заголовков), перечисленных в контейнере
 * pairs, который хранит пары, и присваивает каждому ключу соответствующее значение. Если хотя бы один
 * заголовок отсутствует - выбрасывается исключение FQWException.
 */
inline void fillRequiredFieldsFromHeaders(Poco::Net::HTTPServerRequest & req, auto & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (not req.has(key)) {
            throw FQW::Devkit::FQWException(std::format("Header {} was not received", key), 
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
        value = req.get(key);
    }
}

/**
 * Пытается извлечь из запроса значения для ключей (имён заголовков), перечисленных в контейнере pairs.
 * Для каждого ключа из pairs, присутствующего в заголовках запроса, соответствующее значение обновляется.
 * Если ключ (имя заголовка) отсутствует в запросе, значение, соответствующее данному ключу, 
 * не обновляется. Исключение не выбрасывается.
 */
inline void tryFillRequiredFieldsFromHeaders(Poco::Net::HTTPServerRequest & req, auto & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (req.has(key)) {
            value = req.get(key);
        }
    }
}

/**
 * Извлекает из запроса JSON object и возвращает указатель на него
 */
Poco::JSON::Object::Ptr extractJsonObjectFromRequest(Poco::Net::HTTPServerRequest & req);

// Считывает lua-script из файла с именем filename и возвращает его
std::string readLuaScript(const std::string & filename);

// Проверяет, есть ли для данных fingerprint и UA refresh-токен. Если да, то возвращает его хэш.
// В противном случае возвращает std::nullopt 
std::optional<std::string> getHashRefreshTokenByUserData(Poco::Redis::Client & redisClient, uint64_t userId,
    std::string & fingerprint, std::string & userAgent);

} // namespace FQW::Auth::Utils

#endif // __UTILS_H__
