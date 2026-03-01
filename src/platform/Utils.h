#ifndef __UTILS_H__
#define __UTILS_H__

#include <string>
#include <array>
#include <chrono>

#include <Poco/JSON/Object.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Redis/Client.h>
#include <Poco/Redis/PoolableConnectionFactory.h>

#include <rgt/devkit/General.h>
#include <rgt/devkit/RGTException.h>
#include <rgt/devkit/JWTPayload.h>

namespace RGT::Auth::Utils
{

using RedisClientObjectPool = Poco::ObjectPool<Poco::Redis::Client, Poco::Redis::Client::Ptr>;

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
std::string createAccessToken(const RGT::Devkit::JWTPayload & p);

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
void deleteRefreshFromRedis(RedisClientObjectPool & redisPool, const std::string & hashedRefreshToken, uint64_t userId);

/**
 * Хэширует рефреш-токен и добавляет хэш в Redis (в ZSET + в HSET). Если превышен лимит рефреш-токенов на
 * пользователя, то удаляет самый старый рефреш-токен 
 */
void addRefreshToRedis(RedisClientObjectPool & redisPool, std::string & refreshToken, uint64_t userId,
    std::string & fingerprint, std::string & userAgent);

/**
 * Извлекает из json'а значения для всех ключей, перечисленных в контейнере pairs, который хранит пары, и
 * присваивает каждому ключу соответствующее значение. Если хотя бы одно поле отсутствует в json, 
 * будет выброшено исключение RGTException.
 */
inline void fillRequiredFieldsFromJson(Poco::JSON::Object::Ptr jsonObject, auto & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (not jsonObject->has(key)) {
            throw RGT::Devkit::RGTException(std::format("Field {} was not received", key), 
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
        value = jsonObject->get(key);
    }
}

/** 
 * Извлекает из запроса значения для всех ключей (имён заголовков), перечисленных в контейнере
 * pairs, который хранит пары, и присваивает каждому ключу соответствующее значение. Если хотя бы один
 * заголовок отсутствует - выбрасывается исключение RGTException.
 */
inline void fillRequiredFieldsFromHeaders(Poco::Net::HTTPServerRequest & req, auto & pairs)
{
    for (auto & [key, value] : pairs)
    {
        if (not req.has(key)) {
            throw RGT::Devkit::RGTException(std::format("Header {} was not received", key), 
                Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        }
        value = req.get(key);
    }
}

// Считывает lua-script из файла с именем filename и возвращает его
std::string readLuaScript(const std::string & filename);

// Проверяет, есть ли для данных fingerprint и UA refresh-токен. Если да, то возвращает его хэш.
// В противном случае возвращает std::nullopt 
std::optional<std::string> getHashRefreshTokenByUserData(RedisClientObjectPool & redisPool, uint64_t userId,
    std::string & fingerprint, std::string & userAgent);

} // namespace RGT::Auth::Utils

#endif // __UTILS_H__
