#include <stdexcept>
#include <random>

#include <sodium.h>
#include <Poco/JWT/JWT.h>
#include <Poco/JWT/Signer.h>
#include <Poco/JWT/Token.h>
#include <Poco/Timestamp.h>
#include <Poco/JSON/Object.h>

#include <Utils.h>

namespace FQW::Auth::Utils
{

void libsodiumInitialize()
{
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

std::string hashPassword(const std::string& password) 
{
    char hashed[crypto_pwhash_STRBYTES];
    
    if (crypto_pwhash_str(hashed, password.c_str(), password.length(), 
        crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) 
    { 
        throw std::runtime_error("Password hashing failed - possibly out of memory");
    }
    
    return std::string(hashed);
}

bool verifyPassword(const std::string& password, const std::string& hash) 
{    
    int result = crypto_pwhash_str_verify(hash.c_str(), password.c_str(), password.length());
    
    if (result == 0) {
        return true;
    } 
    else if (result == -1) {
        return false;
    } 
    else {
        throw std::runtime_error("Password verification system error");
    }
}



namespace
{

const std::string key_ = "secret_key";
const std::string_view letters_ = 
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

} // namespace

std::string createAccessToken(const Devkit::Tokens::Payload& p)
{
    Poco::JWT::Token token;

    token.setSubject(std::to_string(p.sub));

    token.payload().set("role", p.role);

    Poco::Timestamp now;
    Poco::Timestamp expires = now + static_cast<Poco::Timestamp::TimeVal>(
        std::chrono::duration_cast<std::chrono::microseconds>(p.exp).count()
    );
    token.setExpiration(expires);
    
    Poco::JWT::Signer signer(key_);
    return signer.sign(token, Poco::JWT::Signer::ALGO_HS256);
}

std::string createRefreshToken()
{
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    static thread_local std::uniform_int_distribution<> dis(0, letters_.size() - 1);

    std::string token;
    token.reserve(refresh_token_size);

    for (size_t i = 0; i < refresh_token_size; ++i) {
        token += letters_[dis(gen)];
    }

    return token; 
}

} // namespace FQW::Auth::Utils
