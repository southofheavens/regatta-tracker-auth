#ifndef __LOGIN_HANDLER_H__
#define __LOGIN_HANDLER_H__

#include <rgt/devkit/HTTPRequestHandler.h>

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Data/SessionPool.h>
#include <Poco/Redis/Client.h>
#include <Poco/Redis/PoolableConnectionFactory.h>
#include <Poco/Util/LayeredConfiguration.h>

namespace RGT::Auth
{

class LoginHandler : public RGT::Devkit::HTTPRequestHandler
{
private:
    using RedisClientObjectPool = Poco::ObjectPool<Poco::Redis::Client, Poco::Redis::Client::Ptr>;

public:
    LoginHandler(Poco::Data::SessionPool & sessionPool, RedisClientObjectPool & redisPool, 
        Poco::Util::LayeredConfiguration & cfg) 
        : sessionPool_{sessionPool}
        , redisPool_{redisPool}
        , cfg_{cfg}
    {
    }

private:
    virtual void requestPreprocessing(Poco::Net::HTTPServerRequest & request) final;

    virtual std::any extractPayloadFromRequest(Poco::Net::HTTPServerRequest & request) final;

    virtual void requestProcessing(Poco::Net::HTTPServerRequest & request, Poco::Net::HTTPServerResponse & response) final;

private:
    struct RequiredPayload
    {
        std::string userAgent;
        std::string fingerprint;
        std::string login;
        std::string password;
    };

    Poco::Data::SessionPool          & sessionPool_;
    RedisClientObjectPool            & redisPool_;
    Poco::Util::LayeredConfiguration & cfg_;
};

} // namespace RGT::Auth

#endif // __LOGIN_HANDLER_H__
