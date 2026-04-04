#pragma once

#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Redis/PoolableConnectionFactory.h>
#include <Poco/Util/LayeredConfiguration.h>

#include <Handlers/LoginHandler.h>
#include <Handlers/RegisterHandler.h>
#include <Handlers/RefreshHandler.h>
#include <Handlers/ErrorHandler.h>

namespace RGT::Auth
{

class AuthFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
    using RedisClientObjectPool = Poco::ObjectPool<Poco::Redis::Client, Poco::Redis::Client::Ptr>;

    AuthFactory(Poco::Data::SessionPool & sessionPool, RedisClientObjectPool & redisPool, 
        Poco::Util::LayeredConfiguration & cfg) 
        : sessionPool_(sessionPool)
        , redisPool_(redisPool)
        , cfg_(cfg)
    {
    }

    Poco::Net::HTTPRequestHandler * createRequestHandler(const Poco::Net::HTTPServerRequest & request) final;

private:
    Poco::Data::SessionPool          & sessionPool_;
    RedisClientObjectPool            & redisPool_;
    Poco::Util::LayeredConfiguration & cfg_;
};

} // namespace RGT::Auth
