#ifndef __AUTH_FACTORY_H__
#define __AUTH_FACTORY_H__

#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Redis/PoolableConnectionFactory.h>

#include <handlers/LoginHandler.h>
#include <handlers/RegisterHandler.h>
#include <handlers/RefreshHandler.h>
#include <handlers/ErrorHandler.h>

namespace RGT::Auth
{

class AuthFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
    using RedisClientObjectPool = Poco::ObjectPool<Poco::Redis::Client, Poco::Redis::Client::Ptr>;

    AuthFactory(Poco::Data::SessionPool & sessionPool, RedisClientObjectPool & redisPool) 
        : sessionPool_(sessionPool), redisPool_(redisPool) 
    {
    }

    Poco::Net::HTTPRequestHandler * createRequestHandler(const Poco::Net::HTTPServerRequest & request) final;

private:
    Poco::Data::SessionPool    & sessionPool_;
    RedisClientObjectPool      & redisPool_;
};

} // namespace RGT::Auth

#endif // __AUTH_FACTORY_H__
