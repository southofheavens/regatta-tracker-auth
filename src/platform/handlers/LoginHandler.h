#ifndef __LOGIN_HANDLER_H__
#define __LOGIN_HANDLER_H__

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Data/SessionPool.h>
#include <Poco/Redis/Client.h>
#include <Poco/Redis/PoolableConnectionFactory.h>
#include <Poco/Util/LayeredConfiguration.h>

namespace RGT::Auth
{

class LoginHandler : public Poco::Net::HTTPRequestHandler
{
public:
    using RedisClientObjectPool = Poco::ObjectPool<Poco::Redis::Client, Poco::Redis::Client::Ptr>;

    LoginHandler(Poco::Data::SessionPool & sessionPool, RedisClientObjectPool & redisPool, Poco::Util::LayeredConfiguration & cfg) 
        : sessionPool_{sessionPool}, redisPool_{redisPool}, cfg_{cfg}
    {
    }

    void handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) final;

private:
    Poco::Data::SessionPool          & sessionPool_;
    RedisClientObjectPool            & redisPool_;
    Poco::Util::LayeredConfiguration & cfg_;
};

} // namespace RGT::Auth

#endif // __LOGIN_HANDLER_H__
