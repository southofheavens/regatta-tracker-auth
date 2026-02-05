#ifndef __REFRESH_HANDLER_H__
#define __REFRESH_HANDLER_H__

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Data/SessionPool.h>
#include <Poco/Redis/Client.h>
#include <Poco/Redis/PoolableConnectionFactory.h>

namespace RGT::Auth
{

class RefreshHandler : public Poco::Net::HTTPRequestHandler
{
public:
    using RedisClientObjectPool = Poco::ObjectPool<Poco::Redis::Client, Poco::Redis::Client::Ptr>;

    RefreshHandler(Poco::Data::SessionPool & sessionPool, RedisClientObjectPool & redisPool);

    void handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) final;

private:
    Poco::Data::SessionPool    & sessionPool_;
    RedisClientObjectPool      & redisPool_;
};

} // namespace RGT::Auth

#endif // __REFRESH_HANDLER_H__
