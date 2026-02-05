#ifndef __AUTH_SERVER_H__
#define __AUTH_SERVER_H__

#include <vector>
#include <string>
#include <memory>
#include <mutex>

#include <Poco/Util/ServerApplication.h>
#include <Poco/Data/SessionPool.h>
#include <Poco/Redis/Client.h>
#include <Poco/Redis/PoolableConnectionFactory.h>

namespace RGT::Auth
{

class AuthServer : public Poco::Util::ServerApplication
{
public:
    using RedisClientObjectPool = Poco::ObjectPool<Poco::Redis::Client, Poco::Redis::Client::Ptr>;

    void initialize(Application & self) final;

    void uninitialize() final;

    int main(const std::vector<std::string> &) final;

private:
    std::unique_ptr<Poco::Data::SessionPool>    sessionPool_;
    std::unique_ptr<RedisClientObjectPool>      redisPool_;
};

} // namespace RGT::Auth

#endif // __AUTH_SERVER_H__
