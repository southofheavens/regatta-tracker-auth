#include <Poco/Data/PostgreSQL/Connector.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/HTTPServer.h>
#include <sodium.h>

#include <AuthServer.h>
#include <AuthFactory.h>

namespace RGT::Auth
{

void AuthServer::initialize(Application & self)
{
    ServerApplication::initialize(self);

    if (sodium_init() < 0) {
        throw Poco::Exception("Failed to initialize libsodium");
    }

    Poco::Data::PostgreSQL::Connector::registerConnector();
    std::string connectionString = "host=localhost port=5432 dbname=something user=postgres password=postgres";
    sessionPool_ = std::make_unique<Poco::Data::SessionPool>("PostgreSQL", connectionString, 1, 10);

    using RedisClientPoolableObjectFactory = Poco::PoolableObjectFactory<Poco::Redis::Client, Poco::Redis::Client::Ptr>;
    redisPool_ = std::make_unique<RedisClientObjectPool>(RedisClientPoolableObjectFactory("127.0.0.1:6379"), 1, 10);
}

void AuthServer::uninitialize()
{
    Poco::Data::PostgreSQL::Connector::unregisterConnector();

    ServerApplication::uninitialize();
}

int AuthServer::main(const std::vector<std::string>&)
try
{
    Poco::Net::ServerSocket svs(8080);
    
    Poco::Net::HTTPServer srv
    (
        new Auth::AuthFactory(*sessionPool_, *redisPool_), 
        svs, 
        new Poco::Net::HTTPServerParams
    );

    srv.start();
    
    waitForTerminationRequest();
    
    srv.stop();
    
    return Application::EXIT_OK;
}
catch (const Poco::Exception& e) 
{
    std::cerr << e.displayText() << '\n';
    return Application::EXIT_SOFTWARE;
}
catch (const std::exception& e) 
{
    std::cerr << e.what() << '\n';
    return Application::EXIT_SOFTWARE;
}
catch (...) {
    return Application::EXIT_SOFTWARE;
}

} // namespace RGT::Auth
