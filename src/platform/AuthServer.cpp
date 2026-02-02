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
}

int AuthServer::main(const std::vector<std::string>&)
try
{
    Poco::Data::PostgreSQL::Connector::registerConnector();
    std::string connectionString = "host=localhost port=5432 dbname=something user=postgres password=postgres";
    Poco::Data::SessionPool sessionPool("PostgreSQL", connectionString, 1, 10);

    Poco::Redis::Client redisClient("127.0.0.1:6379");

    Poco::Net::ServerSocket svs(8080);
    
    Poco::Net::HTTPServer srv
    (
        new Auth::AuthFactory(sessionPool, redisClient), 
        svs, 
        new Poco::Net::HTTPServerParams
    );

    srv.start();
    std::cout << "Сервер запущен на порту 8080..." << std::endl;
    
    waitForTerminationRequest();
    
    srv.stop();

    Poco::Data::PostgreSQL::Connector::unregisterConnector();
    
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
