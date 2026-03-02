#include <rgt/devkit/Connections.h>

#include <Poco/Data/PostgreSQL/Connector.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/HTTPServer.h>
#include <sodium.h>

#include <AuthServer.h>
#include <AuthFactory.h>

namespace RGT::Auth
{

void AuthServer::initialize(Poco::Util::Application & self)
{
    loadConfiguration();
    ServerApplication::initialize(self);

    if (sodium_init() < 0) {
        throw Poco::Exception("Failed to initialize libsodium");
    }

    Poco::Data::PostgreSQL::Connector::registerConnector();

    const Poco::Util::LayeredConfiguration & cfg = AuthServer::config();

    sessionPool_ = RGT::Devkit::connectToPsql(cfg.getString("psql.host"), cfg.getString("psql.port"),
        cfg.getString("psql.dbname"), cfg.getString("psql.user"),cfg.getString("psql.password"),
        cfg.getUInt16("psql.min_sessions"), cfg.getUInt16("psql.max_sessions"));

    redisPool_ = RGT::Devkit::connectToRedis(cfg.getString("redis.host"), cfg.getString("redis.port"),
        cfg.getUInt16("redis.min_sessions"), cfg.getUInt16("redis.max_sessions"));
}

void AuthServer::uninitialize()
{
    Poco::Data::PostgreSQL::Connector::unregisterConnector();

    ServerApplication::uninitialize();
}

int AuthServer::main(const std::vector<std::string>&)
try
{
    Poco::Util::LayeredConfiguration & cfg = AuthServer::config();

    Poco::Net::ServerSocket svs(cfg.getUInt16("server.port"));
    
    Poco::Net::HTTPServer srv
    (
        new Auth::AuthFactory(*sessionPool_, *redisPool_, cfg), 
        svs, 
        new Poco::Net::HTTPServerParams
    );

    srv.start();
    
    waitForTerminationRequest();
    
    srv.stop();
    
    return Application::EXIT_OK;
}
catch (const Poco::Exception & e) 
{
    std::cerr << e.displayText() << '\n';
    return Application::EXIT_SOFTWARE;
}
catch (const std::exception & e) 
{
    std::cerr << e.what() << '\n';
    return Application::EXIT_SOFTWARE;
}
catch (...) {
    return Application::EXIT_SOFTWARE;
}

} // namespace RGT::Auth
