#include <RGT/Devkit/Subsystems/PsqlSubsystem.h>
#include <RGT/Devkit/Subsystems/RedisSubsystem.h>

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

    RGT::Devkit::readDotEnv();

    Poco::Util::Application::addSubsystem(new RGT::Devkit::Subsystems::PsqlSubsystem());
    Poco::Util::Application::addSubsystem(new RGT::Devkit::Subsystems::RedisSubsystem());  

    ServerApplication::initialize(self);

    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

void AuthServer::uninitialize()
{ ServerApplication::uninitialize(); }

int AuthServer::main(const std::vector<std::string>&)
try
{
    Poco::Util::LayeredConfiguration & cfg = AuthServer::config();

    Poco::Net::ServerSocket svs(cfg.getUInt16("server.port"));

    auto & redisSubsystem = Poco::Util::Application::getSubsystem<Devkit::Subsystems::RedisSubsystem>();
    auto & psqlSubsystem = Poco::Util::Application::getSubsystem<Devkit::Subsystems::PsqlSubsystem>();
    
    Poco::Net::HTTPServer srv
    (
        new Auth::AuthFactory(psqlSubsystem.getPool(), redisSubsystem.getPool(), cfg), 
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
