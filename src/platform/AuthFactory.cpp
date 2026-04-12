#include <AuthFactory.h>

#include <RGT/Devkit/ErrorHandler.h>
#include <Handlers/LoginHandler.h>
#include <Handlers/RegisterHandler.h>
#include <Handlers/RefreshHandler.h>

namespace RGT::Auth
{

Poco::Net::HTTPRequestHandler * AuthFactory::createRequestHandler(const Poco::Net::HTTPServerRequest & request) 
{
    std::string uri = request.getURI();
    std::string method = request.getMethod();
    
    if (method == "POST")
    {
        if (uri == "/login") {
            return new RGT::Auth::Handlers::LoginHandler(sessionPool_, redisPool_, cfg_);
        }
        else if (uri == "/register") {
            return new RGT::Auth::Handlers::RegisterHandler(sessionPool_, cfg_);
        }
        else if (uri == "/refresh") {
            return new RGT::Auth::Handlers::RefreshHandler(sessionPool_, redisPool_, cfg_);
        }
        else {
            return new RGT::Devkit::ErrorHandler();
        }
    }
    else {
        return new RGT::Devkit::ErrorHandler();
    }
}

} // namespace RGT::Auth
