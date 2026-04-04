#include <AuthFactory.h>

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
            return new RGT::Auth::Handlers::ErrorHandler();
        }
    }
    else {
        return new RGT::Auth::Handlers::ErrorHandler();
    }
}

} // namespace RGT::Auth
