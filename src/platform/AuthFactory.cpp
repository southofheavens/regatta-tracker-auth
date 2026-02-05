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
            return new RGT::Auth::LoginHandler(sessionPool_, redisPool_);
        }
        else if (uri == "/register") {
            return new RGT::Auth::RegisterHandler(sessionPool_);
        }
        else if (uri == "/refresh") {
            return new RGT::Auth::RefreshHandler(sessionPool_, redisPool_);
        }
        else {
            return new RGT::Auth::ErrorHandler();
        }
    }
    else {
        return new RGT::Auth::ErrorHandler();
    }
}

} // namespace RGT::Auth
