#ifndef __REGISTER_HANDLER_H__
#define __REGISTER_HANDLER_H__

#include <rgt/devkit/HTTPRequestHandler.h>

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Data/SessionPool.h>
#include <Poco/Util/LayeredConfiguration.h>

namespace RGT::Auth
{

class RegisterHandler : public RGT::Devkit::HTTPRequestHandler
{
public:
    RegisterHandler(Poco::Data::SessionPool & sessionPool, Poco::Util::LayeredConfiguration & cfg) 
        : sessionPool_{sessionPool}, cfg_{cfg} 
    {
    }

private:
    virtual void requestPreprocessing(Poco::Net::HTTPServerRequest & request) final;

    virtual std::any extractPayloadFromRequest(Poco::Net::HTTPServerRequest & request) final;

    virtual void requestProcessing(Poco::Net::HTTPServerRequest & request, Poco::Net::HTTPServerResponse & response) final;

private:
    struct RequiredPayload
    {
        std::string name;
        std::string surname;
        std::string role;
        std::string login;
        std::string password;
    };

    Poco::Data::SessionPool          & sessionPool_;
    Poco::Util::LayeredConfiguration & cfg_;
};
    
} // namespace RGT::Auth

#endif // __REGISTER_HANDLER_H__
