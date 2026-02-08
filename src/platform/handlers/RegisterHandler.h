#ifndef __REGISTER_HANDLER_H__
#define __REGISTER_HANDLER_H__

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Data/SessionPool.h>
#include <Poco/Util/LayeredConfiguration.h>

namespace RGT::Auth
{

class RegisterHandler : public Poco::Net::HTTPRequestHandler
{
public:
    RegisterHandler(Poco::Data::SessionPool & sessionPool, Poco::Util::LayeredConfiguration & cfg) 
        : sessionPool_{sessionPool}, cfg_{cfg} 
    {
    }

    void handleRequest(Poco::Net::HTTPServerRequest & req, Poco::Net::HTTPServerResponse & res) final;

private:
    Poco::Data::SessionPool          & sessionPool_;
    Poco::Util::LayeredConfiguration & cfg_;
};
    
} // namespace RGT::Auth

#endif // __REGISTER_HANDLER_H__
