#ifndef __ERROR_HANDLER_H__
#define __ERROR_HANDLER_H__

#include <rgt/devkit/HTTPRequestHandler.h>
#include <Utils.h>

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>

namespace RGT::Auth
{

class ErrorHandler : public RGT::Devkit::HTTPRequestHandler
{
private:
    virtual void requestPreprocessing(Poco::Net::HTTPServerRequest & request) final
    {
    }

    virtual std::any extractPayloadFromRequest(Poco::Net::HTTPServerRequest & request) final
    { return std::any{}; }

    virtual void requestProcessing(Poco::Net::HTTPServerRequest & request, Poco::Net::HTTPServerResponse & response) final
    {
        response.setStatusAndReason(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        HTTPRequestHandler::sendJsonResponse(response, "error", "Non-existent URL or bad method");
    }
};

} // namespace RGT::Auth

#endif // __ERROR_HANDLER_H__   
