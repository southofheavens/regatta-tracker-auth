#pragma once

#include <RGT/Devkit/HTTPRequestHandler.h>
#include <Utils.h>

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>

namespace RGT::Auth::Handlers
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

} // namespace RGT::Auth::Handlers
