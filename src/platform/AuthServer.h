#ifndef __AUTH_SERVER_H__
#define __AUTH_SERVER_H__

#include <vector>
#include <string>

#include <Poco/Util/ServerApplication.h>

namespace RGT::Auth
{

class AuthServer : public Poco::Util::ServerApplication
{
public:
    int main(const std::vector<std::string>&) final;
};

} // namespace RGT::Auth

#endif // __AUTH_SERVER_H__
