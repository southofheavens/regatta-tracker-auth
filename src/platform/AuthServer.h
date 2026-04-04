#pragma once

#include <vector>
#include <string>
#include <memory>
#include <mutex>

#include <Poco/Util/ServerApplication.h>

namespace RGT::Auth
{

class AuthServer : public Poco::Util::ServerApplication
{
public:
    void initialize(Application & self) final;

    void uninitialize() final;

    int main(const std::vector<std::string> &) final;
};

} // namespace RGT::Auth
