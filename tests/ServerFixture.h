#ifndef __SERVER_FIXTURE_H__
#define __SERVER_FIXTURE_H__

#include <memory>
#include <thread>

#include <gtest/gtest.h>
#include <Poco/Data/PostgreSQL/Connector.h>
#include <Poco/Process.h>

namespace RGT::Auth::Tests
{

class ServerFixture : public ::testing::Test 
{
protected:
    static void SetUpTestSuite() 
    {
        Poco::Data::PostgreSQL::Connector::registerConnector();

        processHandlePtr = std::make_unique<Poco::ProcessHandle>(Poco::Process::launch("build/rgt-auth", {}));
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    static void TearDownTestSuite()  
    {
        Poco::Data::PostgreSQL::Connector::unregisterConnector();

        Poco::Process::kill(*processHandlePtr);
    }

private:
    inline static std::unique_ptr<Poco::ProcessHandle> processHandlePtr = nullptr;
};

} // namespace RGT::Auth::Tests

#endif // __SERVER_FIXTURE_H__
