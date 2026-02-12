#include <gtest/gtest.h>
#include <Poco/Process.h>
#include <Poco/Pipe.h>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Util/Application.h>
#include <thread>
#include <chrono>
#include <iostream>

class ServerFixture : public ::testing::Test 
{
protected:
    void SetUp() final 
    {
        processHandlePtr = std::make_unique<Poco::ProcessHandle>(Poco::Process::launch("../build/rgt-auth", {}));
    }

    void TearDown() final 
    {
        Poco::Process::kill(*processHandlePtr);
    }

private:
    std::unique_ptr<Poco::ProcessHandle> processHandlePtr;
};

TEST_F(ServerFixture, simple_test)
{
    ASSERT_EQ(1, 1);
}