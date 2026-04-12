#pragma once

#include <gtest/gtest.h>

#include <RGT/Devkit/TestTools/Client.h>

namespace RGT::Auth::Tests
{

class LoginFixture : public ::testing::Test
{
public:
    static const inline std::string userName = "Name";
    static const inline std::string userSurname = "Surname";
    static const inline std::string userLogin = "name_surname";

private:
    static const inline RGT::Devkit::TestTools::User someUser 
        = Devkit::TestTools::User(userName, userSurname, userLogin, RGT::Devkit::TestTools::Role::Participant);
};

} // namespace RGT::Auth::Tests
