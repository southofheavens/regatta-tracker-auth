#include <gtest/gtest.h>
#include <Poco/Process.h>
#include <Poco/Pipe.h>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Util/Application.h>
#include <Poco/StreamCopier.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/Data/PostgreSQL/Connector.h>
#include <thread>
#include <chrono>
#include <iostream>
#include <random>

#include <ServerFixture.h>

namespace RGT::Auth::Tests
{

// Сценарий:
// Клиент хочет получить access и refresh токены, но размер
// отправляемых данных равен 0 (клиент ничего не отправил)
TEST_F(ServerFixture, login_with_empty_body)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("User-Agent", "TestClient/1.0");
    request.set("X-Fingerprint", "some_fingerprint");

    // Устанавливаем некорректный размер контента (попытка свалить сервер)
    request.setContentLength(0);

    // Отправляем запрос
    session.sendRequest(request);
    
    // Получаем ответ
    Poco::Net::HTTPResponse response;
    std::istream & is = session.receiveResponse(response);
    std::string stringResponse;
    Poco::StreamCopier::copyToString(is, stringResponse);
    
    // Проверяем статус
    EXPECT_EQ(response.getStatus(), Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);

    // Проверяем, что тип ответа - application/json
    EXPECT_NE(response.getContentType().find("application/json"), std::string::npos);

    // Парсим ответ
    Poco::JSON::Parser parser;
    Poco::JSON::Object::Ptr result = parser.parse(stringResponse).extract<Poco::JSON::Object::Ptr>();
    
    // Проверяем поля в ответе
    EXPECT_FALSE(result->has("access_token"));
    EXPECT_FALSE(result->has("refresh_token"));

    EXPECT_TRUE(result->has("status"));
    std::string status = result->getValue<std::string>("status");
    EXPECT_EQ(status, "error");

    EXPECT_TRUE(result->has("message"));
    std::string message = result->getValue<std::string>("message");
    EXPECT_EQ(message, "Content length is zero");
}

} // namespace RGT::Auth::Tests
 