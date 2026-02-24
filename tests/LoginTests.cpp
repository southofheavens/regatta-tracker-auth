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
// Клиент хочет получить access и refresh токены и отправляет на сервер
// корректные логин и пароль, но не устанавливает размер контента
TEST_F(ServerFixture, login_without_content_lenght)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("User-Agent", "TestClient/1.0");
    request.set("X-Fingerprint", "some_fingerprint");

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("login", "zhuravlevsema");
    jsonBody.set("password", "zhuravleVSEMA-");

    // Приводим тело запроса из Poco::JSON::Object к std::string
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();

    // Не устанавливаем размер контента

    // Отправляем запрос
    std::ostream & os = session.sendRequest(request);
    os << body;
    
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
    EXPECT_EQ(message, "Content length is unknown");
}

/*----------------------------------------------------------------------------------------------------*/

// Сценарий:
// Клиент хочет получить access и refresh токены и отправляет на сервер
// корректные логин и пароль, но размер контента превышает допустимый
TEST_F(ServerFixture, login_with_incorrect_content_lenght)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("User-Agent", "TestClient/1.0");
    request.set("X-Fingerprint", "some_fingerprint");

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("login", "zhuravlevsema");
    jsonBody.set("password", "zhuravleVSEMA-");

    // Приводим тело запроса из Poco::JSON::Object к std::string
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();

    // Устанавливаем некорректный размер контента (попытка свалить сервер)
    request.setContentLength(1'000'000'000);

    // Отправляем запрос
    std::ostream & os = session.sendRequest(request);
    os << body;
    
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
    EXPECT_EQ(message, "Content size must not exceed 1 megabyte");
}

/*----------------------------------------------------------------------------------------------------*/

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

    // Устанавливаем некорректный размер контента
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

/*----------------------------------------------------------------------------------------------------*/

// Сценарий:
// Клиент хочет получить access и refresh токены и отправляет на сервер
// корректные логин и пароль, но отсутствует заголовок Content-Type 
TEST_F(ServerFixture, login_without_content_type_header)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.set("User-Agent", "TestClient/1.0");
    request.set("X-Fingerprint", "some_fingerprint");

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("login", "zhuravlevsema");
    jsonBody.set("password", "zhuravleVSEMA-");
    
    // Приводим тело запроса из Poco::JSON::Object к std::string
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();
    
    // Устанавливаем длину контента
    request.setContentLength(body.length());
    
    // Отправляем запрос
    std::ostream & os = session.sendRequest(request);
    os << body;
    
    // Получаем ответ
    Poco::Net::HTTPResponse response;
    std::istream & is = session.receiveResponse(response);
    
    // Проверяем статус
    EXPECT_EQ(response.getStatus(), Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);

    // Проверяем, что тип ответа - application/json
    EXPECT_NE(response.getContentType().find("application/json"), std::string::npos);

    // Парсим ответ
    Poco::JSON::Parser parser;
    Poco::JSON::Object::Ptr result = parser.parse(is).extract<Poco::JSON::Object::Ptr>();
    
    // Проверяем поля в ответе
    EXPECT_FALSE(result->has("access_token"));
    EXPECT_FALSE(result->has("refresh_token"));

    EXPECT_TRUE(result->has("status"));
    std::string status = result->getValue<std::string>("status");
    EXPECT_EQ(status, "error");

    EXPECT_TRUE(result->has("message"));
    std::string message = result->getValue<std::string>("message");
    EXPECT_EQ(message, "Content-Type must be application/json");
}

/*----------------------------------------------------------------------------------------------------*/

// Сценарий:
// Клиент хочет получить access и refresh токены и отправляет на сервер
// НЕкорректные логин и пароль
TEST_F(ServerFixture, login_with_incorrect_data)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("User-Agent", "TestClient/1.0");
    request.set("X-Fingerprint", "some_fingerprint");

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("login", "incorrect");
    jsonBody.set("password", "incorrect");
    
    // Приводим тело запроса из Poco::JSON::Object к std::string
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();
    
    // Устанавливаем длину контента
    request.setContentLength(body.length());
    
    // Отправляем запрос
    std::ostream & os = session.sendRequest(request);
    os << body;
    
    // Получаем ответ
    Poco::Net::HTTPResponse response;
    std::istream & is = session.receiveResponse(response);

    // Проверяем статус
    EXPECT_EQ(response.getStatus(), Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);

    // Парсим ответ
    Poco::JSON::Parser parser;
    Poco::JSON::Object::Ptr result = parser.parse(is).extract<Poco::JSON::Object::Ptr>();
    
    // Проверяем поля в ответе
    EXPECT_FALSE(result->has("access_token"));
    EXPECT_FALSE(result->has("refresh_token"));

    EXPECT_TRUE(result->has("status"));
    std::string status = result->getValue<std::string>("status");
    EXPECT_EQ(status, "error");

    EXPECT_TRUE(result->has("message"));
    std::string message = result->getValue<std::string>("message");
    EXPECT_EQ(message, "Incorrect login or password");
}

/*----------------------------------------------------------------------------------------------------*/

// Сценарий:
// Клиент хочет получить access и refresh токены и отправляет на сервер
// корректные логин и пароль, но в заголовках и полях тела отсутствует fingerprint
TEST_F(ServerFixture, login_without_fingerprint)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("User-Agent", "TestClient/1.0");

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("login", "zhuravlevsema");
    jsonBody.set("password", "zhuravleVSEMA-");
    
    // Приводим тело запроса из Poco::JSON::Object к std::string
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();
    
    // Устанавливаем длину контента
    request.setContentLength(body.length());
    
    // Отправляем запрос
    std::ostream & os = session.sendRequest(request);
    os << body;
    
    // Получаем ответ
    Poco::Net::HTTPResponse response;
    std::istream & is = session.receiveResponse(response);
    
    // Проверяем статус
    EXPECT_EQ(response.getStatus(), Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);

    // Проверяем, что тип ответа - application/json
    EXPECT_NE(response.getContentType().find("application/json"), std::string::npos);

    // Парсим ответ
    Poco::JSON::Parser parser;
    Poco::JSON::Object::Ptr result = parser.parse(is).extract<Poco::JSON::Object::Ptr>();
    
    // Проверяем поля в ответе
    EXPECT_FALSE(result->has("access_token"));
    EXPECT_FALSE(result->has("refresh_token"));

    EXPECT_TRUE(result->has("status"));
    std::string status = result->getValue<std::string>("status");
    EXPECT_EQ(status, "error");

    EXPECT_TRUE(result->has("message"));
    std::string message = result->getValue<std::string>("message");
    EXPECT_EQ(message, "Expected to receive fingerprint in the headers/request body");
}

/*----------------------------------------------------------------------------------------------------*/

// Сценарий:
// Клиент хочет получить access и refresh токены и отправляет на сервер
// корректные логин и пароль, но отсутствует заголовок User-Agent
TEST_F(ServerFixture, login_without_user_agent_header)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("X-Fingerprint", "some_fingerprint");

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("login", "zhuravlevsema");
    jsonBody.set("password", "zhuravleVSEMA-");
    
    // Приводим тело запроса из Poco::JSON::Object к std::string
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();
    
    // Устанавливаем длину контента
    request.setContentLength(body.length());
    
    // Отправляем запрос
    std::ostream & os = session.sendRequest(request);
    os << body;
    
    // Получаем ответ
    Poco::Net::HTTPResponse response;
    std::istream & is = session.receiveResponse(response);
    
    // Проверяем статус
    EXPECT_EQ(response.getStatus(), Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);

    // Проверяем, что тип ответа - application/json
    EXPECT_NE(response.getContentType().find("application/json"), std::string::npos);

    // Парсим ответ
    Poco::JSON::Parser parser;
    Poco::JSON::Object::Ptr result = parser.parse(is).extract<Poco::JSON::Object::Ptr>();
    
    // Проверяем поля в ответе
    EXPECT_FALSE(result->has("access_token"));
    EXPECT_FALSE(result->has("refresh_token"));

    EXPECT_TRUE(result->has("status"));
    std::string status = result->getValue<std::string>("status");
    EXPECT_EQ(status, "error");

    EXPECT_TRUE(result->has("message"));
    std::string message = result->getValue<std::string>("message");
    EXPECT_EQ(message, "User-Agent header was not received");
}

/*----------------------------------------------------------------------------------------------------*/

// Сценарий:
// Клиент хочет получить access и refresh токены и отправляет на сервер
// только логин
TEST_F(ServerFixture, login_with_only_login)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("User-Agent", "TestClient/1.0");
    request.set("X-Fingerprint", "some_fingerprint");

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("login", "zhuravlevsema");
    
    // Приводим тело запроса из Poco::JSON::Object к std::string
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();
    
    // Устанавливаем длину контента
    request.setContentLength(body.length());
    
    // Отправляем запрос
    std::ostream & os = session.sendRequest(request);
    os << body;
    
    // Получаем ответ
    Poco::Net::HTTPResponse response;
    std::istream & is = session.receiveResponse(response);

    // Проверяем статус
    EXPECT_EQ(response.getStatus(), Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);

    // Парсим ответ
    Poco::JSON::Parser parser;
    Poco::JSON::Object::Ptr result = parser.parse(is).extract<Poco::JSON::Object::Ptr>();
    
    // Проверяем поля в ответе
    EXPECT_FALSE(result->has("access_token"));
    EXPECT_FALSE(result->has("refresh_token"));

    EXPECT_TRUE(result->has("status"));
    std::string status = result->getValue<std::string>("status");
    EXPECT_EQ(status, "error");

    EXPECT_TRUE(result->has("message"));
    std::string message = result->getValue<std::string>("message");
    EXPECT_EQ(message, "Field password was not received");
}

/*----------------------------------------------------------------------------------------------------*/

// Сценарий:
// Клиент хочет получить access и refresh токены и отправляет на сервер
// только пароль
TEST_F(ServerFixture, login_with_only_password)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("User-Agent", "TestClient/1.0");
    request.set("X-Fingerprint", "some_fingerprint");

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("password", "zhuravleVSEMA-");
    
    // Приводим тело запроса из Poco::JSON::Object к std::string
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();
    
    // Устанавливаем длину контента
    request.setContentLength(body.length());
    
    // Отправляем запрос
    std::ostream & os = session.sendRequest(request);
    os << body;
    
    // Получаем ответ
    Poco::Net::HTTPResponse response;
    std::istream & is = session.receiveResponse(response);

    // Проверяем статус
    EXPECT_EQ(response.getStatus(), Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);

    // Парсим ответ
    Poco::JSON::Parser parser;
    Poco::JSON::Object::Ptr result = parser.parse(is).extract<Poco::JSON::Object::Ptr>();
    
    // Проверяем поля в ответе
    EXPECT_FALSE(result->has("access_token"));
    EXPECT_FALSE(result->has("refresh_token"));

    EXPECT_TRUE(result->has("status"));
    std::string status = result->getValue<std::string>("status");
    EXPECT_EQ(status, "error");

    EXPECT_TRUE(result->has("message"));
    std::string message = result->getValue<std::string>("message");
    EXPECT_EQ(message, "Field login was not received");
}

/*----------------------------------------------------------------------------------------------------*/

// Сценарий:
// Клиент хочет получить access и refresh токены и отправляет на сервер
// корректные логин и пароль. Fingerprint передается через заголовок
TEST_F(ServerFixture, login_with_correct_data_and_header_fingerprint)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("User-Agent", "TestClient/1.0");
    request.set("X-Fingerprint", "some_fingerprint");

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("login", "zhuravlevsema");
    jsonBody.set("password", "zhuravleVSEMA-");
    
    // Приводим тело запроса из Poco::JSON::Object к std::string
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();
    
    // Устанавливаем длину контента
    request.setContentLength(body.length());
    
    // Отправляем запрос
    std::ostream & os = session.sendRequest(request);
    os << body;
    
    // Получаем ответ
    Poco::Net::HTTPResponse response;
    std::istream & is = session.receiveResponse(response);
    
    // Проверяем статус
    EXPECT_EQ(response.getStatus(), Poco::Net::HTTPResponse::HTTP_OK);

    // Проверяем, что тип ответа - application/json
    EXPECT_NE(response.getContentType().find("application/json"), std::string::npos);

    // Парсим ответ
    Poco::JSON::Parser parser;
    Poco::JSON::Object::Ptr result = parser.parse(is).extract<Poco::JSON::Object::Ptr>();
    
    // Проверяем поля в ответе
    EXPECT_TRUE(result->has("access_token"));
    std::string accessToken = result->getValue<std::string>("access_token");
    EXPECT_FALSE(accessToken.empty());
    
    EXPECT_TRUE(result->has("refresh_token"));
    std::string refreshToken = result->getValue<std::string>("refresh_token");
    EXPECT_FALSE(refreshToken.empty());
}

/*----------------------------------------------------------------------------------------------------*/

// Сценарий:
// Клиент хочет получить access и refresh токены и отправляет на сервер
// корректные логин и пароль. Fingerprint передается через тело запроса
TEST_F(ServerFixture, login_with_correct_data_and_body_fingerprint)
{
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); 
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
        
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("User-Agent", "TestClient/1.0");

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("login", "zhuravlevsema");
    jsonBody.set("password", "zhuravleVSEMA-");
    jsonBody.set("fingerprint", "some_fingerprint");
    
    // Приводим тело запроса из Poco::JSON::Object к std::string
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();
    
    // Устанавливаем длину контента
    request.setContentLength(body.length());
    
    // Отправляем запрос
    std::ostream & os = session.sendRequest(request);
    os << body;
    
    // Получаем ответ
    Poco::Net::HTTPResponse response;
    std::istream & is = session.receiveResponse(response);
    
    // Проверяем статус
    EXPECT_EQ(response.getStatus(), Poco::Net::HTTPResponse::HTTP_OK);

    // Проверяем, что тип ответа - application/json
    EXPECT_NE(response.getContentType().find("application/json"), std::string::npos);

    // Парсим ответ
    Poco::JSON::Parser parser;
    Poco::JSON::Object::Ptr result = parser.parse(is).extract<Poco::JSON::Object::Ptr>();
    
    // Проверяем поля в ответе
    EXPECT_TRUE(result->has("access_token"));
    std::string accessToken = result->getValue<std::string>("access_token");
    EXPECT_FALSE(accessToken.empty());
    
    EXPECT_TRUE(result->has("refresh_token"));
    std::string refreshToken = result->getValue<std::string>("refresh_token");
    EXPECT_FALSE(refreshToken.empty());
}

} // namespace RGT::Auth::Tests
