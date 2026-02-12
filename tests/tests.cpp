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
#include <thread>
#include <chrono>
#include <iostream>
#include <random>

class ServerFixture : public ::testing::Test 
{
protected:
    void SetUp() final 
    {
        processHandlePtr = std::make_unique<Poco::ProcessHandle>(Poco::Process::launch("/Users/semyonzhuravlev/RGT/regatta-tracker-auth/build/rgt-auth", {}));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
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
    // Создаём сессию
    Poco::Net::HTTPClientSession session("127.0.0.1", 8080); // ваш порт
    
    // Формируем запрос
    Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, "/login");
    
    // Генерируем рандомный fingerprint
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, 0xFFFFFFFFFFFFFFFF);
    std::stringstream ss;
    ss << std::hex << dist(gen);
    std::string fingerprint = ss.str();
    
    // Устанавливаем заголовки
    request.setContentType("application/json");
    request.set("User-Agent", "TestClient/1.0");
    request.set("X-Fingerprint", fingerprint);

    // Формируем тело запроса
    Poco::JSON::Object jsonBody;
    jsonBody.set("login", "zhuravlevsema");
    jsonBody.set("password", "zhuravlevsema");
    
    std::ostringstream bodyStream;
    jsonBody.stringify(bodyStream);
    std::string body = bodyStream.str();
    
    request.setContentLength(body.length());
    
    // Отправляем запрос
    std::ostream& os = session.sendRequest(request);
    os << body;
    
    // Получаем ответ
    Poco::Net::HTTPResponse response;
    std::istream& is = session.receiveResponse(response);
    
    std::string responseStr;
    Poco::StreamCopier::copyToString(is, responseStr);
    
    // Проверяем статус
    EXPECT_EQ(response.getStatus(), Poco::Net::HTTPResponse::HTTP_OK);

    // Парсим ответ (если это тоже JSON)
    if (response.getContentType().find("application/json") != std::string::npos) {
        Poco::JSON::Parser parser;
        auto result = parser.parse(responseStr).extract<Poco::JSON::Object::Ptr>();
        
        // Проверяем поля в ответе
        if (result->has("access_token")) {
            std::string accessToken = result->getValue<std::string>("access_token");
            // Можно что-то проверить с токеном
            EXPECT_FALSE(accessToken.empty());
        }
        
        if (result->has("refresh_token")) {
            std::string refreshToken = result->getValue<std::string>("refresh_token");
            EXPECT_FALSE(refreshToken.empty());
        }
    }
    
    // Выводим для отладки
    std::cout << "Fingerprint: " << fingerprint << std::endl;
    std::cout << "Response: " << responseStr << std::endl;
}
