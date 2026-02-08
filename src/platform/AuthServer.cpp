#include <Poco/Data/PostgreSQL/Connector.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/HTTPServer.h>
#include <sodium.h>

#include <AuthServer.h>
#include <AuthFactory.h>

namespace
{

/// @brief Создаёт и инициализирует пул соединений с PostgreSQL
/// @param cfg Конфигурация с параметрами подключения (psql.host, psql.port, ...)
/// @return Указатель на пул сессий
/// @throw Poco::Exception при ошибке подключения
std::unique_ptr<Poco::Data::SessionPool> connectToPsql(const Poco::Util::LayeredConfiguration & cfg)
{
    std::string connectionString = std::format
    (
        "host={0} port={1} dbname={2} user={3} password={4}", 
        cfg.getString("psql.host", "host.docker.internal"),
        cfg.getString("psql.port", "5432"),
        cfg.getString("psql.dbname", "something"),
        cfg.getString("psql.user", "postgres"),
        cfg.getString("psql.password", "postgres")
    );

    std::unique_ptr<Poco::Data::SessionPool> sessionPool = std::make_unique<Poco::Data::SessionPool>("PostgreSQL", 
        connectionString, cfg.getUInt16("psql.minsessions", 10), cfg.getUInt16("psql.maxsessions", 10));

    try 
    {
        // Проверяем подключение к БД
        sessionPool->get() << "SELECT 1", Poco::Data::Keywords::now;
    }
    catch (...) 
    {
        throw Poco::Exception
        (
            std::format
            (
                "Connection attempt to postgresql failed with host {0} and port {1}",
                cfg.getString("psql.host", "host.docker.internal"),
                cfg.getString("psql.port", "5432")
            )
        );
    }

    return sessionPool;
}   

/// @brief Создаёт и инициализирует пул соединений с Redis
/// @param cfg Конфигурация с параметрами подключения (redis.host, redis.port, ...)
/// @return Указатель на пул сессий
/// @throw Poco::Exception при ошибке подключения
std::unique_ptr<RGT::Auth::AuthServer::RedisClientObjectPool> connectToRedis(const Poco::Util::LayeredConfiguration & cfg)
{
    using RedisClientObjectPool = RGT::Auth::AuthServer::RedisClientObjectPool;
    using RedisClientPoolableObjectFactory = Poco::PoolableObjectFactory<Poco::Redis::Client, Poco::Redis::Client::Ptr>;
    std::unique_ptr<RedisClientObjectPool> redisPool = std::make_unique<RedisClientObjectPool>
    (
        RedisClientPoolableObjectFactory
        (
            std::format
            (
                "{0}:{1}",
                cfg.getString("redis.host", "host.docker.internal"),
                cfg.getString("redis.port", "6379")
            )
        ), 
        cfg.getUInt16("redis.minsessions", 10), 
        cfg.getUInt16("redis.maxsessions", 10)
    );

    try
    {
        Poco::Redis::PooledConnection pc(*redisPool);
        Poco::Redis::Array cmd;
        cmd << "PING";
        std::string result = static_cast<Poco::Redis::Client::Ptr>(pc)->execute<std::string>(cmd);
    }
    catch (...) 
    {
        throw Poco::Exception
        (
            std::format
            (
                "Connection attempt to redis failed with host {0} and port {1}",
                cfg.getString("redis.host", "host.docker.internal"),
                cfg.getString("redis.port", "6379")
            )
        );
    }
    
    return redisPool;
} 

} // namespace

namespace RGT::Auth
{

void AuthServer::initialize(Poco::Util::Application & self)
{
    Poco::Util::ServerApplication::loadConfiguration();
    Poco::Util::ServerApplication::initialize(self);

    if (sodium_init() < 0) {
        throw Poco::Exception("Failed to initialize libsodium");
    }

    Poco::Data::PostgreSQL::Connector::registerConnector();

    const Poco::Util::LayeredConfiguration & cfg = AuthServer::config();
    sessionPool_ = connectToPsql(cfg);
    redisPool_ = connectToRedis(cfg);
}

void AuthServer::uninitialize()
{
    Poco::Data::PostgreSQL::Connector::unregisterConnector();

    ServerApplication::uninitialize();
}

int AuthServer::main(const std::vector<std::string>&)
try
{
    Poco::Net::ServerSocket svs(8080);
    
    Poco::Net::HTTPServer srv
    (
        new Auth::AuthFactory(*sessionPool_, *redisPool_), 
        svs, 
        new Poco::Net::HTTPServerParams
    );

    srv.start();
    
    waitForTerminationRequest();
    
    srv.stop();
    
    return Application::EXIT_OK;
}
catch (const Poco::Exception& e) 
{
    std::cerr << e.displayText() << '\n';
    return Application::EXIT_SOFTWARE;
}
catch (const std::exception& e) 
{
    std::cerr << e.what() << '\n';
    return Application::EXIT_SOFTWARE;
}
catch (...) {
    return Application::EXIT_SOFTWARE;
}

} // namespace RGT::Auth
