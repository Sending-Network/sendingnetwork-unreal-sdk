#pragma once

#include "gtest/gtest.h"
#include <cstdlib>
#include <iostream>
#include <limits>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <sdn/responses/login.hpp>
#include <sdnclient/http/client.hpp>

inline int
random_number()
{
    std::random_device rng;
    std::uniform_int_distribution<int> dist(1, std::numeric_limits<int>::max());

    return dist(rng);
}

inline void
sleep()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

#define WAIT_UNTIL(condition)                                                                      \
    while (!(condition)) {                                                                         \
        sleep();                                                                                   \
    };

inline void
check_error(sdn::http::RequestErr err)
{
    if (err) {
        std::cout << "sdn (error)  : " << err->sdn_error.error << "\n";
        std::cout << "sdn (errcode): " << sdn::errors::to_string(err->sdn_error.errcode)
                  << "\n";
        std::cout << "error_code      : " << err->error_code << "\n";
        std::cout << "status_code     : " << err->status_code << "\n";

        if (!err->parse_error.empty())
            std::cout << "parse_error     : " << err->parse_error << "\n";
    }

    ASSERT_FALSE(err);
}

inline std::string
server_name()
{
    const char *server_ = std::getenv("SDN_CLIENT_SERVER");
    return server_ ? server_ : std::string("localhost");
}

inline auto
make_test_client()
{
    auto client = std::make_shared<sdn::http::Client>(server_name(), 8008);
    client->verify_certificates(false);
    return client;
}

inline void
check_login(const sdn::responses::Login &, sdn::http::RequestErr err)
{
    check_error(err);
}

inline void
validate_login(const std::string &user, const sdn::responses::Login &res)
{
    EXPECT_EQ(res.user_id.to_string(), user);
    ASSERT_TRUE(res.access_token.size() > 20);
    ASSERT_TRUE(res.device_id.size() > 5);
}

template<class Collection>
std::vector<std::string>
get_event_ids(const std::vector<Collection> &events)
{
    std::vector<std::string> ids;

    for (const auto &e : events)
        ids.push_back(std::visit([](auto msg) { return msg.event_id; }, e));

    return ids;
}

inline std::string
fixture_prefix()
{
    auto var = std::getenv("FIXTURE_PREFIX");

    if (var)
        return var;
    else
        return ".";
}
