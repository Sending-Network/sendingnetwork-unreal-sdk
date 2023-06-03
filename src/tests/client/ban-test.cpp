/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch_all.hpp>
#include <boost/asio.hpp>
#include <asio-promise-handler.hpp>
#include <cursorutil.hpp>
#include <sdk-model.hpp>
#include <client/client.hpp>

#include "client-test-util.hpp"

TEST_CASE("Send ban job", "[client][membership]")
{
    ClientModel loggedInModel = createTestClientModel();
    auto [resModel, dontCareEffect] = ClientModel::update(
        loggedInModel, BanAction{"!room:example.com", "@alice:example.com", "spamming"});

    assert1Job(resModel);
    for1stJob(resModel, [] (const auto &job) {
        REQUIRE(job.jobId() == "Ban");
        REQUIRE(job.url().find("!room:example.com") != std::string::npos);
        auto jsonBody = json::parse(std::get<BytesBody>(job.requestBody()));
        REQUIRE(jsonBody["user_id"] == "@alice:example.com");
        REQUIRE(jsonBody["reason"] == "spamming");
    });
}

TEST_CASE("Process ban response", "[client][membership]")
{
    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    WHEN("Success response")
    {
        auto succResponse = createResponse("Ban", json::object({}));
        store.dispatch(ProcessResponseAction{succResponse})
            .then([] (auto stat) {
                REQUIRE(stat.success());
            });
    }

    WHEN("Failed response")
    {
        auto failResponse = createResponse("Ban", R"({
  "errcode": "M_FORBIDDEN",
  "error": "You do not have a high enough power level to ban from this room."
})"_json);
        failResponse.statusCode = 403;
        store.dispatch(ProcessResponseAction{failResponse})
            .then([] (auto stat) {
                REQUIRE(!stat.success());
                REQUIRE(stat.dataStr("error") == "You do not have a high enough power level to ban from this room.");
                REQUIRE(stat.dataStr("errorCode") == "M_FORBIDDEN");
            });
    }

    io.run();
}


TEST_CASE("Send unban job", "[client][membership]")
{
    ClientModel loggedInModel = createTestClientModel();
    auto [resModel, dontCareEffect] = ClientModel::update(
        loggedInModel, UnbanAction{"!room:example.com", "@alice:example.com"});

    assert1Job(resModel);
    for1stJob(resModel, [] (const auto &job) {
        REQUIRE(job.jobId() == "Unban");
        REQUIRE(job.url().find("!room:example.com") != std::string::npos);
        auto jsonBody = json::parse(std::get<BytesBody>(job.requestBody()));
        REQUIRE(jsonBody["user_id"] == "@alice:example.com");
        // No reason field in r0
        // REQUIRE(jsonBody["reason"] == "spamming");
    });
}

TEST_CASE("Process unban response", "[client][membership]")
{
    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    WHEN("Success response")
    {
        auto succResponse = createResponse("Unban", json::object({}));
        store.dispatch(ProcessResponseAction{succResponse})
            .then([] (auto stat) {
                REQUIRE(stat.success());
            });
    }

    WHEN("Failed response")
    {
        auto failResponse = createResponse("Unban", R"({
  "errcode": "M_FORBIDDEN",
  "error": "You do not have a high enough power level to unban from this room."
})"_json);
        failResponse.statusCode = 403;
        store.dispatch(ProcessResponseAction{failResponse})
            .then([] (auto stat) {
                REQUIRE(!stat.success());
                REQUIRE(stat.dataStr("error") == "You do not have a high enough power level to unban from this room.");
                REQUIRE(stat.dataStr("errorCode") == "M_FORBIDDEN");
            });
    }

    io.run();
}
