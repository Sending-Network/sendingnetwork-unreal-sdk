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

TEST_CASE("Send kick job", "[client][membership]")
{
    ClientModel loggedInModel = createTestClientModel();
    auto [resModel, dontCareEffect] = ClientModel::update(
        loggedInModel, KickAction{"!room:example.com", "@alice:example.com", "spamming"});

    assert1Job(resModel);
    for1stJob(resModel, [] (const auto &job) {
        REQUIRE(job.jobId() == "Kick");
        REQUIRE(job.url().find("!room:example.com") != std::string::npos);
    });
}

TEST_CASE("Process kick response", "[client][membership]")
{
    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    WHEN("Success response")
    {
        auto succResponse = createResponse("Kick", json::object({}));
        store.dispatch(ProcessResponseAction{succResponse})
            .then([] (auto stat) {
                REQUIRE(stat.success());
            });
    }

    WHEN("Failed response")
    {
        auto failResponse = createResponse("Kick", R"({
  "errcode": "M_FORBIDDEN",
  "error": "You do not have a high enough power level to kick from this room."
})"_json);
        failResponse.statusCode = 403;
        store.dispatch(ProcessResponseAction{failResponse})
            .then([] (auto stat) {
                REQUIRE(!stat.success());
                REQUIRE(stat.dataStr("error") == "You do not have a high enough power level to kick from this room.");
                REQUIRE(stat.dataStr("errorCode") == "M_FORBIDDEN");
            });
    }

    io.run();
}
