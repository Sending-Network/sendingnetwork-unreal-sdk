/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2022 Tusooa Zhu <tusooa@kazv.moe>
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

static const json wellKnownResponseJson = R"({
  "m.node": {
    "base_url": "https://sdn.example.com"
  },
  "m.identity_server": {
    "base_url": "https://identity.example.com"
  },
  "org.example.custom.property": {
    "app_url": "https://custom.app.example.org"
  }
})"_json;

static const json versionsResponseJson = R"({
  "unstable_features": {
    "org.example.my_feature": true
  },
  "versions": [
    "r0.0.1",
    "v1.1"
  ]
})"_json;


TEST_CASE("Auto-discovery tests", "[client][discovery]")
{
    using namespace Kazv::CursorOp;
    using Catch::Matchers::StartsWith;

    WHEN("We do a discovery")
    {
        ClientModel m;
        auto [resModel, dontCareEffect] = ClientModel::update(m, GetWellknownAction{"@foo:example.com"});

        THEN("We should send to the server address as in the userId")
        {
            REQUIRE(resModel.nextJobs.size() == 1);
            auto job = resModel.nextJobs[0];
            REQUIRE_THAT(job.url(), StartsWith("https://example.com/"));
            REQUIRE(job.dataStr("serverUrl") == "https://example.com");
        }
    }

    WHEN("We do a discovery no remote part provided")
    {
        ClientModel m;
        auto [resModel, dontCareEffect] = ClientModel::update(m, GetWellknownAction{"@foo"});

        THEN("We should not send any job")
        {
            REQUIRE(resModel.nextJobs.size() == 0);
        }
    }

    WHEN("We do a discovery 0-length part provided")
    {
        ClientModel m;
        auto [resModel, dontCareEffect] = ClientModel::update(m, GetWellknownAction{"@foo:"});

        THEN("We should not send any job")
        {
            REQUIRE(resModel.nextJobs.size() == 0);
        }
    }

    // Test different server names
    WHEN("We do a discovery with server names containing ports")
    {
        ClientModel m;
        auto [resModel, dontCareEffect] = ClientModel::update(m, GetWellknownAction{"@foo:example.com:8080"});

        THEN("We should send to the server address as in the userId")
        {
            REQUIRE(resModel.nextJobs.size() == 1);
            auto job = resModel.nextJobs[0];
            REQUIRE_THAT(job.url(), StartsWith("https://example.com:8080/"));
        }
    }

    WHEN("We do a discovery with server names containing ipv4 address")
    {
        ClientModel m;
        auto [resModel, dontCareEffect] = ClientModel::update(m, GetWellknownAction{"@foo:1.2.3.4:8080"});

        THEN("We should send to the server address as in the userId")
        {
            REQUIRE(resModel.nextJobs.size() == 1);
            auto job = resModel.nextJobs[0];
            REQUIRE_THAT(job.url(), StartsWith("https://1.2.3.4:8080/"));
        }
    }

    WHEN("We do a discovery with server names containing ipv6 address")
    {
        ClientModel m;
        auto [resModel, dontCareEffect] = ClientModel::update(m, GetWellknownAction{"@foo:[1234:5678::abcd]:5678"});

        THEN("We should send to the server address as in the userId")
        {
            REQUIRE(resModel.nextJobs.size() == 1);
            auto job = resModel.nextJobs[0];
            REQUIRE_THAT(job.url(), StartsWith("https://[1234:5678::abcd]:5678/"));
        }
    }


    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    WHEN("We got a successful response")
    {
        auto resp = createResponse("GetWellknown", wellKnownResponseJson,
            json{{"serverUrl", "https://example.com"}});

        THEN("We should return the server url in the response")
        {
            store.dispatch(ProcessResponseAction{resp})
                .then([](auto stat) {
                    REQUIRE(stat.success());
                    auto data = stat.dataStr("nodeUrl");
                    REQUIRE(data == std::string("https://sdn.example.com"));
                });
        }
    }

    WHEN("We got 404")
    {
        auto resp = createResponse("GetWellknown", wellKnownResponseJson,
            json{{"serverUrl", "https://example.com"}});

        resp.statusCode = 404;

        THEN("We should return the server in the user id")
        {
            store.dispatch(ProcessResponseAction{resp})
                .then([](auto stat) {
                    REQUIRE(stat.success());
                    auto data = stat.dataStr("nodeUrl");
                    REQUIRE(data == std::string("https://example.com"));
                });
        }
    }

    WHEN("We got other error codes")
    {
        auto resp = createResponse("GetWellknown", wellKnownResponseJson,
            json{{"serverUrl", "https://example.com"}});

        resp.statusCode = 500;

        THEN("We should FAIL_PROMPT")
        {
            store.dispatch(ProcessResponseAction{resp})
                .then([](auto stat) {
                    REQUIRE(!stat.success());
                    auto data = stat.dataStr("error");
                    REQUIRE(data == std::string("FAIL_PROMPT"));
                });
        }
    }

    io.run();
}

TEST_CASE("GetVersions", "[client][discovery]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    WHEN("We got a successful response")
    {
        auto resp = createResponse("GetVersions", versionsResponseJson);

        THEN("We should return the versions supported")
        {
            store.dispatch(ProcessResponseAction{resp})
                .then([](auto stat) {
                    REQUIRE(stat.success());
                    auto data = stat.dataJson("versions");
                    REQUIRE(data == immer::flex_vector<std::string>{
                        "r0.0.1",
                        "v1.1"
                    });
                });
        }
    }

    WHEN("We got an error")
    {
        auto resp = createResponse("GetVersions", json());

        resp.statusCode = 400;

        THEN("We should fail")
        {
            store.dispatch(ProcessResponseAction{resp})
                .then([](auto stat) {
                    REQUIRE(!stat.success());
                    REQUIRE(stat.dataJson("errorCode") == "400");
                });
        }
    }

    io.run();
}
