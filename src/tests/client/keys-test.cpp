/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2022 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch_all.hpp>

#include <client-model.hpp>

#include "client-test-util.hpp"

using namespace Kazv;

TEST_CASE("Query keys", "[client][keys]")
{
    ClientModel m;
    m.crypto = Crypto{};
    m.deviceLists.track(immer::flex_vector<std::string>{"@mew:example.org", "@mew2:example.org"});

    WHEN("We query keys")
    {
        auto [res, dontCareEffect] = ClientModel::update(m, QueryKeysAction{true});
        THEN("It should make a request with a map of empty lists")
        {
            assert1Job(res);
            for1stJob(res, [](const auto &job) {
                auto body = json::parse(std::get<BytesBody>(job.requestBody()));
                REQUIRE(body.at("device_keys").at("@mew:example.org") == json::array());
                REQUIRE(body.at("device_keys").at("@mew2:example.org") == json::array());
            });
        }
    }
}
