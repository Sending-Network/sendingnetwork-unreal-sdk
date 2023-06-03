/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch_all.hpp>

#include <event.hpp>

using namespace Kazv;


TEST_CASE("Should distinguish between state events and other events", "[base][event]")
{
    Event state = R"({
    "state_key": "",
    "sender": "@example:example.org",
    "type": "moe.kazv.mxc.custom.state.type",
    "event_id": "!dummy",
    "origin_server_ts": 1234,
    "content": {}
})"_json;

    REQUIRE(state.isState());

    Event nonState = R"({
    "sender": "@example:example.org",
    "type": "moe.kazv.mxc.custom.non.state.type",
    "event_id": "!dummy",
    "origin_server_ts": 1234,
    "content": {}
})"_json;

    REQUIRE(!nonState.isState());
}
