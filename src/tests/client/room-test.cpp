/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch_all.hpp>

#include <lager/event_loop/boost_asio.hpp>
#include <boost/asio.hpp>

#include <sdk.hpp>
#include <cprjobhandler.hpp>
#include <lagerstoreeventemitter.hpp>
#include <asio-promise-handler.hpp>

#include "client-test-util.hpp"

using namespace Kazv;

TEST_CASE("Result of Room::toEventLoop() should not vary with the original cursor", "[client][room]")
{
    auto io = boost::asio::io_context{};
    auto jh = Kazv::CprJobHandler{io.get_executor()};
    auto ee = Kazv::LagerStoreEventEmitter(lager::with_boost_asio_event_loop{io.get_executor()});

    auto roomWithId = [](std::string roomId) {
                          auto r = RoomModel{};
                          r.roomId = roomId;
                          return r;
                      };

    auto initModel = Kazv::SdkModel{};
    initModel.client.roomList.rooms = std::move(initModel.client.roomList.rooms)
        .set("!foo:example.org", roomWithId("!foo:example.org"))
        .set("!bar:example.org", roomWithId("!bar:example.org"));
    auto sdk = Kazv::makeSdk(
        initModel,
        jh,
        ee,
        Kazv::AsioPromiseHandler{io.get_executor()},
        zug::identity
        );

    auto ctx = sdk.context();

    auto client = sdk.client();

    auto roomId = lager::make_state(std::string("!foo:example.org"), lager::automatic_tag{});

    auto room = client.roomByCursor(roomId);

    using namespace Kazv::CursorOp;

    REQUIRE(+room.roomId() == "!foo:example.org");

    auto roomInEventLoop = room.toEventLoop();

    REQUIRE(+roomInEventLoop.roomId() == "!foo:example.org");

    roomId.set("!bar:example.org");

    REQUIRE(+room.roomId() == "!bar:example.org");
    REQUIRE(+roomInEventLoop.roomId() == "!foo:example.org");
}

static const std::string exampleRoomId = "!example:example.org";

static auto exampleRoomWithoutNameEvent()
{
    RoomModel model;
    model.roomId = "!example:example.org";
    model.stateEvents = model.stateEvents
        .set(
            {"m.room.member", "@foo:example.org"},
            Event(R"(
            {
                "content": {
                    "displayname": "foo's name",
                    "membership": "join"
                },
                "event_id": "some id2",
                "room_id": "!example:example.org",
                "type": "m.room.member",
                "state_key": "@foo:example.org"
            })"_json))
        .set(
            {"m.room.member", "@bar:example.org"},
            Event(R"(
            {
                "content": {
                    "displayname": "bar's name",
                    "membership": "join"
                },
                "event_id": "some id3",
                "room_id": "!example:example.org",
                "type": "m.room.member",
                "state_key": "@bar:example.org"
            })"_json));
    model.heroIds = {"@foo:example.org", "@bar:example.org"};
    return model;
}

static auto exampleRoomWithNameEvent()
{
    auto model = exampleRoomWithoutNameEvent();
    model.stateEvents = model.stateEvents
        .set(
            {"m.room.name", ""},
            Event(R"(
            {
                "content": {
                    "name": "some name"
                },
                "event_id": "some id",
                "room_id": "!example:example.org",
                "type": "m.room.name",
                "state_key": ""
            })"_json));
    return model;
};

static auto sdkWith(RoomModel room)
{
    SdkModel model;
    model.client.roomList.rooms = model.client.roomList.rooms.set(room.roomId, room);
    return model;
}

static auto makeRoomWithDumbContext(RoomModel room)
{
    auto cursor = lager::make_constant(sdkWith(room));
    auto nameCursor = lager::make_constant(room.roomId);
    return Room(cursor, nameCursor, dumbContext());
}

TEST_CASE("Room::nameOpt()", "[client][room][getter]")
{
    WHEN("the room has a name") {
        auto room = makeRoomWithDumbContext(exampleRoomWithNameEvent());
        THEN("it should give out the name") {
            auto val = room.nameOpt().make().get();
            REQUIRE(val.has_value());
            REQUIRE(val.value() == "some name");
        }
    }

    WHEN("the room has no name") {
        auto room = makeRoomWithDumbContext(exampleRoomWithoutNameEvent());
        THEN("it should give out nullopt") {
            auto val = room.nameOpt().make().get();
            REQUIRE(!val.has_value());
        }
    }
}

TEST_CASE("Room::heroMemberEvents()", "[client][room][getter]")
{
    auto room = makeRoomWithDumbContext(exampleRoomWithNameEvent());
    THEN("it should give out the events") {
        auto val = room.heroMemberEvents().make().get();
        REQUIRE(val.size() == 2);
        REQUIRE(std::any_of(val.begin(), val.end(),
                [](const auto &v) {
                    return v.id() == "some id2";
                }));
        REQUIRE(std::any_of(val.begin(), val.end(),
                [](const auto &v) {
                    return v.id() == "some id3";
                }));
    }
}

TEST_CASE("Room::heroDisplayNames()", "[client][room][getter]")
{
    auto room = makeRoomWithDumbContext(exampleRoomWithNameEvent());
    THEN("it should give out the names") {
        auto val = room.heroDisplayNames().make().get();
        REQUIRE(val.size() == 2);
        REQUIRE(std::any_of(val.begin(), val.end(),
                [](const auto &v) {
                    return v == "foo's name";
                }));
        REQUIRE(std::any_of(val.begin(), val.end(),
                [](const auto &v) {
                    return v == "bar's name";
                }));
    }
}

TEST_CASE("Room::encrypted()", "[client][room][getter]")
{
    auto roomModel = exampleRoomWithNameEvent();
    WHEN("the room is encrypted") {
        roomModel.encrypted = true;
        auto room = makeRoomWithDumbContext(roomModel);
        THEN("it should give out true") {
            auto val = room.encrypted().make().get();
            REQUIRE(val);
        }
    }

    WHEN("the room is not encrypted") {
        roomModel.encrypted = false;
        auto room = makeRoomWithDumbContext(roomModel);
        THEN("it should give out false") {
            auto val = room.encrypted().make().get();
            REQUIRE(!val);
        }
    }
}
