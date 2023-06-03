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
#include <iostream>

using namespace Kazv;

static json paginateResponseJson = R"({
  "start": "prevBatchForEvent1",
  "end": "anotherPrevBatch",
  "chunk": [
    {
      "content": {
        "body": "This is an example text message",
        "msgtype": "m.text",
        "format": "org.sdn.custom.html",
        "formatted_body": "<b>This is an example text message</b>"
      },
      "type": "m.room.message",
      "event_id": "$third:example.org",
      "room_id": "!foo:example.org",
      "sender": "@example:example.org",
      "origin_server_ts": 1432735824653,
      "unsigned": {
        "age": 1234
      }
    },
    {
      "content": {
        "name": "The room name"
      },
      "type": "m.room.name",
      "event_id": "$second:example.org",
      "room_id": "!foo:example.org",
      "sender": "@example:example.org",
      "origin_server_ts": 1432735824653,
      "unsigned": {
        "age": 1234
      },
      "state_key": ""
    },
    {
      "content": {
        "body": "Gangnam Style",
        "url": "mxc://example.org/a526eYUSFFxlgbQYZmo442",
        "info": {
          "thumbnail_url": "mxc://example.org/FHyPlCeYUSFFxlgbQYZmoEoe",
          "thumbnail_info": {
            "mimetype": "image/jpeg",
            "size": 46144,
            "w": 300,
            "h": 300
          },
          "w": 480,
          "h": 320,
          "duration": 2140786,
          "size": 1563685,
          "mimetype": "video/mp4"
        },
        "msgtype": "m.video"
      },
      "type": "m.room.message",
      "event_id": "$first:example.org",
      "room_id": "!foo:example.org",
      "sender": "@example:example.org",
      "origin_server_ts": 1432735824651,
      "unsigned": {
        "age": 1234
      }
    }
  ]
})"_json;

static Event event1 = R"({
        "type": "m.room.message",
        "event_id": "$event1:example.org",
        "room_id": "!foo:example.org",
        "sender": "@example:example.org",
        "origin_server_ts": 1432735824654
    })"_json;

static Event event2 = R"({
        "type": "m.room.message",
        "event_id": "$event2:example.org",
        "room_id": "!foo:example.org",
        "sender": "@example:example.org",
        "origin_server_ts": 1432735824656
    })"_json;

static Event secEvent = R"({
  "content": {
    "name": "The room name"
  },
  "type": "m.room.name",
  "event_id": "$second:example.org",
  "room_id": "!foo:example.org",
  "sender": "@example:example.org",
  "origin_server_ts": 1432735824653,
  "unsigned": {
    "age": 1234
  },
  "state_key": ""
})"_json;

TEST_CASE("Pagination should remove the original gap and record a new one", "[client][paginate]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto m = createTestClientModel();

    auto room = RoomModel{};
    room.roomId = "!foo:example.org";
    room.timeline = immer::flex_vector<std::string>{"$event1:example.org", "$event2:example.org"};

    room.messages = std::move(room.messages)
        .set("$event1:example.org", event1)
        .set("$event2:example.org", event2);

    room.timelineGaps = room.timelineGaps.set("$event1:example.org", "prevBatchForEvent1");

    m.roomList.rooms = m.roomList.rooms.set(room.roomId, room);

    auto store = createTestClientStoreFrom(m, ph);

    auto resp = createResponse("GetRoomEvents", paginateResponseJson,
                               json{{"roomId", "!foo:example.org"},
                                       {"gapEventId", "$event1:example.org"}});

    auto client = Client(store.reader().map([](auto c) { return SdkModel{c}; }), store,
                         std::nullopt);

    store.dispatch(ProcessResponseAction{resp});
    io.run();

    auto r = client.room("!foo:example.org");

    auto timelineGaps = +r.timelineGaps();

    REQUIRE(! timelineGaps.find("$event1:example.org"));
    REQUIRE(timelineGaps.at("$first:example.org") == "anotherPrevBatch");
}

TEST_CASE("Pagination should erase all gaps in (start-of-fetched-batch, orig-gapped-event]", "[client][paginate]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto m = createTestClientModel();

    auto room = RoomModel{};
    room.roomId = "!foo:example.org";
    room.timeline = immer::flex_vector<std::string>{"$second:example.org", "$event1:example.org", "$event2:example.org"};

    room.messages = std::move(room.messages)
        .set("$event1:example.org", event1)
        .set("$event2:example.org", event2)
        .set("$second:example.org", secEvent);

    room.timelineGaps = room.timelineGaps
        .set("$event1:example.org", "prevBatchForEvent1")
        .set("$second:example.org", "prevBatchForSecEvent");

    m.roomList.rooms = m.roomList.rooms.set(room.roomId, room);

    auto store = createTestClientStoreFrom(m, ph);

    auto resp = createResponse("GetRoomEvents", paginateResponseJson,
                               json{{"roomId", "!foo:example.org"},
                                       {"gapEventId", "$event1:example.org"}});

    auto client = Client(store.reader().map([](auto c) { return SdkModel{c}; }), store,
                         std::nullopt);

    store.dispatch(ProcessResponseAction{resp});
    io.run();

    auto r = client.room("!foo:example.org");

    auto timelineGaps = +r.timelineGaps();

    REQUIRE(! timelineGaps.find("$second:example.org"));
    REQUIRE(timelineGaps.at("$first:example.org") == "anotherPrevBatch");
}
