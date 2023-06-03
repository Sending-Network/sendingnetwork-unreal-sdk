/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include <catch2/catch_all.hpp>

#include <boost/asio.hpp>

#include <zug/into_vector.hpp>

#include <asio-promise-handler.hpp>
#include <cursorutil.hpp>
#include <sdk-model.hpp>
#include <client/client.hpp>

#include "client-test-util.hpp"

// The example response
static json syncResponseJson = R"({
  "next_batch": "s72595_4483_1934",
  "presence": {
    "events": [
      {
        "content": {
          "avatar_url": "mxc://localhost:wefuiwegh8742w",
          "last_active_ago": 2478593,
          "presence": "online",
          "currently_active": false,
          "status_msg": "Making cupcakes"
        },
        "type": "m.presence",
        "sender": "@example:localhost"
      }
    ]
  },
  "account_data": {
    "events": [
      {
        "type": "org.example.custom.config",
        "content": {
          "custom_config_key": "custom_config_value"
        }
      }
    ]
  },
  "rooms": {
    "join": {
      "!726s6s6q:example.com": {
        "summary": {
          "m.heroes": [
            "@alice:example.com",
            "@bob:example.com"
          ],
          "m.joined_member_count": 2,
          "m.invited_member_count": 0
        },
        "state": {
          "events": [
            {
              "content": {
                "membership": "join",
                "avatar_url": "mxc://example.org/SEsfnsuifSDFSSEF",
                "displayname": "Alice Margatroid"
              },
              "type": "m.room.member",
              "event_id": "$143273582443PhrSn:example.org",
              "room_id": "!726s6s6q:example.com",
              "sender": "@example:example.org",
              "origin_server_ts": 1432735824653,
              "unsigned": {
                "age": 1234
              },
              "state_key": "@alice:example.org"
            }
          ]
        },
        "timeline": {
          "events": [
            {
              "content": {
                "membership": "join",
                "avatar_url": "mxc://example.org/SEsfnsuifSDFSSEF",
                "displayname": "Alice Margatroid"
              },
              "type": "m.room.member",
              "event_id": "$143273582443PhrSn:example.org",
              "room_id": "!726s6s6q:example.com",
              "sender": "@example:example.org",
              "origin_server_ts": 1432735824653,
              "unsigned": {
                "age": 1234
              },
              "state_key": "@alice:example.org"
            },
            {
              "content": {
                "body": "This is an example text message",
                "msgtype": "m.text",
                "format": "org.sdn.custom.html",
                "formatted_body": "<b>This is an example text message</b>"
              },
              "type": "m.room.message",
              "event_id": "$anothermessageevent:example.org",
              "room_id": "!726s6s6q:example.com",
              "sender": "@example:example.org",
              "origin_server_ts": 1432735824653,
              "unsigned": {
                "age": 1234
              }
            }
          ],
          "limited": true,
          "prev_batch": "t34-23535_0_0"
        },
        "ephemeral": {
          "events": [
            {
              "content": {
                "user_ids": [
                  "@alice:sdn.org",
                  "@bob:example.com"
                ]
              },
              "type": "m.typing",
              "room_id": "!jEsUZKDJdhlrceRyVU:example.org"
            }
          ]
        },
        "account_data": {
          "events": [
            {
              "content": {
                "tags": {
                  "u.work": {
                    "order": 0.9
                  }
                }
              },
              "type": "m.tag"
            },
            {
              "type": "org.example.custom.room.config",
              "content": {
                "custom_config_key": "custom_config_value"
              }
            },
            {
              "type": "m.fully_read",
              "content": {
                "event_id": "$anothermessageevent:example.org"
              }
            }
          ]
        }
      }
    },
    "invite": {
      "!696r7674:example.com": {
        "invite_state": {
          "events": [
            {
              "sender": "@alice:example.com",
              "type": "m.room.name",
              "state_key": "",
              "content": {
                "name": "My Room Name"
              }
            },
            {
              "sender": "@alice:example.com",
              "type": "m.room.member",
              "state_key": "@bob:example.com",
              "content": {
                "membership": "invite"
              }
            }
          ]
        }
      }
    },
    "leave": {}
  },
  "to_device": {
    "events": [
      {
        "sender": "@alice:example.com",
        "type": "m.new_device",
        "content": {
          "device_id": "XYZABCDE",
          "rooms": ["!726s6s6q:example.com"]
        }
      }
    ]
  }
})"_json;

static json stateInTimelineResponseJson = R"({
  "next_batch": "some-example-value",
  "rooms": {
    "join": {
      "!exampleroomid:example.com": {
        "timeline": {
          "events": [
            {
              "content": { "example": "foo" },
              "state_key": "",
              "event_id": "$example:example.com",
              "sender": "@example:example.org",
              "origin_server_ts": 1432735824653,
              "unsigned": { "age": 1234 },
              "type": "moe.kazv.mxc.custom.state.type"
            }
          ],
          "limited": false
        }
      }
    }
  }
})"_json;

TEST_CASE("use sync response to update client model", "[client][sync]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    auto resp = createResponse("Sync", syncResponseJson, json{{"is", "initial"}});

    auto client = Client(store.reader().map([](auto c) { return SdkModel{c}; }), store,
                         std::nullopt);

    store.dispatch(ProcessResponseAction{resp});

    io.run();

    auto rooms = +client.rooms();

    std::string roomId = "!726s6s6q:example.com";

    SECTION("rooms should be added") {
        REQUIRE(rooms.find(roomId));
    }

    auto r = client.room(roomId);

    SECTION("room members should be updated") {
        auto members = +r.members();

        auto hasAlice = zug::into_vector(
            zug::filter([](auto id) { return id == "@alice:example.org"; }),
            members)
            .size() > 0;

        REQUIRE(hasAlice);
    }

    SECTION("heroes should be updated") {
        auto heroIds = +r.heroIds();

        REQUIRE(heroIds == immer::flex_vector<std::string>{"@alice:example.com", "@bob:example.com"});
    }

    SECTION("ephemeral events should be updated") {
        auto users = +r.typingUsers();

        REQUIRE((users == immer::flex_vector<std::string>{
                    "@alice:sdn.org",
                    "@bob:example.com"
                }));
    }

    auto eventId = "$anothermessageevent:example.org"s;

    SECTION("timeline should be updated") {
        auto timeline = +r.timelineEvents();

        auto filtered = zug::into_vector(
            zug::filter([=](auto event) { return event.id() == eventId; }),
            timeline);

        auto hasEvent = filtered.size() > 0;
        REQUIRE(hasEvent);

        auto onlyOneEvent = filtered.size() == 1;
        REQUIRE(onlyOneEvent);

        auto ev = filtered[0];

        auto eventHasRoomId = ev.originalJson().get().contains("room_id"s);
        REQUIRE(eventHasRoomId);

        auto gaps = +r.timelineGaps();
        // first event in the batch, correspond to its prevBatch
        REQUIRE(gaps.at("$143273582443PhrSn:example.org") == "t34-23535_0_0");
    }

    SECTION("fully read marker should be updated") {
        auto readMarker = +r.readMarker();

        REQUIRE(readMarker == eventId);
    }

    SECTION("toDevice should be updated") {
        auto toDevice = +client.toDevice();

        REQUIRE(toDevice.size() == 1);
        REQUIRE(toDevice[0].sender() == "@alice:example.com");
    }
}

TEST_CASE("Sync should record state events in timeline", "[client][sync]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    auto resp = createResponse("Sync", stateInTimelineResponseJson, json{{"is", "initial"}});

    auto client = Client(store.reader().map([](auto c) { return SdkModel{c}; }), store,
                         std::nullopt);

    store.dispatch(ProcessResponseAction{resp});

    io.run();

    auto r = client.room("!exampleroomid:example.com");

    auto stateOpt = +r.stateOpt(KeyOfState{"moe.kazv.mxc.custom.state.type", ""});

    REQUIRE(stateOpt.has_value());
    REQUIRE(stateOpt.value().content().get().at("example") == "foo");
}
