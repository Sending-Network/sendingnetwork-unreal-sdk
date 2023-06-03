/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch_all.hpp>

#include <sstream>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>

#include <serialization/immer-flex-vector.hpp>
#include <serialization/immer-map.hpp>
#include <serialization/immer-box.hpp>
#include <serialization/immer-array.hpp>
#include <serialization/std-optional.hpp>

#include <event.hpp>

using namespace Kazv;
using IAr = boost::archive::text_iarchive;
using OAr = boost::archive::text_oarchive;

template<class T>
static void serializeTest(const T &in, T &out)
{
    std::stringstream stream;

    {
        auto ar = OAr(stream);
        ar << in;
    }

    {
        auto ar = IAr(stream);
        ar >> out;
    }

    REQUIRE(in == out);
}

TEST_CASE("Serialize immer::array", "[base][serialization]")
{
    immer::array<int> v{1, 2, 3, 4, 5};
    immer::array<int> v2{50};

    serializeTest(v, v2);
}


TEST_CASE("Serialize immer::flex_vector", "[base][serialization]")
{
    immer::flex_vector<int> v{1, 2, 3, 4, 5};
    immer::flex_vector<int> v2{50};

    serializeTest(v, v2);
}

TEST_CASE("Serialize immer::map", "[base][serialization]")
{
    auto v = immer::map<int, int>{}
         .set(1, 6)
         .set(2, 7)
         .set(3, 8)
         .set(4, 9)
         .set(5, 10);
    auto v2 = immer::map<int, int>{}.set(10, 7);

    serializeTest(v, v2);
}

TEST_CASE("Serialize immer::box", "[base][serialization]")
{
    auto v = immer::box<int>{42};
    immer::box<int> v2;

    serializeTest(v, v2);
}

TEST_CASE("Serialize JsonWrap", "[base][serialization]")
{
    auto v = JsonWrap{json::object({{"foo", "bar"}})};
    auto v2 = JsonWrap{};
    serializeTest(v, v2);

    v = json::array({"mew"});
    serializeTest(v, v2);
}

TEST_CASE("Serialize Event", "[base][serialization]")
{
    auto v = Event{R"({
  "type": "m.room.encrypted",
  "content": {},
  "sender": "@example:example.org",
  "event_id": "!example:example.org"
})"_json};
    auto v2 = Event{};
    serializeTest(v, v2);
}

TEST_CASE("Serialize std::optional", "[base][serialization]")
{
    std::optional<int> o{20};
    std::optional<int> o2{1};

    serializeTest(o, o2);

    o2.reset();

    serializeTest(o, o2);

    o.reset();

    serializeTest(o, o2);
}
