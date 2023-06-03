/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch_all.hpp>

#include <room/room-model.hpp>

using namespace Kazv;

TEST_CASE("SetHeroIdsAction", "[client][room]")
{
    RoomModel r;
    r.heroIds = immer::flex_vector<std::string>{"@u:test.org"};

    auto newHeroes = immer::flex_vector<std::string>{"@a:test.org", "@b:test.org"};

    WHEN("We update the model") {
        auto res = RoomModel::update(r, SetHeroIdsAction{newHeroes});

        THEN("it should update hero ids") {
            REQUIRE(res.heroIds == newHeroes);
        }

        THEN("it should compare different than the original") {
            REQUIRE(!(res == r));
        }
    }
}
