/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include <catch2/catch_all.hpp>

#include <clientutil.hpp>

#include <immer/flex_vector.hpp>

namespace
{
    struct Model
    {
        int value;
        std::string data;
    };

    bool operator==(Model a, Model b)
    {
        return a.value == b.value && a.data == b.data;
    }

    bool operator!=(Model a, Model b)
    {
        return !(a == b);
    }
}

using namespace Kazv;

TEST_CASE("sortedUniqueMerge should behave correctly", "[client][clientutil]")
{
    immer::flex_vector<Model> base = {{50, "foo"}, {100, "bar"}};
    immer::flex_vector<Model> addon = {{1, "a"}, {2, "b"}, {70, "c"}, {110, "d"}};

    auto exists = [base](auto m) { return std::find(base.begin(), base.end(), m) != base.end(); };
    auto key = [](auto m) { return m.value; };

    auto res = sortedUniqueMerge(base, addon, exists, key);

    REQUIRE( res == immer::flex_vector<Model>{{1, "a"}, {2, "b"}, {50, "foo"}, {70, "c"}, {100, "bar"}, {110, "d"}} );
}
