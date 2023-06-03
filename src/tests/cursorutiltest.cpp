/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <string>
#include <tuple>
#include <iostream>
#include <map>
#include <catch2/catch_all.hpp>
#include <boost/asio.hpp>

#include <immer/array.hpp>
#include <immer/array_transient.hpp>
#include <immer/map.hpp>
#include <lager/store.hpp>
#include <lager/state.hpp>
#include <lager/constant.hpp>
#include <lager/reader.hpp>
#include <lager/event_loop/manual.hpp>

#include <cursorutil.hpp>

using namespace Kazv;

TEST_CASE("cursorutil should perform correctly", "[cursorutil]")
{
    immer::array<int> src1{4, 8, 7, 6};
    immer::array<std::string> exp1{"4", "8", "7", "6"};
    auto res1 = intoImmer(
        immer::array<std::string>{},
        zug::map(
            [](int x) {
                return std::to_string(x);
            }),
        src1);

    REQUIRE( exp1 == res1 );

    immer::map<int, int> src2;
    src2 = std::move(src2).set(4, 8).set(7, 6);
    immer::map<std::string, int> exp2;
    exp2 = std::move(exp2).set("4", 8).set("7", 6);
    auto res2 = intoImmer(
        immer::map<std::string, int>{},
        zug::map(
            [](auto x) {
                return std::make_pair(std::to_string(x.first), x.second);
            }),
        src2);

    REQUIRE( exp2 == res2 );

    immer::map<std::string, int> res3;

    auto rf =
        [&](auto st, auto in) {
            *st = in;
            return st;
        };

    containerMap(
        immer::map<std::string, int>{},
        zug::map(
            [](auto x) {
                return std::make_pair(std::to_string(x.first), x.second);
            }))(rf)(&res3, src2);

    REQUIRE( res3 == exp2 );
}

using MapT = immer::map<std::string, std::string>;

struct Whole
{
    std::string first;
    std::string second;
    MapT map;
    struct ChangeFirstAction {
        std::string first;
    };

    struct ChangeMapAction {
        std::string key;
        std::string value;
    };

    using Action = std::variant<ChangeFirstAction, ChangeMapAction>;
    static Whole update(Whole m, Action a) {
        return lager::match(a)(
            [&](ChangeFirstAction a) {
                m.first = a.first;
                return m;
            },
            [&](ChangeMapAction a) {
                m.map = std::move(m.map).set(a.key, a.value);
                return m;
            }
            );
    }
};

bool operator==(Whole a, Whole b)
{
    return a.first == b.first
        && a.second == b.second
        && a.map == b.map;
}

struct WholeWrap
{
    WholeWrap(lager::reader<Whole> w)
        : m_d(w)
        {}

    inline decltype(auto) first() const {
        return m_d[&Whole::first];
    };

    inline decltype(auto) complex() const {
        return m_d[&Whole::map]["Wow"][lager::lenses::or_default];
    };

    lager::reader<Whole> m_d;
};

template<class Cursor>
inline decltype(auto) vv(Cursor &&c)
{
    return std::move(c).make().get();
}

TEST_CASE("cursorop should perform correctly", "[cursorop]")
{
    using namespace Kazv::CursorOp;

    MapT map;
    std::string longStr1{"qwjrf8qqqiuafejhuahhvjdugy3t"};
    std::string longStr2{"4837q9rfueiomehvjn ncbaeiur"};
    std::string longStr3{"fhim  jzdbuifh4o8t 374ry33"};
    std::string longStr4{"jaiecjnjvdk nbqiufu38rhnm d"};
    map = std::move(map).set("Wow", longStr1);
    map = std::move(map).set("ww", longStr2);

    Whole src1{"www", "34rfea", map};
    std::string exp1{"ppp"};

    auto store = lager::make_store<Whole::Action>(
        src1,
        lager::with_manual_event_loop{},
        lager::with_reducer(&Whole::update));

    lager::reader<Whole> reader = store;
    auto w = WholeWrap(reader);

    auto res1 = +w.first();
    auto cond = res1 == "www";
    REQUIRE(cond);
    auto res2 = +w.complex();
    auto cond2 = res2 == longStr1;
    REQUIRE(cond2);
    auto res3 = +reader[&Whole::map]["Wow"];
    auto cond3 = res3 && res3.value() == longStr1;
    REQUIRE(cond3);

    using Map2T = std::map<std::string, std::string>;
    Map2T src2{{"Wow", longStr1}, {"uuu", longStr2}};
    auto state = lager::make_constant(src2);

    lager::reader<Map2T> r2 = state;

    auto res5 = +r2["Wow"];
    auto res6 = r2["Wow"].make().get();
    auto cond4 = res5 && res6 && res5.value() == res6.value();
    REQUIRE(cond4);
}
