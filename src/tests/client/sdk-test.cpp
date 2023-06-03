/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
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
#include <random-generator.hpp>

using namespace Kazv;

TEST_CASE("makeSdk should work", "[client][sdk]")
{
    auto io = boost::asio::io_context{};
    auto jh = Kazv::CprJobHandler{io.get_executor()};
    auto ee = Kazv::LagerStoreEventEmitter(lager::with_boost_asio_event_loop{io.get_executor()});

    auto sdk = Kazv::makeSdk(
        Kazv::SdkModel{},
        jh,
        ee,
        Kazv::AsioPromiseHandler{io.get_executor()},
        zug::identity
        );

    REQUIRE(sdk.context().has<SdkModelCursorTag>());

    REQUIRE(sdk.context().has<RandomInterface &>());
}

TEST_CASE("makeSdk should work with withRandomGenerator() enhancer", "[client][sdk]")
{
    auto io = boost::asio::io_context{};
    auto jh = Kazv::CprJobHandler{io.get_executor()};
    auto ee = Kazv::LagerStoreEventEmitter(lager::with_boost_asio_event_loop{io.get_executor()});

    auto fakeGenerator = []() { return 1; };
    auto rg = RandomInterface(fakeGenerator);

    auto sdk = Kazv::makeSdk(
        Kazv::SdkModel{},
        jh,
        ee,
        Kazv::AsioPromiseHandler{io.get_executor()},
        zug::identity,
        withRandomGenerator(rg)
        );

    REQUIRE(sdk.context().has<RandomInterface &>());

    auto &generatorInSdk = sdk.context().get<RandomInterface &>();
    REQUIRE(generatorInSdk() == 1);
    REQUIRE(generatorInSdk.fillRange(std::vector<int>(10)) == std::vector<int>(10, 1));
}
