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

#ifdef KAZV_USE_THREAD_SAFETY_HELPER
using namespace Kazv;

TEST_CASE("Thread-safety verification should work", "[client][thread-safety]")
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

    auto ctx = sdk.context();

    REQUIRE(ctx.has<EventLoopThreadIdKeeper>());

    auto client = sdk.client();

    bool thrown = false;
    try {
        client.userId();
    } catch (const ThreadNotMatchException &) {
        thrown = true;
    }
    REQUIRE(! thrown); // event loop has not started yet, so do not throw

    auto g = boost::asio::make_work_guard(io.get_executor());

    std::thread([&io] { io.run(); }).detach();

    // wait till the event loop thread is logged
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    thrown = false;
    std::thread([=, &thrown] {
                    try {
                        client.userId();
                    } catch (const ThreadNotMatchException &) {
                        thrown = true;
                    }
                }).join();
    REQUIRE(thrown);

    ctx.createResolvedPromise({})
        .then([](auto &&) {})
        .then([&client](auto &&) {
                  client.userId();
              });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    thrown = false;
    try {
        client.userId();
    } catch (const ThreadNotMatchException &) {
        thrown = true;
    }
    REQUIRE(thrown);
}

TEST_CASE("Thread-safety verification from secondary root should work", "[client][thread-safety]")
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

    auto ctx = sdk.context();

    auto guard = boost::asio::make_work_guard(io.get_executor());

    std::thread([&io] { io.run(); }).detach();

    auto io2 = boost::asio::io_context{};

    auto sr = sdk.createSecondaryRoot(lager::with_boost_asio_event_loop{io2.get_executor()});

    auto client2 = sdk.clientFromSecondaryRoot(sr);

    bool thrown = false;
    std::thread([client2, &thrown] {
                    try {
                        client2.userId();
                    } catch(const ThreadNotMatchException &) {
                        thrown = true;
                    }
                }).join();

    REQUIRE(thrown);

    thrown = false;
    std::thread([&client2, &thrown] {
                    try {
                        client2.userId();
                    } catch(const ThreadNotMatchException &) {
                        thrown = true;
                    }
                }).join();

    REQUIRE(thrown);

    io2.run();
}

TEST_CASE("Thread-safety verification should properly verify toEventLoop calls", "[client][thread-safety]")
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

    auto ctx = sdk.context();

    auto io2 = boost::asio::io_context{};

    auto sr = sdk.createSecondaryRoot(lager::with_boost_asio_event_loop{io2.get_executor()});

    auto client2 = sdk.clientFromSecondaryRoot(sr);

    auto room2 = client2.room("!foo:example.org");

    ctx.createResolvedPromise({})
        .then([client2, room2, guard=boost::asio::make_work_guard(io.get_executor())](auto &&) {
                  bool thrown = false;

                  try {
                      client2.userId();
                  } catch (const ThreadNotMatchException &) {
                      thrown = true;
                  }
                  REQUIRE(thrown);

                  thrown = false;
                  try {
                      room2.roomId();
                  } catch (const ThreadNotMatchException &) {
                      thrown = true;
                  }
                  REQUIRE(thrown);
              });

    ctx.createResolvedPromise({})
        .then([client2=client2.toEventLoop(), room2=room2.toEventLoop(),
               guard=boost::asio::make_work_guard(io.get_executor())](auto &&) {
                  bool thrown2 = false;

                  try {
                      client2.userId();
                  } catch (const ThreadNotMatchException &) {
                      thrown2 = true;
                  }
                  REQUIRE(!thrown2);

                  thrown2 = false;

                  try {
                      room2.roomId();
                  } catch (const ThreadNotMatchException &) {
                      thrown2 = true;
                  }
                  REQUIRE(!thrown2);
              });

    std::thread([&io] { io.run(); }).detach();

    io2.run();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

#endif
