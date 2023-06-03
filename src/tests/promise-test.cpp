/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <catch2/catch_all.hpp>

#include <asio-promise-handler.hpp>

#include <context.hpp>

using namespace Kazv;

struct MockDataStruct
{
    int i{};
};

TEST_CASE("Promise should behave properly", "[promise]")
{
    boost::asio::io_context ioContext;
    auto ph = AsioPromiseHandler(ioContext.get_executor());
    std::vector<int> v;

    auto p1 = ph.create<int>([&v](auto resolve) {
                                 v.push_back(1);
                                 resolve(2);
                             });

    auto p2 = p1.then([&v, &ph](int val) {
                          v.push_back(val);
                          return ph.createResolved(3);
                      });

    auto p3 = p2.then([&v, &ph](int val) {
                          v.push_back(val);
                          return ph.createResolved(-1);
                      });

    auto p4 = p3.then([](int val) {
                          REQUIRE(val == -1);
                          return 5;
                      });

    auto p5 = p4.then([](int val) {
                          REQUIRE(val == 5);
                          return MockDataStruct{6};
                      });

    auto p6 = p5.then([](MockDataStruct m) {
                          REQUIRE(m.i == 6);
                          return 0;
                      });

    auto pTimer = ph.create<int>([&ioContext](auto resolve) {
                                     auto timer = std::make_shared<boost::asio::steady_timer>(ioContext);
                                     timer->expires_after(std::chrono::milliseconds(300));
                                     timer->async_wait(
                                         [timer, resolve](const boost::system::error_code& error) {
                                             if (! error) {
                                                 resolve(20);
                                             }
                                         });
                                 });

    auto pTimer2 = pTimer.then([](int val) {
                                   REQUIRE(val == 20);
                                   return 0;
                               });

    ioContext.run();

    REQUIRE(v == std::vector<int>{ 1, 2, 3 });
}


TEST_CASE("BoolPromise should behave properly", "[promise]")
{
    boost::asio::io_context ioContext;
    auto ph = BoolPromiseInterface(AsioPromiseHandler(ioContext.get_executor()));

    auto p1 = ph.create([](auto resolve) {
                            resolve(true);
                        });
    auto p2 = p1.then([](bool v) {
                          REQUIRE(v == true);
                      });

    auto p3 = p2.then([&](bool v) {
                          REQUIRE(v == true);
                          return ph.createResolved(false);
                      });

    auto p4 = p3.then([](bool v) {
                          REQUIRE(v == false);
                      });


    ioContext.run();
}

TEST_CASE("EffectStatus should combine properly with .all()", "[promise][store]")
{
    boost::asio::io_context ioContext;
    using PH = SingleTypePromiseInterface<EffectStatus>;
    using PromiseT = typename PH::PromiseT;
    auto ph = PH(AsioPromiseHandler(ioContext.get_executor()));

    auto e1 = EffectStatus(true, json{{"foo", "bar"}});
    auto e2 = EffectStatus(true, json{{"foo2", "bar2"}});
    auto e3 = EffectStatus(false, json{{"foo3", "bar3"}});

    auto p1 = ph.createResolved(e1);
    auto p2 = ph.createResolved(e2);
    auto p3 = ph.createResolved(e3);

    SECTION(".all(singlePromise) should give the Promise as-is") {
        ph.all(std::vector<PromiseT>{p1})
            .then([](auto e) {
                      REQUIRE(e.success());
                      REQUIRE(e.dataStr("foo") == "bar");
                  });
    }

    SECTION(".all(multiplePromises) should give out the data"
            " as an array and compute successfulness using &&") {
        ph.all(std::vector<PromiseT>{p2, p3, p1})
            .then([](auto e) {
                      REQUIRE(! e.success());
                      REQUIRE(e.dataStr(0, "foo2") == "bar2");
                      REQUIRE(e.dataStr(1, "foo3") == "bar3");
                      REQUIRE(e.dataStr(2, "foo") == "bar");
                  });
    }

    ioContext.run();
}
