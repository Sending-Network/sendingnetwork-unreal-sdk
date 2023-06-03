/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <catch2/catch_all.hpp>

#include <asio-promise-handler.hpp>
#include <store.hpp>
#include <context.hpp>

using namespace Kazv;

struct BackInserter
{
    BackInserter(const BackInserter &) = delete;
    BackInserter(BackInserter &&) = default;

    void operator()(int a) const { insertFunc(a); }
    std::function<void(int)> insertFunc;
};

TEST_CASE("Store should behave properly", "[store]")
{
    boost::asio::io_context ioContext;
    auto ph = AsioPromiseHandler(ioContext.get_executor());

    std::vector<int> results;

    BackInserter bi = { [&results](int a) { results.push_back(a); } };

    using Model = int;
    using Action = int;
    using Deps = lager::deps<BackInserter &>;
    using Result = std::pair<Model, Effect<Action, Deps>>;
    using Reducer = std::function<Result(Model, Action)>;

    Reducer update = [&results](Model m, Action a) -> Result {
                         if (a > 0) {
                             return { m + a, lager::noop };
                         } else {
                             auto newM = m + a;
                             return { newM,
                                      [&results, newM](auto &&ctx) {
                                          auto &bi = lager::get<BackInserter &>(ctx);
                                          bi(newM);
                                          return ctx.dispatch(1);
                                      }
                             };
                         }
                     };

    auto store = makeStore<Action>(Model{}, update, ph, lager::with_deps(std::ref(bi)));

    lager::reader<Model> reader = store;

    Context<Action> ctx = store.context();
    Context<Action> ctx2 = ctx;

    store.dispatch(1)
        .then([=](auto res) {
                  REQUIRE(res);
                  REQUIRE(reader.get() == 1);
              })
        .then([=](auto) {
                  return ctx.dispatch(2);
              })
        .then([=](auto) {
                  REQUIRE(reader.get() == 3); // 1 + 2
              })
        .then([=](auto) {
                  return ctx2.dispatch(-5);
              })
        .then([=](auto) {
                  REQUIRE(reader.get() == -1); // 3 - 5 + 1
              })
        .then([=, &ioContext](auto) {
                  return ctx.createWaitingPromise(
                      [=, &ioContext](auto resolve) {
                          auto timer = std::make_shared<boost::asio::steady_timer>(ioContext);
                          timer->expires_after(std::chrono::milliseconds(300));
                          timer->async_wait(
                              [ctx, timer, resolve](const boost::system::error_code& error) {
                                  if (! error) {
                                      resolve(ctx.createResolvedPromise(true)
                                              .then([=](auto) { return ctx.dispatch(10); }));
                                  }
                              });
                      });
              })
        .then([=](auto) {
                  REQUIRE(reader.get() == 9); // -1 + 10
              });

    ioContext.run();
    REQUIRE(results[0] == -2); // 3 - 5
}

TEST_CASE("Store and Context can be moved", "[store]")
{
    boost::asio::io_context ioContext;
    auto ph = AsioPromiseHandler(ioContext.get_executor());

    using Model = int;
    using Action = int;
    using Result = std::pair<Model, Effect<Action>>;
    using Reducer = std::function<Result(Model, Action)>;

    Reducer update = [](Model m, Action a) -> Result {
                         return { m + a, lager::noop };
                     };

    auto store = makeStore<Action>(Model{}, update, ph);

    Context<Action> ctx = store.context();
    lager::reader<Model> reader = store.reader();

    SECTION("Store can be moved without invalidating Contexts") {
        auto p1 = ctx.dispatch(1)
            .then([=](auto) {
                      REQUIRE(reader.get() == 1);
                  });

        auto store2 = std::move(store);

        p1
            .then([=](auto) {
                      return ctx.dispatch(1);
                  })
            .then([=](auto) {
                      REQUIRE(reader.get() == 2);
                  });
    }

    SECTION("Context can be moved without affecting dispatched actions") {
        auto p1 = ctx.dispatch(1)
            .then([=](auto) {
                      REQUIRE(reader.get() == 1);
                  });

        auto ctx2 = std::move(ctx);

        p1
            .then([=](auto) {
                      return ctx2.dispatch(1);
                  })
            .then([=](auto) {
                      REQUIRE(reader.get() == 2);
                  });
    }

    ioContext.run();
}
