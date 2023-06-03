/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <lager/deps.hpp>

#include <boost/hana.hpp>

#include <jsonwrap.hpp>
#include <promise-interface.hpp>

namespace Kazv
{
    class EffectStatus
    {
    public:
        inline EffectStatus() : m_succ(true) {}
        inline EffectStatus(bool succ) : m_succ(succ) {}
        inline EffectStatus(bool succ, JsonWrap d) : m_succ(succ), m_data(d) {}

        /**
         * Get whether this is successful.
         *
         * @return Whether this is successful.
         */
        inline bool success() const { return m_succ; }
        /**
         * Conversion to bool.
         *
         * @return `success()`.
         */
        inline explicit operator bool() const { return success(); }
        /**
         * Get the attached data.
         *
         * @return A JsonWrap containing the attached data.
         */
        inline const JsonWrap &data() const { return m_data; }

        /**
         * Get the data at `key`.
         *
         * This requires `data()` to contain a json object.
         *
         * @param key The key.
         * @return A json with the data at `key`.
         */
        inline const json &dataJson(std::string key) const {
            return data().get().at(key);
        }

        /**
         * Get the data at `index` at `key`.
         *
         * This requires `data()` to contain a json array of json objects.
         *
         * @param index The index.
         * @param key The key.
         * @return A json with the data at `index` at `key`.
         */
        inline const json &dataJson(int index, std::string key) const {
            return data().get().at(index).at(key);
        }

        /**
         * Get the data string at `key`.
         *
         * This requires `data()` to contain a json object, and
         * `data().get().at(key)` to be a json string.
         *
         * @param key The key.
         * @return A std::string for the data at `key`.
         */
        inline std::string dataStr(std::string key) const {
            return dataJson(key).template get<std::string>();
        }

        /**
         * Get the data at `index` at `key`.
         *
         * This requires `data()` to contain a json array of json objects,
         * and `data().get().at(index).at(key)` to be a json string.
         *
         * @param index The index.
         * @param key The key.
         * @return A std::string for the data at `index` at `key`.
         */
        inline std::string dataStr(int index, std::string key) const {
            return dataJson(index, key).template get<std::string>();
        }
    private:
        bool m_succ;
        JsonWrap m_data;
    };

    inline EffectStatus createDefaultForPromiseThen(EffectStatus)
    {
        return EffectStatus{true, json::array()};
    }

    inline EffectStatus dataCombine(EffectStatus a, EffectStatus b)
    {
        auto succ = a.success() && b.success();
        auto data = a.data().get().is_array()
            ? a.data().get()
            : json::array({a.data().get()});
        if (b.data().get().is_array()) {
            for (const auto &i: b.data().get()) {
                data.push_back(i);
            }
        } else {
            data.push_back(b.data().get());
        }
        return {succ, data};
    }

    inline EffectStatus dataCombineNone(EffectStatus)
    {
        return EffectStatus(true);
    }

    using DefaultRetType = EffectStatus;

    template<class T, class Action, class Deps = lager::deps<>>
    class ContextBase : public Deps
    {
    public:
        using RetType = T;
        using PromiseInterfaceT = SingleTypePromiseInterface<RetType>;
        using PromiseT = SingleTypePromise<RetType>;
        template<class Func>
        ContextBase(Func &&dispatcher, PromiseInterfaceT ph, Deps deps)
            : Deps(std::move(deps))
            , m_ph(ph)
            , m_dispatcher(std::forward<Func>(dispatcher))
            {
            }

        template<class AnotherAction, class AnotherDeps,
                 std::enable_if_t<std::is_convertible_v<Action, AnotherAction>
                                  && std::is_convertible_v<AnotherDeps, Deps>, int> = 0>
        ContextBase(const ContextBase<RetType, AnotherAction, AnotherDeps> &that)
            : Deps(that)
            , m_ph(that.m_ph)
            , m_dispatcher(that.m_dispatcher)
            {
            }

        template<class AnotherAction, class AnotherDeps, class Conv,
                 std::enable_if_t<std::is_convertible_v<std::invoke_result_t<Conv, Action>, AnotherAction>
                                  && std::is_convertible_v<AnotherDeps, Deps>, int> = 0>
        ContextBase(const ContextBase<RetType, AnotherAction, AnotherDeps> &that, Conv &&conv)
            : Deps(that)
            , m_ph(that.m_ph)
            , m_dispatcher([=,
                            thatDispatcher=that.m_dispatcher,
                            conv=std::forward<Conv>(conv)](Action a) {
                               thatDispatcher(conv(std::move(a)));
                           })
            {
            }

        PromiseT dispatch(Action a) const {
            return m_dispatcher(std::move(a));
        }

        decltype(auto) deps() {
            return static_cast<Deps &>(*this);
        }

        template<class Func>
        PromiseT createPromise(Func func) const {
            return m_ph.create(std::move(func));
        }

        template<class Func>
        PromiseT createWaitingPromise(Func func) const {
            return m_ph.createResolveToPromise(std::move(func));
        }

        PromiseT createResolvedPromise(RetType v) const {
            return m_ph.createResolved(v);
        }

        PromiseInterfaceT promiseInterface() const {
            return m_ph;
        }

    private:
        template<class R2, class A2, typename D2>
        friend class ContextBase;
        PromiseInterfaceT m_ph;
        std::function<PromiseT(Action)> m_dispatcher;
    };

    template<class A, class D = lager::deps<>>
    using Context = ContextBase<DefaultRetType, A, D>;

    template<class T, class Action, class Deps = lager::deps<>>
    class EffectBase
    {
    public:
        using RetType = T;
        using PromiseT = SingleTypePromise<RetType>;
        using ContextT = ContextBase<RetType, Action, Deps>;

        /**
         * Constructor.
         *
         * @return An effect that runs `func` upon invocation.
         * The effect will return a Promise that
         * \arg resolves after the effect is invoked, to
         * `PromiseCombination::defaultForPromiseThen(RetType())`,
         * if `func(ctx)` returns void;
         * \arg resolves after `func(ctx)` is resolved, to
         * what `func(ctx)` resolves to, if `func(ctx)`
         * returns a Promise;
         * \arg resolves after the effect is invoked, to
         * `func(ctx)` (converted to `RetType` if it is not already one),
         * otherwise.
         */
        template<class Func>
        EffectBase(Func func) {
            if constexpr (std::is_same_v<std::invoke_result_t<Func, ContextT>, void>) {
                m_d = [func=std::move(func)](const auto &ctx) {
                          return ctx.createPromise(
                              [ctx,
                               func](auto resolve) {
                                  func(ctx);
                                  resolve(PromiseCombination::defaultForPromiseThen(RetType()));
                              });
                      };
            } else {
                m_d = [func=std::move(func)](const auto &ctx) {
                          return ctx.createResolvedPromise(PromiseCombination::defaultForPromiseThen(RetType()))
                              .then([ctx,
                                     func](auto) {
                                        return func(ctx);
                                    });
                      };
            }
        }

        PromiseT operator()(const ContextT &ctx) const {
            return m_d(ctx);
        }

    private:
        std::function<PromiseT(const ContextT &)> m_d;
    };

    template<class A, class D = lager::deps<>>
    using Effect = EffectBase<DefaultRetType, A, D>;

    template<class Reducer, class RetType, class Model, class Action, class Deps>
    constexpr bool hasEffect = boost::hana::is_valid(
        []() -> decltype((void)EffectBase<RetType, Action, Deps>(
                             std::get<1>(std::declval<std::invoke_result_t<Reducer, Model, Action>>()))) {}
        )();

}
