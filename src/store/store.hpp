/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <lager/state.hpp>
#include <lager/deps.hpp>
#include <lager/util.hpp>
#include <lager/context.hpp>
#include <lager/store.hpp>
#include "context.hpp"

namespace Kazv
{
    template<class Action,
             class EffectRetType,
             class Model,
             class Reducer,
             class Deps = lager::deps<>,
             class Tag = lager::automatic_tag>
    class StoreBase
    {
    public:
        using RetType = EffectRetType;
        using PromiseInterfaceT = SingleTypePromiseInterface<RetType>;
        using PromiseT = SingleTypePromise<RetType>;
        using ContextT = ContextBase<RetType, Action, Deps>;

        template<class PH>
        StoreBase(Model initialModel, Reducer reducer, PH &&ph, Deps deps)
            : m_d{std::make_shared<Private>(
                lager::make_state(std::move(initialModel), Tag{}),
                reducer,
                PromiseInterfaceT{std::forward<PH>(ph)},
                deps)}
            {}

        StoreBase(const StoreBase &that) = delete;
        StoreBase &operator=(const StoreBase &that) = delete;

        StoreBase(StoreBase &&that)
            : m_d(std::move(that.m_d))
            {}

        StoreBase &operator=(StoreBase &&that) {
            m_d = std::move(that.m_d);
            return *this;
        }

        auto dispatch(Action a) -> PromiseT {
            return m_d->dispatch(std::move(a));
        };

        operator lager::reader<Model>() const {
            return m_d->state;
        }

        lager::reader<Model> reader() const {
            return m_d->state;
        }

        template<class A2, class D2>
        operator Context<A2, D2>() const {
            return m_d->ctx;
        }

        ContextT context() const {
            return m_d->ctx;
        }

    private:
        struct Private
        {
            Private(lager::state<Model, Tag> state,
                    Reducer reducer,
                    PromiseInterfaceT ph,
                    Deps deps)
                : state(std::move(state))
                , reducer(std::move(reducer))
                , ph(std::move(ph))
                  // this Private will remain untouched between moves of StoreBases
                  // so it is safe to capture by referenced
                , ctx([this](auto a) { return dispatch(std::move(a)); }, this->ph, deps)
                {}
            ~Private() = default;
            lager::state<Model, Tag> state;
            Reducer reducer;
            PromiseInterfaceT ph;
            ContextT ctx;

            auto dispatch(Action a) -> PromiseT {
                return ph.createResolved(true)
                    .then(
                        [this, a=std::move(a)](auto) {
                            if constexpr (hasEffect<Reducer, RetType, Model, Action, Deps>) {
                            auto [newModel, eff] = reducer(state.get(), a);
                            state.set(newModel);
                            return eff(ctx);
                        } else {
                            auto newModel = reducer(state.get(), a);
                            state.set(newModel);
                            return ph.createResolved(true);
                        }
                    });
        }
        };
        std::shared_ptr<Private> m_d;
    };

    template<class Action,
             class Model,
             class Reducer,
             class Deps = lager::deps<>,
             class Tag = lager::automatic_tag>
    using Store = StoreBase<Action, DefaultRetType, Model, Reducer, Deps, Tag>;

    namespace detail
    {
        constexpr auto compose()
        {
            return zug::identity;
        }

        template<class F1, class ...Fs>
        constexpr auto compose(F1 &&f1, Fs &&...fs)
        {
            return zug::comp(std::forward<F1>(f1), std::forward<Fs>(fs)...);
        }
    }

    template<class Action,
             class Tag = lager::automatic_tag,
             class Model,
             class Reducer,
             class PH,
             class ...Enhancers
             >
    auto makeStore(Model &&initialModel, Reducer &&reducer, PH &&ph, Enhancers &&...enhancers)
    {
        auto enhancer = detail::compose(std::forward<Enhancers>(enhancers)...);
        auto factory = enhancer(
            [&](auto actionTraits,
                auto &&model,
                auto &&reducer,
                auto &&ph,
                auto &&deps,
                auto &&) {
                using ActionTraits = decltype(actionTraits);

                using ModelF = decltype(model);
                using ReducerF = decltype(reducer);
                using PHF = decltype(ph);
                using DepsF = decltype(deps);

                using ActionT = typename ActionTraits::type;
                using ModelT = std::decay_t<ModelF>;
                using ReducerT = std::decay_t<ReducerF>;
                using DepsT = std::decay_t<DepsF>;
                return Store<ActionT, ModelT, ReducerT, DepsT, Tag>(
                    std::forward<ModelF>(initialModel), std::forward<ReducerF>(reducer),
                    std::forward<PHF>(ph), std::forward<DepsF>(deps));
            });
        return factory(
            lager::type_<Action>{},
            std::forward<Model>(initialModel), std::forward<Reducer>(reducer),
            std::forward<PH>(ph), lager::deps<>{}, Tag{});
    }
}
