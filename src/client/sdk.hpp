/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>
#include <lager/store.hpp>

#include <random>

#include <store.hpp>

#include "sdk-model.hpp"
#include "sdk-model-cursor-tag.hpp"
#include "client.hpp"
#include "thread-safety-helper.hpp"

#include "random-generator.hpp"


namespace Kazv
{
    /**
     * Contain the single source of truth of a sdn sdk.
     */
    template<class EventLoop, class Xform, class ...Enhancers>
    class Sdk
    {
        using ModelT = ::Kazv::SdkModel;
        using ClientT = ::Kazv::ClientModel;
        using ActionT = typename ModelT::Action;
        using CursorT = lager::reader<ModelT>;
        using CursorTSP = std::shared_ptr<CursorT>;

        using StoreT = decltype(
            makeStore<ActionT>(
                std::declval<ModelT>(),
                &ModelT::update,
                std::declval<EventLoop>(),
                lager::with_deps(
                    std::ref(detail::declref<JobInterface>()),
                    std::ref(detail::declref<EventInterface>()),
                    lager::dep::as<SdkModelCursorKey>(std::declval<std::function<CursorTSP()>>()),
                    std::ref(detail::declref<RandomInterface>())
#ifdef KAZV_USE_THREAD_SAFETY_HELPER
                    , std::ref(detail::declref<EventLoopThreadIdKeeper>())
#endif
                    ),
                std::declval<Enhancers>()...)
            );

        using DepsT = lager::deps<JobInterface &, EventInterface &, SdkModelCursorKey, RandomInterface &
#ifdef KAZV_USE_THREAD_SAFETY_HELPER
                                  , EventLoopThreadIdKeeper &
#endif
                                  >;

        using ContextT = Context<ActionT, DepsT>;
    public:
        Sdk(ModelT model,
            JobInterface &jobHandler,
            EventInterface &eventEmitter,
            EventLoop &&eventLoop,
            Xform &&xform,
            Enhancers &&...enhancers)
            : m_d(std::make_unique<Private>(
                      std::move(model), jobHandler, eventEmitter,
                      std::forward<EventLoop>(eventLoop), std::forward<Xform>(xform),
                      std::forward<Enhancers>(enhancers)...)) {}

        /**
         * Get the context associated with this.
         *
         * The returned context is thread-safe if every thread calls with
         * different instances.
         */
        ContextT context() const {
            return m_d->store;
        }

        /**
         * Get a Client representing this.
         *
         * The returned Client belongs to the thread where the promise handler runs.
         */
        Client client() const {
            return {Client::InEventLoopTag{}, ContextT(m_d->store)};
        }

        /**
         * Create a secondary root for this Sdk.
         *
         * @param eventLoop An event loop passed to `lager::make_store`.
         * The resulting secondary root will belong to the thread of this event loop.
         *
         * @return A lager::store that belongs to the thread of `eventLoop`. The
         * store will be kept update with this sdk.
         */
        template<class EL>
        auto createSecondaryRoot(EL &&eventLoop) const {
            auto secondaryStore = lager::make_store<ModelT>(
                ModelT{},
                std::forward<EL>(eventLoop),
                lager::with_reducer([](auto &&, auto next) { return next; }));

            lager::context<ModelT> secondaryCtx = secondaryStore;

            context().createResolvedPromise({})
                .then([secondaryCtx, d=m_d.get()](auto &&) {
                          lager::watch(*(d->sdk),
                                       [secondaryCtx](auto next) { secondaryCtx.dispatch(std::move(next)); });
                      });

            return secondaryStore;
        }

        /**
         * Get a Client representing this.
         *
         * The returned Client belongs to the same thread as `sr`.
         *
         * This function is thread-safe, but it must be called from the thread
         * where `sr` belongs.
         *
         * @param sr The secondary root cursor that represents this sdk.
         *
         * @return A Client representing this in the same thread as `sr`.
         */
        Client clientFromSecondaryRoot(lager::reader<ModelT> sr) const {
            return Client(sr, ContextT(m_d->store));
        }

    private:
        struct Private
        {
            Private(ModelT model,
                    JobInterface &jobHandler,
                    EventInterface &eventEmitter,
                    EventLoop &&eventLoop,
                    Xform &&xform,
                    Enhancers &&...enhancers)
                : rg(RandomInterface{RandomDeviceGenerator{}})
                , store(makeStore<ActionT>(
                            std::move(model),
                            &ModelT::update,
                            std::forward<EventLoop>(eventLoop),
                            lager::with_deps(
                                std::ref(jobHandler),
                                std::ref(eventEmitter),
                                lager::dep::as<SdkModelCursorKey>(
                                    std::function<CursorTSP()>([this] { return sdk; })),
                                std::ref(rg.value())
#ifdef KAZV_USE_THREAD_SAFETY_HELPER
                                , std::ref(keeper)
#endif
                                ),
                            std::forward<Enhancers>(enhancers)...))
                , sdk(std::make_shared<lager::reader<ModelT>>(store.reader().xform(std::forward<Xform>(xform))))
                {
#ifdef KAZV_USE_THREAD_SAFETY_HELPER
                    store.context().createResolvedPromise(EffectStatus{})
                        .then([this](auto &&) {
                                  keeper.set(std::this_thread::get_id());
                              });
#endif
                }
#ifdef KAZV_USE_THREAD_SAFETY_HELPER
            EventLoopThreadIdKeeper keeper;
#endif
            std::optional<RandomInterface> rg;
            StoreT store;
            CursorTSP sdk;
        };

        std::unique_ptr<Private> m_d;
    };

    /**
     * Create an sdk with the provided model.
     *
     * @param sdk The initial SdkModel.
     * @param jobHandler The job handler for the sdk.
     * @param eventEmitter The event emitter for the sdk.
     * @param ph The Promise handler for the sdk.
     * @param xform A function to extract the SdkModel from
     * the model type of the created Store. This is to take into
     * account any enhancer that changes the model type. If you
     * do not use any enhancer that changes the model type, put
     * an identity function (e.g. `zug::identity`) here.
     * @param enhancers The enhancers to pass to `makeStore()`.
     *
     * @return An Sdk created with these parameters.
     *
     * @sa JobInterface, EventInterface, PromiseInterface
     */
    template<class EventLoop, class Xform, class ...Enhancers>
    inline auto makeSdk(SdkModel sdk,
                        JobInterface &jobHandler,
                        EventInterface &eventEmitter,
                        EventLoop &&eventLoop,
                        Xform &&xform,
                        Enhancers &&...enhancers)
        -> Sdk<EventLoop, Xform, Enhancers...>
    {
        return { std::move(sdk),
                 jobHandler,
                 eventEmitter,
                 std::forward<EventLoop>(eventLoop),
                 std::forward<Xform>(xform),
                 std::forward<Enhancers>(enhancers)... };
    }

    /**
     * @return The size of random data needed for makeDefaultSdkWithCryptoRandom
     */
    inline std::size_t makeDefaultSdkWithCryptoRandomSize()
    {
        return Crypto::constructRandomSize();
    }

    template<class EventLoop, class Xform, class ...Enhancers>
    [[deprecated("Use deterministic makeDefaultSdkWithCryptoRandom instead. In the future, this will be removed.")]]
    inline auto makeDefaultEncryptedSdk(
        JobInterface &jobHandler,
        EventInterface &eventEmitter,
        EventLoop &&eventLoop,
        Xform &&xform,
        Enhancers &&...enhancers)
        -> Sdk<EventLoop, Xform, Enhancers...>
    {
        auto m = SdkModel{};
        m.client.crypto = Crypto(RandomTag{}, genRandomData(makeDefaultSdkWithCryptoRandomSize()));

        return makeSdk(std::move(m),
                       jobHandler,
                       eventEmitter,
                       std::forward<EventLoop>(eventLoop),
                       std::forward<Xform>(xform),
                       std::forward<Enhancers>(enhancers)...);
    }

    /**
     * Create an sdk with a default-constructed model, and
     * a Crypto constructed with user-provided random data.
     *
     * @param random The random data to construct Crypto.
     * Must be of at least size `makeDefaultSdkWithCryptoRandomSize()`.
     * @param jobHandler The job handler for the sdk.
     * @param eventEmitter The event emitter for the sdk.
     * @param ph The Promise handler for the sdk.
     * @param xform A function to extract the SdkModel from
     * the model type of the created Store. This is to take into
     * account any enhancer that changes the model type. If you
     * do not use any enhancer that changes the model type, put
     * an identity function (e.g. `zug::identity`) here.
     * @param enhancers The enhancers to pass to `makeStore()`.
     *
     * @return An Sdk created with these parameters.
     *
     * @sa JobInterface, EventInterface, PromiseInterface
     */
    template<class PH, class Xform, class ...Enhancers>
    inline auto makeDefaultSdkWithCryptoRandom(
        RandomData random,
        JobInterface &jobHandler,
        EventInterface &eventEmitter,
        PH &&ph,
        Xform &&xform,
        Enhancers &&...enhancers)
        -> Sdk<PH, Xform, Enhancers...>
    {
        auto m = SdkModel{};
        m.client.crypto = Crypto(RandomTag{}, std::move(random));

        return makeSdk(std::move(m),
                       jobHandler,
                       eventEmitter,
                       std::forward<PH>(ph),
                       std::forward<Xform>(xform),
                       std::forward<Enhancers>(enhancers)...);
    }


    /**
     * An enhancer to use a custom random generator.
     *
     * This is to be used with `makeSdk()`-series functions.
     *
     * @param random The random generator to use.
     */
    inline auto withRandomGenerator(RandomInterface &random)
    {
        return lager::with_deps(std::ref(random));
    }
}
