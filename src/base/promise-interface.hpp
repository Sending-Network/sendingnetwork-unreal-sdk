/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <memory>
#include <type_traits>
#include <functional>

namespace Kazv
{
    class TypelessPromise
    {
    };

    template<template<class> class DeriveT, class T>
    class AbstractPromise;

    namespace detail
    {
        template<class T, class = void>
        struct PromiseParameterT
        {
            using type = T;
        };

        template<class PromiseT>
        struct PromiseParameterT<PromiseT,
                                 std::void_t<std::enable_if_t<std::is_base_of_v<TypelessPromise, PromiseT>, int>>>
        {
            using type = typename PromiseT::DataT;
        };

        template<class T>
        using PromiseParameter = typename PromiseParameterT<T>::type;

        template<class T, class = void>
        struct PromiseResult
        {
        };

        template<class T>
        struct PromiseResult<T, std::void_t<std::invoke_result_t<T>>>
        {
            using Res = std::invoke_result_t<T>;

            using type = PromiseParameter<Res>;
        };

        template<class T>
        using PromiseResultT = typename PromiseResult<T>::type;


        template<class T, class P>
        struct PromiseThenResultT
        {
            using Res = std::invoke_result_t<T, PromiseParameter<P>>;

            using type = PromiseParameter<Res>;
        };
    }

    template<class T, class P>
    using PromiseThenResult = typename detail::PromiseThenResultT<T, P>::type;

    template<class T>
    constexpr auto isPromise = std::is_base_of_v<TypelessPromise, T>;

    template<template<class> class DeriveT, class T>
    class AbstractPromise : TypelessPromise
    {
    public:
        using DataT = T;

        static_assert(!isPromise<DataT>, "Cannot create a promise of promise");

        AbstractPromise(DeriveT<T> *obj) : m_derived(obj) {}

        template<class FuncT>
        auto then(FuncT &&func)
            -> DeriveT<PromiseThenResult<FuncT, DataT>> {
            return m_derived->then(std::forward<FuncT>(func));
        }

    private:
        DeriveT<T> *m_derived;
    };

    namespace PromiseCombination
    {
        constexpr bool createDefaultForPromiseThen(bool) { return true; }
        constexpr bool dataCombine(bool a, bool b) { return a && b; }
        constexpr bool dataCombineNone(bool) { return true; }

        template<class T, class = void>
        struct DefaultForPromiseT
        {
            constexpr T operator()() const { return T(); }
        };

        template<class T>
        struct DefaultForPromiseT<
            T,
            std::void_t<decltype(createDefaultForPromiseThen(std::declval<T>()))>>
        {
            constexpr T operator()() const { return createDefaultForPromiseThen(T()); }
        };

        template<class T>
        constexpr T defaultForPromiseThen(T)
        {
            return DefaultForPromiseT<T>{}();
        }
    }


    template<class T>
    class SingleTypePromise : TypelessPromise
    {
    public:
        using DataT = T;

        template<class DeriveT>
        SingleTypePromise(DeriveT obj)
            : m_d(std::unique_ptr<Concept>(new Model<DeriveT>(std::move(obj)))) {}

        SingleTypePromise(const SingleTypePromise &that)
            : m_d(that.m_d->clone())
            {}

        SingleTypePromise(SingleTypePromise &&that)
            : m_d(std::move(that.m_d))
            {}

        SingleTypePromise &operator=(const SingleTypePromise &that) {
            m_d = that.m_d->clone();
            return *this;
        }

        SingleTypePromise &operator=(SingleTypePromise &&that) {
            m_d = std::move(that.m_d);
            return *this;
        }

        template<class F>
        SingleTypePromise then(F &&f) {
            if constexpr (std::is_same_v<std::invoke_result_t<F, DataT>, void>) {
                return m_d->thenVoid(f);
            } else if constexpr(isPromise<std::invoke_result_t<F, DataT>>) {
                return m_d->thenPromise(f);
            } else {
                return m_d->thenData(f);
            }
        }

        bool ready() const { return m_d->ready(); }
        DataT get() const { return m_d->get(); }

    private:
        struct Concept
        {
            virtual ~Concept() = default;
            virtual SingleTypePromise thenVoid(std::function<void(DataT)> f) = 0;
            virtual SingleTypePromise thenData(std::function<DataT(DataT)> f) = 0;
            virtual SingleTypePromise thenPromise(std::function<SingleTypePromise(DataT)> f) = 0;
            virtual std::unique_ptr<Concept> clone() const = 0;
            virtual bool ready() const = 0;
            virtual DataT get() const = 0;
        };

        template<class DeriveT>
        struct Model : public Concept
        {
            Model(DeriveT obj) : instance(std::move(obj)) {}
            ~Model() override = default;
            SingleTypePromise thenVoid(std::function<void(DataT)> f) override {
                return instance.then([=](DataT v) {
                                         f(v);
                                         return PromiseCombination::defaultForPromiseThen(DataT());
                                     });
            }
            SingleTypePromise thenData(std::function<DataT(DataT)> f) override {
                return instance.then([=](DataT v) { return f(v); });
            }
            SingleTypePromise thenPromise(std::function<SingleTypePromise(DataT)> f) override {
                return instance.then([=](DataT v) { return f(v); });
            }
            std::unique_ptr<Concept> clone() const override {
                return std::unique_ptr<Concept>(new Model<DeriveT>(instance));
            }
            bool ready() const override {
                return instance.ready();
            }
            DataT get() const override {
                return instance.get();
            }
            DeriveT instance;
        };

        std::unique_ptr<Concept> m_d;
    };

    using BoolPromise = SingleTypePromise<bool>;

    template<class DeriveT, template<class> class PromiseT>
    class PromiseInterface
    {
    public:
        PromiseInterface(DeriveT *obj) : m_derived(obj) {}

        template<class T, class FuncT>
        auto create(FuncT &&func) -> PromiseT<T>;

        template<class T>
        auto createResolved(T &&val) -> PromiseT<T>;

    private:
        DeriveT *m_derived;
    };

    template<class DeriveT, template<class> class PromiseT>
    template<class T, class FuncT>
    auto PromiseInterface<DeriveT, PromiseT>::create(FuncT &&func) -> PromiseT<T> {
        return m_derived->create(std::forward<FuncT>(func));
    }

    template<class DeriveT, template<class> class PromiseT>
    template<class T>
    auto PromiseInterface<DeriveT, PromiseT>::createResolved(T &&val) -> PromiseT<T> {
        return m_derived->createResolved(std::forward<T>(val));
    }

    template<class T>
    class SingleTypePromiseInterface
    {
    public:
        using DataT = T;
        using PromiseT = SingleTypePromise<DataT>;
        using ResolveT = std::function<void(DataT)>;
        using ResolveToPromiseT = std::function<void(PromiseT)>;

        template<class DeriveT>
        SingleTypePromiseInterface(DeriveT obj)
            : m_d(std::unique_ptr<Concept>(new Model<std::decay_t<DeriveT>>(std::move(obj)))) {
            if (! m_d) {
                throw std::logic_error("promise handler is empty");
            }
        }

        SingleTypePromiseInterface(const SingleTypePromiseInterface &that)
            : m_d(that.m_d) {
            if (! m_d) {
                throw std::logic_error("promise handler is empty");
            }
        }
        SingleTypePromiseInterface(SingleTypePromiseInterface &&that)
            : m_d(std::move(that.m_d)) {
            if (! m_d) {
                throw std::logic_error("promise handler is empty");
            }
        }

        SingleTypePromiseInterface &operator=(const SingleTypePromiseInterface &that) {
            m_d = that.m_d;
            return *this;
        }

        SingleTypePromiseInterface &operator=(SingleTypePromiseInterface &&that) {
            m_d = std::move(that.m_d);
            return *this;
        }

        PromiseT create(std::function<void(ResolveT)> f) const {
            return m_d->create(f);
        }

        PromiseT createResolveToPromise(std::function<void(ResolveToPromiseT)> f) const {
            return m_d->createResolveToPromise(f);
        }

        PromiseT createResolved(DataT v) const {
            return m_d->createResolved(v);
        }

        template<class RangeT>
        PromiseT all(RangeT promises) const {
            using PromiseCombination::dataCombine;
            using PromiseCombination::dataCombineNone;
            if (promises.empty()) {
                return createResolved(dataCombineNone(DataT{}));
            }
            auto p1 = *(promises.begin());
            promises.erase(promises.begin());
            if (promises.empty()) {
                return p1;
            }
            return p1.then([*this, promises=std::move(promises)](DataT val) mutable {
                               return all(std::move(promises))
                                   .then([=](DataT val2) {
                                             return dataCombine(val, val2);
                                         });
                           });
        }

    private:
        struct Concept
        {
            virtual ~Concept() = default;
            virtual PromiseT create(std::function<void(ResolveT)> f) = 0;
            virtual PromiseT createResolveToPromise(std::function<void(ResolveToPromiseT)> f) = 0;
            virtual PromiseT createResolved(DataT v) = 0;
        };

        template<class DeriveT>
        struct Model : public Concept
        {
            static_assert(std::is_same_v<std::decay_t<DeriveT>, DeriveT>, "DeriveT must not be a reference");
            Model(DeriveT obj) : instance(std::move(obj)) {}
            ~Model() override = default;
            PromiseT create(std::function<void(ResolveT)> f) override {
                return instance.template create<DataT>(f);
            }
            PromiseT createResolveToPromise(std::function<void(ResolveToPromiseT)> f) override {
                return instance.template create<DataT>(f);
            }
            PromiseT createResolved(DataT v) override {
                return instance.createResolved(v);
            }
            DeriveT instance;
        };

        std::shared_ptr<Concept> m_d;
    };

    using BoolPromiseInterface = SingleTypePromiseInterface<bool>;
}
