/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include "libkazv-config.hpp"

#include <iterator>
#include <boost/hana/type.hpp>

#include <lager/constant.hpp>
#include <lager/reader.hpp>
#include <lager/lenses/optional.hpp>

#include <zug/into.hpp>
#include <zug/tuplify.hpp>
#include <zug/transducer/each.hpp>
#include <zug/run.hpp>

namespace Kazv
{
    namespace detail
    {
        constexpr auto hasPushBack = boost::hana::is_valid(
            [](auto t) -> decltype(
                (void)
                std::declval<typename decltype(t)::type>().push_back(std::declval<typename decltype(t)::type::value_type>())) { });

        constexpr auto hasInsert = boost::hana::is_valid(
            [](auto t) -> decltype(
                (void)
                std::declval<typename decltype(t)::type>().insert(std::declval<typename decltype(t)::type::value_type>())) { });

        struct ImmerPushBackOrInsertT
        {
            template<class Container, class ...InputRanges>
            auto operator()(Container container, InputRanges &&...ins) {
                using ContT = std::decay_t<Container>;
                if constexpr (hasPushBack(boost::hana::type_c<ContT>)) {
                    return std::move(container)
                        .push_back(zug::tuplify(std::forward<InputRanges>(ins)...));
                } else {
                    static_assert(hasInsert(boost::hana::type_c<ContT>),
                                  "Container must have either push_back() or insert() method");
                    return std::move(container)
                        .insert(zug::tuplify(std::forward<InputRanges>(ins)...));
                }
            }
        };

        inline ImmerPushBackOrInsertT immerPushBackOrInsert{};

        struct IntoImmerT
        {
            // We check for both transient_type and persistent_type
            // because for some containers, transient_type is not
            // implemented.
            constexpr static auto hasTransientType = boost::hana::is_valid(
                [](auto t) -> boost::hana::type<typename decltype(t)::type::transient_type::persistent_type> {});

            template<class Container, class Func, class ...InputRanges>
            auto operator()(Container &&m, Func &&transducer, InputRanges &&...ins) const {
                using ContainerT = std::decay_t<Container>;
                if constexpr (hasTransientType(boost::hana::type_c<ContainerT>)) {
                    using TransientT = typename ContainerT::transient_type;
                    return zug::into(
                        std::forward<TransientT>(m.transient()),
                        std::forward<Func>(transducer),
                        std::forward<InputRanges>(ins)...)
                        .persistent();
                } else {
                    ContainerT c;
                    zug::run(
                        std::forward<Func>(transducer)
                        | zug::each(
                            [&](auto ...ins) {
                                c = immerPushBackOrInsert(std::move(c), std::move(ins)...);
                            }),
                        std::forward<InputRanges>(ins)...);
                    return c;
                }
            }

        };
    }
    inline detail::IntoImmerT intoImmer{};

    namespace detail
    {
        inline auto looksLikeImmer = boost::hana::is_valid(
            [](auto t) -> boost::hana::type<typename decltype(t)::type::transient_type> { });
        struct ContainerMapT
        {
            template<class ResultContainer, class Func>
            auto operator()(ResultContainer c, Func transducer) {
                return zug::map(
                    [=](auto m) {
                        using ContT = std::decay_t<ResultContainer>;
                        if constexpr (looksLikeImmer(boost::hana::type_c<ContT>)) {
                            return intoImmer(c, transducer, m);
                        } else {
                            return zug::into(c, transducer, m);
                        }
                    });
            }
        };
    }

    inline detail::ContainerMapT containerMap{};

    namespace CursorOp
    {
        template<class Cursor>
        inline auto operator~(Cursor &&c)
        {
            return std::forward<Cursor>(c).make();
        }

        template<class Cursor>
        inline auto operator+(Cursor &&c)
        {
            return (~std::forward<Cursor>(c)).get();
        }
    }

    inline constexpr auto eventContent =
        zug::map([](auto &&event) {
                     return std::forward<decltype(event)>(event).content();
                 });

    namespace detail
    {
        constexpr auto isJsonWrap = boost::hana::is_valid(
            [](auto t) -> decltype((void) std::declval<typename decltype(t)::type>().get()) { });
    }

    template<class T, class V>
    constexpr auto jsonAtOr(T &&key, V &&defaultValue)
    {
        return
            zug::map([key=std::forward<T>(key), def=std::forward<V>(defaultValue)](auto &&j) -> std::decay_t<V> {
                         using JsonT = decltype(j);
                         using ValueT = std::decay_t<V>;
                         try {
                             if constexpr (detail::isJsonWrap(boost::hana::type_c<std::decay_t<JsonT>>)) {
                                 return j.get().contains(key)
                                     ? std::forward<JsonT>(j).get().at(key).template get<ValueT>()
                                     : def;
                             } else {
                                 return j.contains(key)
                                     ? std::forward<JsonT>(j).at(key).template get<ValueT>()
                                     : def;
                             }
                         } catch (const std::exception &) {
                             return def;
                         }
                     });
    }

    namespace detail
    {
        struct AllTrueT
        {
            template<class B1, class ...Bs>
            constexpr auto operator()(B1 &&b1, Bs &&...bs) const {
                return std::forward<B1>(b1)
                    && operator()(std::forward<Bs>(bs)...);
            }

            constexpr auto operator()() const {
                return true;
            }
        };

        constexpr AllTrueT allTrue{};

        struct AnyTrueT
        {
            template<class B1, class ...Bs>
            constexpr auto operator()(B1 &&b1, Bs &&...bs) const {
                return std::forward<B1>(b1)
                    || operator()(std::forward<Bs>(bs)...);
            }

            constexpr auto operator()() const {
                return false;
            }
        };

        constexpr AnyTrueT anyTrue{};
    }

    template<class Cursor, class ...Cursors>
    constexpr auto allCursors(Cursor &&first, Cursors &&...cursors)
    {
        return lager::with(std::forward<Cursor>(first),
                           std::forward<Cursors>(cursors)...)
            .map(detail::allTrue);
    }

    inline auto allCursors()
    {
        return lager::make_constant(detail::allTrue());
    }

    template<class Cursor, class ...Cursors>
    constexpr auto anyCursor(Cursor &&first, Cursors &&...cursors)
    {
        return lager::with(std::forward<Cursor>(first),
                           std::forward<Cursors>(cursors)...)
            .map(detail::anyTrue);
    }

    inline auto anyCursor()
    {
        return lager::make_constant(detail::anyTrue());
    }
}
