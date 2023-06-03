/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include "libkazv-config.hpp"

#include <optional>
#include <string>
#include <variant>

#include <nlohmann/json.hpp>
#include <immer/array.hpp>
#include <immer/flex_vector.hpp>
#include <immer/map.hpp>
#include <boost/hana/type.hpp>
#include <lager/util.hpp>

#include "jsonwrap.hpp"
#include "event.hpp"
#include "descendent.hpp"

namespace Kazv
{
    using Bytes = std::string;

    enum Status : bool
    {
        FAIL,
        SUCC,
    };

    namespace detail
    {
        constexpr auto hasEmptyMethod = boost::hana::is_valid(
            [](auto t) -> decltype((void)std::declval<typename decltype(t)::type>().empty()) {});
        template<class U>
        struct AddToJsonIfNeededT
        {
            template<class T>
            static void call(json &j, std::string name, T &&arg) {
                using Type = std::decay_t<T>;
                if constexpr (detail::hasEmptyMethod(boost::hana::type_c<Type>)) {
                    if (! arg.empty()) {
                        j[name] = std::forward<T>(arg);
                    }
                } else {
                    j[name] = std::forward<T>(arg);
                }
            }
        };

        template<class U>
        struct AddToJsonIfNeededT<std::optional<U>>
        {
            template<class T>
            static void call(json &j, std::string name, T &&arg) {
                if (arg.has_value()) {
                    j[name] = std::forward<T>(arg).value();
                }
            }
        };

    }

    template<class T>
    inline void addToJsonIfNeeded(json &j, std::string name, T &&arg)
    {
        detail::AddToJsonIfNeededT<std::decay_t<T>>::call(j, name, std::forward<T>(arg));
    };

    // Provide a non-destructive way to add the map
    // to json.
    template<class MapT,
             // disallow json object here
             std::enable_if_t<!std::is_same_v<std::decay_t<MapT>, json>
                              && !std::is_same_v<std::decay_t<MapT>, JsonWrap>, int> = 0>
    inline void addPropertyMapToJson(json &j, MapT &&arg)
    {
        for (auto kv : std::forward<MapT>(arg)) {
            auto [k, v] = kv;
            j[k] = v;
        }
    };

    inline void addPropertyMapToJson(json &j, const json &arg)
    {
        for (auto kv : arg.items()) {
            auto [k, v] = kv;
            j[k] = v;
        }
    };

    using EventList = immer::flex_vector<Event>;

    using namespace std::string_literals;

    struct Null {};
    using Variant = std::variant<std::string, JsonWrap, Null>;

    namespace detail
    {
        struct DefaultValT
        {
            template<class T>
            constexpr operator T() const {
                return T();
            }
        };
    }

    constexpr detail::DefaultValT DEFVAL;

    enum RoomMembership
    {
        Invite, Join, Leave
    };

    namespace detail
    {
        // emulates declval() but returns lvalue reference
        template<class T>
        typename std::add_lvalue_reference<T>::type declref() noexcept;
    }
}

namespace nlohmann {
    template <class T, class V>
    struct adl_serializer<immer::map<T, V>> {
        static void to_json(json& j, immer::map<T, V> map) {
            if constexpr (std::is_same_v<T, std::string>) {
                j = json::object();
                for (auto [k, v] : map) {
                    j[k] = v;
                }
            } else {
                j = json::array();
                for (auto [k, v] : map) {
                    j.push_back(k);
                    j.push_back(v);
                }
            }
        }

        static void from_json(const json& j, immer::map<T, V> &m) {
            immer::map<T, V> ret;
            if constexpr (std::is_same_v<T, std::string>) {
                for (const auto &[k, v] : j.items()) {
                    ret = std::move(ret).set(k, v);
                }
            } else {
                for (std::size_t i = 0; i < j.size(); i += 2) {
                    ret = std::move(ret).set(j[i], j[i+1]);
                }
            }
            m = ret;
        }
    };

    template <class T>
    struct adl_serializer<immer::array<T>> {
        static void to_json(json& j, immer::array<T> arr) {
            j = json::array();
            for (auto i : arr) {
                j.push_back(json(i));
            }
        }

        static void from_json(const json& j, immer::array<T> &a) {
            immer::array<T> ret;
            if (j.is_array()) {
                for (const auto &i : j) {
                    ret = std::move(ret).push_back(i);
                }
            }
            a = ret;
        }
    };

    template <class T>
    struct adl_serializer<immer::flex_vector<T>> {
        static void to_json(json& j, immer::flex_vector<T> arr) {
            j = json::array();
            for (auto i : arr) {
                j.push_back(json(i));
            }
        }

        static void from_json(const json& j, immer::flex_vector<T> &a) {
            immer::flex_vector<T> ret;
            if (j.is_array()) {
                for (const auto &i : j) {
                    ret = std::move(ret).push_back(i.get<T>());
                }
            }
            a = ret;
        }
    };

    template <>
    struct adl_serializer<Kazv::Variant> {
        static void to_json(json& j, const Kazv::Variant &var) {
            std::visit(lager::visitor{
                    [&j](std::string i) { j = i; },
                    [&j](Kazv::JsonWrap i) { j = i; },
                    [&j](Kazv::Null) { j = nullptr; }
                }, var);
        }

        static void from_json(const json& j, Kazv::Variant &var) {
            if (j.is_string()) {
                var = j.get<std::string>();
            } else if (j.is_null()) {
                var = Kazv::Null{};
            } else { // is object
                var = Kazv::Variant(Kazv::JsonWrap(j));
            }
        }
    };
}
