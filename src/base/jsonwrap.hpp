/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include "libkazv-config.hpp"

#include <boost/serialization/version.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/split_member.hpp>

#include <nlohmann/json.hpp>
#include <immer/box.hpp>

namespace Kazv
{
    using json = nlohmann::json;

    class JsonWrap
    {
        // Cannot directly use box here, because it causes the resulting json
        // to be wrapped into an array.
        // https://github.com/arximboldi/immer/issues/155
        struct Private
        {
            json j;
        };

        immer::box<Private> m_d;
    public:
        JsonWrap() : m_d(Private{json()}) {}
        JsonWrap(json&& j) : m_d(Private{std::move(j)}) {}
        JsonWrap(const json& j) : m_d(Private{j}) {}

        const json &get() const { return m_d.get().j; }
        operator json() const { return m_d.get().j; }

        template <class Archive>
        void save(Archive &ar, std::uint32_t const /*version*/) const {
            ar << get().dump();
        }

        template <class Archive>
        void load(Archive &ar, std::uint32_t const /*version*/) {
            std::string j;
            ar >> j;
            m_d = immer::box<Private>(Private{json::parse(std::move(j))});
        }
        BOOST_SERIALIZATION_SPLIT_MEMBER()
    };
}

BOOST_CLASS_VERSION(Kazv::JsonWrap, 0)

namespace nlohmann
{
    template <>
    struct adl_serializer<Kazv::JsonWrap> {
        static void to_json(json& j, Kazv::JsonWrap w) {
            j = w.get();
        }

        static void from_json(const json& j, Kazv::JsonWrap &w) {
            w = Kazv::JsonWrap(j);
        }
    };

}

namespace Kazv
{
    inline bool operator==(JsonWrap a, JsonWrap b)
    {
        return a.get() == b.get();
    }
}
