/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include <libkazv-config.hpp>

#include <boost/serialization/nvp.hpp>
#include <boost/serialization/split_free.hpp>

#include <optional>

namespace boost::serialization
{
    template<class Archive, class T>
    void save(Archive &ar, const std::optional<T> &o, const unsigned int /* version */)
    {
        auto hasValue = o.has_value();
        ar << BOOST_SERIALIZATION_NVP(hasValue);

        if (hasValue) {
            const auto &value = o.value();
            ar << BOOST_SERIALIZATION_NVP(value);
        }
    }

    template<class Archive, class T>
    void load(Archive &ar, std::optional<T> &o, const unsigned int /* version */)
    {
        auto hasValue = bool{};
        ar >> BOOST_SERIALIZATION_NVP(hasValue);

        o.reset();

        if (hasValue) {
            T value;
            ar >> BOOST_SERIALIZATION_NVP(value);
            o = std::move(value);
        }
    }

    template<class Archive,
             class T>
    inline void serialize(Archive &ar, std::optional<T> &o, const unsigned int version)
    {
        boost::serialization::split_free(ar, o, version);
    }
}
