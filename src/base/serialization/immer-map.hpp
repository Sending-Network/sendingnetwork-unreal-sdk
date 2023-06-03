/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once

#include <libkazv-config.hpp>

#include <boost/serialization/nvp.hpp>
#include <boost/serialization/split_free.hpp>

#include <immer/map.hpp>

namespace boost::serialization
{

    template <class Archive, class K, class T, class H, class E, class MP>
    void save(Archive &ar, const immer::map<K, T, H, E, MP> &map, const unsigned int /* version */)
    {
        auto size = map.size();
        ar << BOOST_SERIALIZATION_NVP(size);
        for (const auto &[k, v] : map) {
            ar << k << v;
        }
    }

    template <class Archive, class K, class T, class H, class E, class MP>
    void load(Archive &ar, immer::map<K, T, H, E, MP> &map, const unsigned int /* version */)
    {
        // map transient is not yet implemented
        // using TransientT = decltype(v.transient());
        using SizeT = decltype(map.size());

        map = {};

        SizeT size{};
        ar >> BOOST_SERIALIZATION_NVP(size);

        for (auto i = SizeT{}; i < size; ++i) {
            K k;
            T v;
            ar >> k >> v;
            map = std::move(map).set(std::move(k), std::move(v));
        }

        assert(size == map.size());
    }

    template<class Archive, class K, class T, class H, class E, class MP>
    inline void serialize(Archive &ar, immer::map<K, T, H, E, MP> &m, const unsigned int version)
    {
        boost::serialization::split_free(ar, m, version);
    }

}
