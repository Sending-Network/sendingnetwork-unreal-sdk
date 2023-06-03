/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <libkazv-config.hpp>

#include <boost/serialization/nvp.hpp>
#include <boost/serialization/split_free.hpp>

#include <immer/array.hpp>
#include <immer/array_transient.hpp>

namespace boost::serialization
{
    template<class Archive,
             class T,
             class MP>
    void save(Archive &ar, const immer::array<T, MP> &v, const unsigned int /* version */)
    {
        auto size = v.size();
        ar << BOOST_SERIALIZATION_NVP(size);

        for (const auto &i : v) {
            ar << i;
        }
    }

    template<class Archive,
             class T,
             class MP>
    void load(Archive &ar, immer::array<T, MP> &v, const unsigned int /* version */)
    {
        using VecT = immer::array<T, MP>;
        using TransientT = decltype(v.transient());
        using SizeT = decltype(v.size());
        using ValueT = typename VecT::value_type;

        SizeT size{};
        ar >> BOOST_SERIALIZATION_NVP(size);
        TransientT transient = VecT(size).transient();

        for (auto i = SizeT{}; i != size; ++i) {
            ValueT val;
            ar >> val;
            transient.set(i, std::move(val));
        }

        v = transient.persistent();
    }

    template<class Archive,
             class T,
             class MP>
    inline void serialize(Archive &ar, immer::array<T, MP> &v, const unsigned int version)
    {
        boost::serialization::split_free(ar, v, version);
    }
}
