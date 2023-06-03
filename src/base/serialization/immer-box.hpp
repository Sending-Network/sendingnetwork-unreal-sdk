/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once

#include <libkazv-config.hpp>

#include <boost/serialization/nvp.hpp>
#include <boost/serialization/split_free.hpp>

#include <immer/box.hpp>

namespace boost::serialization
{

    template <class Archive, class T, class MP>
    void save(Archive &ar, const immer::box<T, MP> &box, const unsigned int /* version */)
    {
        ar << box.get();
    }

    template <class Archive, class T, class MP>
    void load(Archive &ar, immer::box<T, MP> &box, const unsigned int /* version */)
    {
        T val;
        ar >> val;

        box = val;
    }

    template<class Archive, class T, class MP>
    inline void serialize(Archive &ar, immer::box<T, MP> &box, const unsigned int version)
    {
        boost::serialization::split_free(ar, box, version);
    }

}
