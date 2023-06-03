/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#define KAZV_DECLARE_COPYABLE(typeName)         \
    typeName(const typeName &that);             \
    typeName(typeName &&that);                  \
    typeName &operator=(const typeName &that);  \
    typeName &operator=(typeName &&that);

#define KAZV_DEFINE_COPYABLE_UNIQUE_PTR(typeName, privateName)          \
    typeName::typeName(const typeName &that)                            \
        : privateName(std::make_unique<decltype(privateName)::element_type>(*(that.privateName))) \
    {                                                                   \
    }                                                                   \
    typeName::typeName(typeName &&that)                                 \
        : privateName(std::move(that.privateName))                      \
    {                                                                   \
    }                                                                   \
    typeName &typeName::operator=(const typeName &that)                 \
    {                                                                   \
        privateName.reset();                                            \
        privateName = std::make_unique<decltype(privateName)::element_type>(*(that.privateName)); \
        return *this;                                                   \
    }                                                                   \
    typeName &typeName::operator=(typeName &&that)                      \
    {                                                                   \
        if (m_d != that.m_d) {                                          \
            privateName.reset();                                        \
            privateName = std::move(that.privateName);                  \
        }                                                               \
        return *this;                                                   \
    }
