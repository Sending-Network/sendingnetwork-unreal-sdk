/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include "libkazv-config.hpp"

#include <string>
#include <optional>

namespace Kazv
{
    class NotBut
    {
        std::string m_reason;
    public:
        explicit NotBut(std::string r) : m_reason(r) {}
        std::string reason() const { return m_reason; }
    };

    template<class T>
    class Maybe : public std::optional<T>
    {
        std::string m_reason;
        using BaseT = std::optional<T>;
    public:
        Maybe(T x) : BaseT(x) {}
        Maybe(NotBut r) : BaseT(), m_reason(r.reason()) {}

        std::string reason() const { return m_reason; }
    };

    using MaybeString = Maybe<std::string>;
}
