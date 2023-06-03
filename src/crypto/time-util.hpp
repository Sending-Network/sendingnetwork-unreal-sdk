/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <chrono>

#include <event.hpp>

namespace Kazv
{
    namespace detail
    {
        using ClockT = std::chrono::system_clock;
    }

    inline Timestamp currentTimeMs()
    {
        auto now = detail::ClockT::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }
}
