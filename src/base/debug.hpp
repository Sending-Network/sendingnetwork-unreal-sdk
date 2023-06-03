/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include "libkazv-config.hpp"
#include <iostream>
#include <chrono>
#include <ctime>

#include <boost/iostreams/stream.hpp>

namespace Kazv
{
    namespace detail
    {
        extern boost::iostreams::stream<boost::iostreams::null_sink> voidOutputHelper;

        enum OutputLevel
        {
            NONE,
            ERROR,
            WARNING,
            INFO,
            DEBUG,
        };

        struct OutputHelper
        {
            std::string category;
            OutputLevel severity;
            OutputLevel level;

            std::ostream &basicFormat() const;

            template<class T>
            std::ostream &operator<<(T &&arg) const {
                if (severity <= level) {
                    return basicFormat() << std::forward<T>(arg);
                } else {
                    return voidOutputHelper;
                }
            }
        };

        struct OutputGroup
        {
            std::string name;
            OutputLevel level;

            OutputHelper dbg() const;
            OutputHelper info() const;
            OutputHelper warn() const;
            OutputHelper err() const;
        };

        struct OutputConfig
        {
            OutputConfig();
            OutputGroup api;
            OutputGroup base;
            OutputGroup client;
            OutputGroup ee;
            OutputGroup job;
            OutputGroup crypto;
        };
    }

    extern const detail::OutputConfig kzo;
}
