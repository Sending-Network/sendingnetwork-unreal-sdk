/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include "libkazv-config.hpp"
#include "kazvevents.hpp"

namespace Kazv
{
    class EventInterface
    {
    public:
        virtual ~EventInterface() = default;
        virtual void emit(KazvEvent e) = 0;
    };
}
