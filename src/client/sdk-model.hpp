/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <context.hpp>
#include "client-model.hpp"

namespace Kazv
{
    struct SdkModel;

    using SdkAction = std::variant<
        ClientAction
        >;

    using SdkEffect = Effect<SdkAction, lager::deps<JobInterface &, EventInterface &>>;

    using SdkResult = std::pair<SdkModel, SdkEffect>;

    struct SdkModel
    {
        ClientModel client;

        inline operator ClientModel() const { return client; }
        inline const ClientModel &c() const { return client; }

        using Action = SdkAction;
        using Effect = SdkEffect;
        using Result = SdkResult;

        static SdkResult update(SdkModel s, SdkAction a);
    };

    template<class Archive>
    void serialize(Archive &ar, SdkModel &s, std::uint32_t const /*version*/)
    {
        ar & s.client;
    }
}

BOOST_CLASS_VERSION(Kazv::SdkModel, 0)
