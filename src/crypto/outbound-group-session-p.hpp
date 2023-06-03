/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include "outbound-group-session.hpp"

#include <olm/olm.h>

#include <immer/map.hpp>

namespace Kazv
{
    struct OutboundGroupSessionPrivate
    {
        /// to be deprecated
        OutboundGroupSessionPrivate();
        OutboundGroupSessionPrivate(RandomTag,
                                    RandomData random,
                                    Timestamp creationTime);
        OutboundGroupSessionPrivate(const OutboundGroupSessionPrivate &that);
        ~OutboundGroupSessionPrivate() = default;

        ByteArray sessionData;
        OlmOutboundGroupSession *session;

        bool valid{false};

        Timestamp creationTime;

        std::string initialSessionKey;


        std::size_t checkError(std::size_t code) const;
        std::string error() const;

        std::string pickle() const;
        bool unpickle(std::string pickleData);

        std::string sessionKey();
    };

}
