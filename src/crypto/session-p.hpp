/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include "session.hpp"

namespace Kazv
{
    struct SessionPrivate
    {
        SessionPrivate();
        SessionPrivate(OutboundSessionTag,
                       OlmAccount *acc,
                       std::string theirIdentityKey,
                       std::string theirOneTimeKey);

        SessionPrivate(OutboundSessionTag,
                       RandomTag,
                       RandomData data,
                       OlmAccount *acc,
                       std::string theirIdentityKey,
                       std::string theirOneTimeKey);

        SessionPrivate(InboundSessionTag,
                       OlmAccount *acc,
                       std::string theirIdentityKey,
                       std::string message);

        SessionPrivate(const SessionPrivate &that);
        ~SessionPrivate() = default;

        ByteArray sessionData;
        OlmSession *session{0};

        bool valid{false};

        std::string pickle() const;
        bool unpickle(std::string data);

        std::size_t checkError(std::size_t code) const;

        std::string error() const { return olm_session_last_error(session); }
    };
}
