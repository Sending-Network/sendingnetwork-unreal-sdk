/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <memory>

#include <maybe.hpp>
#include <event.hpp>

#include "crypto-util.hpp"

namespace Kazv
{
    struct InboundGroupSessionPrivate;

    class InboundGroupSession
    {
    public:
        explicit InboundGroupSession();
        explicit InboundGroupSession(std::string sessionKey, std::string ed25519Key);

        InboundGroupSession(const InboundGroupSession &that);
        InboundGroupSession(InboundGroupSession &&that);
        InboundGroupSession &operator=(const InboundGroupSession &that);
        InboundGroupSession &operator=(InboundGroupSession &&that);
        ~InboundGroupSession();

        MaybeString decrypt(std::string message, std::string eventId, Timestamp originServerTs);

        bool valid() const;

        std::string ed25519Key() const;
    private:
        friend void to_json(nlohmann::json &j, const InboundGroupSession &s);
        friend void from_json(const nlohmann::json &j, InboundGroupSession &s);
        std::unique_ptr<InboundGroupSessionPrivate> m_d;
    };
}
