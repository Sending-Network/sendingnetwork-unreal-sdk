/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include "inbound-group-session.hpp"

#include <olm/olm.h>

#include <immer/map.hpp>

namespace Kazv
{
    struct KeyOfDecryptedEvent
    {
        std::string eventId;
        Timestamp originServerTs;
    };

    inline void to_json(nlohmann::json &j, const KeyOfDecryptedEvent &k)
    {
        j = nlohmann::json::object();
        j["eventId"] = k.eventId;
        j["originServerTs"] = k.originServerTs;
    }

    inline void from_json(const nlohmann::json &j, KeyOfDecryptedEvent &k)
    {
        k.eventId = j.at("eventId");
        k.originServerTs = j.at("originServerTs");
    }

    inline bool operator==(KeyOfDecryptedEvent a, KeyOfDecryptedEvent b)
    {
        return a.eventId == b.eventId
            && a.originServerTs == b.originServerTs;
    }

    inline bool operator!=(KeyOfDecryptedEvent a, KeyOfDecryptedEvent b)
    {
        return !(a == b);
    }

    struct InboundGroupSessionPrivate
    {
        InboundGroupSessionPrivate();
        InboundGroupSessionPrivate(std::string sessionKey, std::string ed25519Key);
        InboundGroupSessionPrivate(const InboundGroupSessionPrivate &that);
        ~InboundGroupSessionPrivate() = default;

        ByteArray sessionData;
        OlmInboundGroupSession *session;

        std::string ed25519Key;

        bool valid{false};

        immer::map<std::uint32_t /* index */, KeyOfDecryptedEvent> decryptedEvents;

        std::size_t checkError(std::size_t code) const;
        std::string error() const;

        std::string pickle() const;
        bool unpickle(std::string pickleData);
    };

}
