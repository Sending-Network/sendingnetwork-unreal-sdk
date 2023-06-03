/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <olm/olm.h>

#include <unordered_map>

#include "crypto.hpp"
#include "crypto-util.hpp"
#include "session.hpp"
#include "inbound-group-session.hpp"
#include "outbound-group-session.hpp"

namespace Kazv
{
    using SessionList = std::vector<Session>;

    struct CryptoPrivate
    {
        CryptoPrivate();
        CryptoPrivate(RandomTag, RandomData data);
        CryptoPrivate(const CryptoPrivate &that);
        ~CryptoPrivate();

        ByteArray accountData;
        OlmAccount *account;
        immer::map<std::string /* algorithm */, int> uploadedOneTimeKeysCount;
        int numUnpublishedKeys{0};
        std::unordered_map<std::string /* theirCurve25519IdentityKey */, Session> knownSessions;
        std::unordered_map<KeyOfGroupSession, InboundGroupSession> inboundGroupSessions;

        std::unordered_map<std::string /* roomId */, OutboundGroupSession> outboundGroupSessions;

        ByteArray utilityData;
        OlmUtility *utility;
        bool valid{true};

        std::size_t checkUtilError(std::size_t code) const;

        std::string pickle() const;
        void unpickle(std::string data);

        ByteArray identityKeys();
        std::string ed25519IdentityKey();
        std::string curve25519IdentityKey();

        std::size_t checkError(std::size_t code) const;

        MaybeString decryptOlm(nlohmann::json content);
        // Here we need the full event for eventId and originServerTs
        MaybeString decryptMegOlm(nlohmann::json eventJson);

        /// returns whether the session is successfully established
        bool createInboundSession(std::string theirCurve25519IdentityKey,
                                  std::string message);

        bool createInboundGroupSession(KeyOfGroupSession k, std::string sessionKey, std::string ed25519Key);

        bool reuseOrCreateOutboundGroupSession(RandomData random, Timestamp timeMs,
                                               std::string roomId, std::optional<MegOlmSessionRotateDesc> desc);
    };

}
