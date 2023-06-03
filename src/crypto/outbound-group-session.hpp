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
    struct OutboundGroupSessionPrivate;

    class OutboundGroupSession
    {
    public:
        /**
         * @return The size of random data needed to construct an OutboundGroupSession.
         */
        static std::size_t constructRandomSize();

        [[deprecated("Use deterministic variant instead. In the future, this will construct an invalid OutboundGroupSession.")]]
        explicit OutboundGroupSession();

        /**
         * Constructs an OutboundGroupSession from custom random data.
         *
         * @param random The random data to use. Must be of at least size
         * `constructRandomSize()`.
         * @param creationTime The creation time of this OutboundGroupSession.
         */
        OutboundGroupSession(RandomTag, RandomData random, Timestamp creationTime);

        OutboundGroupSession(const OutboundGroupSession &that);
        OutboundGroupSession(OutboundGroupSession &&that);
        OutboundGroupSession &operator=(const OutboundGroupSession &that);
        OutboundGroupSession &operator=(OutboundGroupSession &&that);
        ~OutboundGroupSession();

        std::string encrypt(std::string plainText);

        bool valid() const;

        std::string sessionKey();
        std::string initialSessionKey() const;
        std::string sessionId();

        int messageIndex();

        Timestamp creationTimeMs() const;
    private:
        friend void to_json(nlohmann::json &j, const OutboundGroupSession &s);
        friend void from_json(const nlohmann::json &j, OutboundGroupSession &s);
        std::unique_ptr<OutboundGroupSessionPrivate> m_d;
    };
}
