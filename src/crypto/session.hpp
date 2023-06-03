/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <memory>
#include <tuple>

#include <olm/olm.h>

#include <maybe.hpp>

#include "crypto-util.hpp"

namespace Kazv
{
    class Crypto;

    struct InboundSessionTag {};
    struct OutboundSessionTag {};

    struct SessionPrivate;
    class Session
    {
        /**
         * @return The size of random data needed to construct an outbound session.
         */
        static std::size_t constructOutboundRandomSize();

        // Creates an outbound session
        [[deprecated("Use deterministic variant instead. In the future, this will be removed.")]]
        explicit Session(OutboundSessionTag,
                         OlmAccount *acc,
                         std::string theirIdentityKey,
                         std::string theirOneTimeKey);

        /**
         * Construct an outbound session with custom random data.
         *
         * @param data The custom random data. Must be of at least
         * size `constructOutboundRandomSize()`.
         */
        explicit Session(OutboundSessionTag,
                         RandomTag,
                         RandomData data,
                         OlmAccount *acc,
                         std::string theirIdentityKey,
                         std::string theirOneTimeKey);

        // Creates an inbound session
        explicit Session(InboundSessionTag,
                         OlmAccount *acc,
                         std::string theirIdentityKey,
                         std::string message);

    public:
        explicit Session();

        Session(const Session &that);
        Session(Session &&that);
        Session &operator=(const Session &that);
        Session &operator=(Session &&that);
        ~Session();

        bool matches(std::string message);

        bool valid() const;

        MaybeString decrypt(int type, std::string message);

        /**
         * @return The size of random data needed for the next encryption.
         */
        std::size_t encryptRandomSize() const;

        [[deprecated("Use deterministic variant instead. In the future, this will be removed.")]]
        std::pair<int /* type */, std::string /* message */> encrypt(std::string plainText);

        /**
         * Encrypt plainText.
         *
         * @param random The random data needed for the encryption. Must be
         * of at least size `encryptRandomSize()`.
         * @param plainText The plain text to encrypt.
         *
         * @return A pair containing the type and encrypted message string.
         */
        std::pair<int /* type */, std::string /* message */> encryptWithRandom(
            RandomData random, std::string plainText);

    private:
        friend class Crypto;
        friend class CryptoPrivate;
        friend class SessionPrivate;

        friend void to_json(nlohmann::json &j, const Session &s);
        friend void from_json(const nlohmann::json &j, Session &s);
        std::unique_ptr<SessionPrivate> m_d;
    };
}
