/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <olm/olm.h>

#include <debug.hpp>

#include "crypto-p.hpp"
#include "session-p.hpp"


namespace Kazv
{
    std::size_t SessionPrivate::checkError(std::size_t code) const
    {
        if (code == olm_error()) {
            kzo.crypto.warn() << "Olm session error: " << olm_session_last_error(session) << std::endl;
        }
        return code;
    }

    SessionPrivate::SessionPrivate()
        : sessionData(olm_session_size(), '\0')
        , session(olm_session(sessionData.data()))
    {
    }

    SessionPrivate::SessionPrivate(OutboundSessionTag,
                                   OlmAccount *acc,
                                   std::string theirIdentityKey,
                                   std::string theirOneTimeKey)
        : SessionPrivate()
    {
        auto random = genRandom(Session::constructOutboundRandomSize());

        auto res = checkError(olm_create_outbound_session(
                                  session,
                                  acc,
                                  theirIdentityKey.c_str(), theirIdentityKey.size(),
                                  theirOneTimeKey.c_str(), theirOneTimeKey.size(),
                                  random.data(), random.size()));

        if (res != olm_error()) {
            valid = true;
        }
    }

    SessionPrivate::SessionPrivate(OutboundSessionTag,
                                   RandomTag,
                                   RandomData random,
                                   OlmAccount *acc,
                                   std::string theirIdentityKey,
                                   std::string theirOneTimeKey)
        : SessionPrivate()
    {
        assert(random.size() >= Session::constructOutboundRandomSize());

        auto res = checkError(olm_create_outbound_session(
                                  session,
                                  acc,
                                  theirIdentityKey.c_str(), theirIdentityKey.size(),
                                  theirOneTimeKey.c_str(), theirOneTimeKey.size(),
                                  random.data(), random.size()));

        if (res != olm_error()) {
            valid = true;
        }
    }

    SessionPrivate::SessionPrivate(InboundSessionTag,
                   OlmAccount *acc,
                   std::string theirIdentityKey,
                   std::string message)
        : SessionPrivate()
    {
        auto res = checkError(olm_create_inbound_session_from(
                                  session,
                                  acc,
                                  theirIdentityKey.c_str(), theirIdentityKey.size(),
                                  message.data(), message.size()));

        if (res != olm_error()) {
            valid = true;
        }
    }

    SessionPrivate::SessionPrivate(const SessionPrivate &that)
        : SessionPrivate()
    {
        valid = unpickle(that.pickle());
    }

    std::string SessionPrivate::pickle() const
    {
        auto pickleData = std::string(olm_pickle_session_length(session), '\0');
        auto key = ByteArray(3, 'x');
        checkError(olm_pickle_session(session,
                                      key.data(), key.size(),
                                      pickleData.data(), pickleData.size()));
        return pickleData;
    }

    bool SessionPrivate::unpickle(std::string pickleData)
    {
        auto key = ByteArray(3, 'x');
        auto res = checkError(olm_unpickle_session(
                                   session,
                                   key.data(), key.size(),
                                   pickleData.data(), pickleData.size()));

        return res != olm_error();
    }


    std::size_t Session::constructOutboundRandomSize()
    {
        static size_t s =
            [] {
                ByteArray sessionData(olm_session_size(), '\0');
                OlmSession *session(olm_session(sessionData.data()));
                return olm_create_outbound_session_random_length(session);
            }();
        return s;
    }

    Session::Session()
        : m_d(new SessionPrivate)
    {
    }

    Session::Session(OutboundSessionTag,
                     OlmAccount *acc,
                     std::string theirIdentityKey,
                     std::string theirOneTimeKey)
        : m_d(new SessionPrivate{
                OutboundSessionTag{},
                acc,
                theirIdentityKey,
                theirOneTimeKey})
    {
    }

    Session::Session(OutboundSessionTag,
                     RandomTag,
                     RandomData data,
                     OlmAccount *acc,
                     std::string theirIdentityKey,
                     std::string theirOneTimeKey)
        : m_d(new SessionPrivate{
                OutboundSessionTag{},
                RandomTag{},
                std::move(data),
                acc,
                theirIdentityKey,
                theirOneTimeKey})
    {
    }

    Session::Session(InboundSessionTag,
                     OlmAccount *acc,
                     std::string theirIdentityKey,
                     std::string theirOneTimeKey)
        : m_d(new SessionPrivate{
                InboundSessionTag{},
                acc,
                theirIdentityKey,
                theirOneTimeKey})
    {
    }

    Session::~Session() = default;

    Session::Session(const Session &that)
        : m_d(new SessionPrivate(*that.m_d))
    {
    }

    Session::Session(Session &&that)
        : m_d(std::move(that.m_d))
    {
    }

    Session &Session::operator=(const Session &that)
    {
        m_d.reset(new SessionPrivate(*that.m_d));
        return *this;
    }

    Session &Session::operator=(Session &&that)
    {
        m_d = std::move(that.m_d);
        return *this;
    }


    bool Session::matches(std::string message)
    {
        auto res = m_d->checkError(
            olm_matches_inbound_session(m_d->session, message.data(), message.size()));

        // if match, returns 1
        return res == 1;
    }

    bool Session::valid() const
    {
        // maybe a moved-from state, so check m_d first
        return m_d && m_d->valid;
    }

    MaybeString Session::decrypt(int type, std::string message)
    {
        auto msgBuffer = ByteArray(message.begin(), message.end());

        auto size = m_d->checkError(olm_decrypt_max_plaintext_length(
                                        m_d->session, type, msgBuffer.data(), msgBuffer.size()));

        if (size == olm_error()) {
            return NotBut(m_d->error());
        }

        auto plainTextBuffer = ByteArray(size, '\0');

        auto actualSize = m_d->checkError(
            olm_decrypt(m_d->session, type,
                        message.data(), message.size(),
                        plainTextBuffer.data(), plainTextBuffer.size()));

        if (actualSize == olm_error()) {
            return NotBut(m_d->error());
        }

        return std::string(plainTextBuffer.begin(), plainTextBuffer.begin() + actualSize);
    }

    std::size_t Session::encryptRandomSize() const
    {
        return olm_encrypt_random_length(m_d->session);
    }

    std::pair<int, std::string> Session::encrypt(std::string plainText)
    {
        return encryptWithRandom(genRandomData(encryptRandomSize()), std::move(plainText));
    }

    std::pair<int, std::string> Session::encryptWithRandom(RandomData random, std::string plainText)
    {
        assert(random.size() >= encryptRandomSize());

        auto type = m_d->checkError(olm_encrypt_message_type(m_d->session));

        auto size = m_d->checkError(olm_encrypt_message_length(m_d->session, plainText.size()));

        auto buf = ByteArray(size, '\0');

        auto actualSize = m_d->checkError(
            olm_encrypt(m_d->session, plainText.c_str(), plainText.size(),
                        random.data(), random.size(),
                        buf.data(), buf.size()));

        if (actualSize != olm_error()) {
            return { type, std::string(buf.begin(), buf.begin() + actualSize) };
        }

        return { -1, "" };
    }

    void to_json(nlohmann::json &j, const Session &s)
    {
        j = nlohmann::json::object({
                {"valid", s.m_d->valid},
                {"data", s.m_d->valid ? s.m_d->pickle() : std::string()}
            });
    }

    void from_json(const nlohmann::json &j, Session &s)
    {
        if (j.at("valid").template get<bool>()) {
            s.m_d->valid = s.m_d->unpickle(j.at("data"));
        }
    }

}
