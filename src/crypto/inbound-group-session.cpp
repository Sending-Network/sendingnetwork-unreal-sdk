/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include "inbound-group-session-p.hpp"

#include <types.hpp>

#include <debug.hpp>

namespace Kazv
{
    std::size_t InboundGroupSessionPrivate::checkError(std::size_t code) const
    {
        if (code == olm_error()) {
            kzo.crypto.warn() << "Olm inbound group session error: "
                              << olm_inbound_group_session_last_error(session) << std::endl;
        }
        return code;
    }

    std::string InboundGroupSessionPrivate::error() const
    {
        return olm_inbound_group_session_last_error(session);
    }


    InboundGroupSessionPrivate::InboundGroupSessionPrivate()
        : sessionData(olm_inbound_group_session_size(), '\0')
        , session(olm_inbound_group_session(sessionData.data()))
    {
    }

    InboundGroupSessionPrivate::InboundGroupSessionPrivate(std::string sessionKey, std::string ed25519Key)
        : InboundGroupSessionPrivate()
    {
        this->ed25519Key = ed25519Key;

        auto keyBuf = ByteArray(sessionKey.begin(), sessionKey.end());

        auto res = checkError(olm_init_inbound_group_session(session, keyBuf.data(), keyBuf.size()));
        if (res != olm_error()) {
            valid = true;
        }
    }

    InboundGroupSessionPrivate::InboundGroupSessionPrivate(const InboundGroupSessionPrivate &that)
        : InboundGroupSessionPrivate()
    {
        ed25519Key = that.ed25519Key;
        valid = unpickle(that.pickle());
        decryptedEvents = that.decryptedEvents;
    }

    std::string InboundGroupSessionPrivate::pickle() const
    {
        auto pickleData = std::string(olm_pickle_inbound_group_session_length(session), '\0');
        auto key = ByteArray(3, 'x');
        checkError(olm_pickle_inbound_group_session(session,
                                      key.data(), key.size(),
                                      pickleData.data(), pickleData.size()));
        return pickleData;
    }

    bool InboundGroupSessionPrivate::unpickle(std::string pickleData)
    {
        auto key = ByteArray(3, 'x');
        auto res = checkError(olm_unpickle_inbound_group_session(
                                   session,
                                   key.data(), key.size(),
                                   pickleData.data(), pickleData.size()));

        return res != olm_error();
    }


    InboundGroupSession::InboundGroupSession()
        : m_d(new InboundGroupSessionPrivate)
    {
    }

    InboundGroupSession::InboundGroupSession(std::string sessionKey, std::string ed25519Key)
        : m_d(new InboundGroupSessionPrivate(std::move(sessionKey), std::move(ed25519Key)))
    {
    }

    InboundGroupSession::~InboundGroupSession() = default;

    InboundGroupSession::InboundGroupSession(const InboundGroupSession &that)
        : m_d(new InboundGroupSessionPrivate(*that.m_d))
    {
    }

    InboundGroupSession::InboundGroupSession(InboundGroupSession &&that)
        : m_d(std::move(that.m_d))
    {
    }

    InboundGroupSession &InboundGroupSession::operator=(const InboundGroupSession &that)
    {
        m_d.reset(new InboundGroupSessionPrivate(*that.m_d));
        return *this;
    }

    InboundGroupSession &InboundGroupSession::operator=(InboundGroupSession &&that)
    {
        m_d = std::move(that.m_d);
        return *this;
    }

    bool InboundGroupSession::valid() const
    {
        return m_d && m_d->valid;
    }

    MaybeString InboundGroupSession::decrypt(std::string message, std::string eventId, std::int_fast64_t originServerTs)
    {
        ByteArray msgBuffer(message.begin(), message.end());
        ByteArray msgBuffer2 = msgBuffer;

        auto size = m_d->checkError(olm_group_decrypt_max_plaintext_length(
                                        m_d->session,
                                        msgBuffer.data(), msgBuffer.size()));
        if (size == olm_error()) {
            return NotBut(m_d->error());
        }

        auto plainText = ByteArray(size, '\0');
        std::uint32_t messageIndex;

        auto actualSize = m_d->checkError(olm_group_decrypt(
                                              m_d->session,
                                              msgBuffer2.data(), msgBuffer2.size(),
                                              plainText.data(), plainText.size(),
                                              &messageIndex));

        if (actualSize == olm_error()) {
            return NotBut(m_d->error());
        }

        // Check for possible replay attack
        auto keyForThisMsg = KeyOfDecryptedEvent{eventId, originServerTs};

        if (! m_d->decryptedEvents.find(messageIndex)) {
            m_d->decryptedEvents = std::move(m_d->decryptedEvents)
                .set(messageIndex, keyForThisMsg);
        } else { // already decrypted in the past
            auto key = m_d->decryptedEvents.at(messageIndex);
            if (key != keyForThisMsg) {
                return NotBut("This message has been decrypted in the past, but eventId or originServerTs does not match");
            }
        }

        return std::string(plainText.begin(), plainText.begin() + actualSize);
    }

    std::string InboundGroupSession::ed25519Key() const
    {
        return m_d->ed25519Key;
    }

    void to_json(nlohmann::json &j, const InboundGroupSession &s)
    {
        j = nlohmann::json::object();
        j["ed25519Key"] = s.m_d->ed25519Key;
        j["valid"] = s.m_d->valid;
        j["decryptedEvents"] = s.m_d->decryptedEvents;
        if (s.m_d->valid) {
            j["session"] = s.m_d->pickle();
        }
    }

    void from_json(const nlohmann::json &j, InboundGroupSession &s)
    {
        s.m_d->ed25519Key = j.at("ed25519Key");
        s.m_d->valid = j.at("valid");
        s.m_d->decryptedEvents = j.at("decryptedEvents");
        if (s.m_d->valid) {
            s.m_d->valid = s.m_d->unpickle(j.at("session"));
        }
    }
}
