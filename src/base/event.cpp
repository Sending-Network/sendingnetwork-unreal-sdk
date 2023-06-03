/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "libkazv-config.hpp"


#include "event.hpp"

namespace Kazv
{
    const JsonWrap Event::notYetDecryptedEvent = {
        json{{"type", "m.room.message"},
             {"content", {
                     {"msgtype", "xyz.tusooa.kazv.not.yet.decrypted"},
                     {"body", "**This message has not yet been decrypted.**"}}}}};

    Event::Event() : m_json(json::object()) {}

    Event::Event(JsonWrap j)
        : m_json(j) {
        using namespace std::string_literals;
        if (m_json.get().contains("type"s)) {
            auto type = m_json.get().at("type"s).get<std::string>();
            if (type == "m.room.encrypted"s) {
                m_encrypted = true;
                m_decryptedJson = notYetDecryptedEvent;
            }
        }
    }

    Event Event::fromSync(Event e, std::string roomId) {
        auto j = e.originalJson().get();
        j["room_id"] = roomId;
        return Event(j);
    }

    std::string Event::id() const {
        // the decrypted json does not have an event id
        return originalJson().get().contains("event_id")
            ? originalJson().get().at("event_id")
            : "";
    }

    std::string Event::sender() const {
        return originalJson().get().contains("sender")
            ? originalJson().get().at("sender")
            : "";
    }

    Timestamp Event::originServerTs() const {
        return originalJson().get().contains("origin_server_ts")
            ? originalJson().get().at("origin_server_ts")
            : "";
    }

    std::string Event::type() const {
        return raw().get().contains("type")
            ? raw().get().at("type")
            : "";
    }

    JsonWrap Event::content() const {
        return raw().get().contains("content")
            ? raw().get().at("content")
            : json::object();
    }

    std::string Event::stateKey() const {
        return raw().get().contains("state_key")
            ? raw().get().at("state_key")
            : "";
    }

    bool Event::isState() const
    {
        return raw().get().contains("state_key");
    }

    /// returns the decrypted json
    JsonWrap Event::raw() const {
        return m_encrypted ? decryptedJson() : m_json;
    }

    /// returns the original json we fetched, probably encrypted.
    JsonWrap Event::originalJson() const {
        return m_json;
    }

    JsonWrap Event::decryptedJson() const {
        return m_decryptedJson;
    }

    bool Event::encrypted() const {
        return m_encrypted;
    }

    bool Event::decrypted() const {
        return m_decrypted == Decrypted;
    }

    Event Event::setDecryptedJson(JsonWrap decryptedJson, DecryptionStatus decrypted) const {
        Event e(*this);
        e.m_decryptedJson = decryptedJson;
        e.m_decrypted = decrypted;
        return e;
    }

    bool operator==(Event a, Event b)
    {
        return a.id() == b.id()
            && a.originalJson() == b.originalJson()
            && a.raw() == b.raw();
    }

}
