/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include <debug.hpp>
#include <types.hpp>

#include "send.hpp"
#include "status-utils.hpp"

namespace Kazv
{
    static std::string increaseTxnId(std::string cur)
    {
        return std::to_string(std::stoull(cur) + 1);
    }

    ClientResult updateClient(ClientModel m, SendMessageAction a)
    {
        auto event = std::move(a.event);
        auto roomId = a.roomId;

        auto origJson = event.originalJson().get();

        if (!origJson.contains("type") || !origJson.contains("content")) {
            m.addTrigger(InvalidMessageFormat{});
            return { std::move(m), lager::noop };
        }

        // We do not use event.type() etc. because we want
        // encrypted events stay encrypted.
        auto type = origJson["type"];
        auto content = origJson["content"];

        kzo.client.dbg() << "Sending message of type " << type
                  << " with content " << content.dump()
                  << " to " << a.roomId
                  << " as #" << m.nextTxnId << std::endl;

        // We combine the hash of json, the timestamp,
        // and a numeric count in the client to avoid collision.
        auto txnId = std::to_string(std::hash<json>{}(origJson))
            + std::to_string(std::chrono::system_clock::now()
                             .time_since_epoch().count())
            + m.nextTxnId;

        m.nextTxnId = increaseTxnId(m.nextTxnId);

        auto job = m.job<SendMessageJob>()
            .make(a.roomId, type, txnId, content)
            .withData(json{{"roomId", a.roomId}});

        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, SendMessageResponse r)
    {
        auto roomId = r.dataStr("roomId");
        if (! r.success()) {
            kzo.client.dbg() << "Send message failed" << std::endl;
            m.addTrigger(SendMessageFailed{roomId, r.errorCode(), r.errorMessage()});
            return { std::move(m), failWithResponse(r) };
        }

        m.addTrigger(SendMessageSuccessful{roomId, r.eventId()});
        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, SendToDeviceMessageAction a)
    {
        auto origJson = a.event.originalJson().get();
        if (!origJson.contains("type") || !origJson.contains("content")) {
            return { std::move(m), simpleFail };
        }

        // We do not use event.type() etc. because we want
        // encrypted events stay encrypted.
        auto type = origJson["type"];
        auto content = origJson["content"];

        auto txnId = std::to_string(std::hash<json>{}(origJson))
            + std::to_string(std::chrono::system_clock::now()
                             .time_since_epoch().count())
            + m.nextTxnId;

        m.nextTxnId = increaseTxnId(m.nextTxnId);

        auto messages =
            immer::map<std::string, immer::map<std::string, JsonWrap>>{};

        for (auto [userId, devices] : a.devicesToSend) {
            auto deviceIdToContentMap = immer::map<std::string, JsonWrap>{};
            for (auto deviceId : devices) {
                deviceIdToContentMap = std::move(deviceIdToContentMap).set(deviceId, content);
            }
            messages = std::move(messages).set(userId, deviceIdToContentMap);
        }

        auto job = m.job<SendToDeviceJob>()
            .make(type, txnId, messages)
            .withData(json{{"devicesToSend", a.devicesToSend},
                           {"txnId", txnId}});

        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, SendToDeviceResponse r)
    {
        auto devicesToSend = r.dataJson("devicesToSend");
        auto txnId = r.dataStr("txnId");

        if (! r.success()) {
            m.addTrigger(SendToDeviceMessageFailed{devicesToSend, txnId, r.errorCode(), r.errorMessage()});
            return { std::move(m), failWithResponse(r) };
        }

        m.addTrigger(SendToDeviceMessageSuccessful{devicesToSend, txnId});
        return { std::move(m), lager::noop };
    }

}
