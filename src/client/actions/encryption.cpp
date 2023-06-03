/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <zug/transducer/filter.hpp>
#include <zug/transducer/cat.hpp>

#include "encryption.hpp"

#include <debug.hpp>
#include "cursorutil.hpp"
#include "status-utils.hpp"

namespace Kazv
{
    using namespace CryptoConstants;

    static json convertSignature(const ClientModel &m, std::string signature)
    {
        auto j = json::object();
        j[m.userId] = json::object();
        j[m.userId][ed25519 + ":" + m.deviceId] = signature;

        return j;
    }

    ClientResult updateClient(ClientModel m, UploadIdentityKeysAction)
    {
        if (! m.crypto) {
            kzo.client.warn() << "Client::crypto is invalid, ignoring it." << std::endl;
            return { std::move(m), lager::noop };
        }

        auto &crypto = m.crypto.value();

        auto keys =
            immer::map<std::string, std::string>{}
             .set(ed25519 + ":" + m.deviceId, crypto.ed25519IdentityKey())
             .set(curve25519 + ":" + m.deviceId, crypto.curve25519IdentityKey());

        DeviceKeys k {
            m.userId,
            m.deviceId,
            {olmAlgo, megOlmAlgo},
            keys,
            {} // signatures to be added soon
        };

        auto j = json(k);

        auto sig = crypto.sign(j);

        k.signatures = convertSignature(m, sig);

        auto job = m.job<UploadKeysJob>()
            .make(k)
            .withData(json{{"is", "identityKeys"}});

        kzo.client.dbg() << "Uploading identity keys" << std::endl;

        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, GenerateAndUploadOneTimeKeysAction a)
    {
        if (! m.crypto) {
            kzo.client.warn() << "Client::crypto is invalid, ignoring it." << std::endl;
            return { std::move(m), simpleFail };
        }

        auto &crypto = m.crypto.value();

        kzo.client.dbg() << "Generating one-time keys..." << std::endl;

        auto maxNumKeys = crypto.maxNumberOfOneTimeKeys();
        auto numLocalKeys = crypto.numUnpublishedOneTimeKeys();
        auto numStoredKeys = crypto.uploadedOneTimeKeysCount(signedCurve25519) + numLocalKeys;
        auto numKeysToGenerate = a.numToGen;
        auto genKeysLimit = maxNumKeys - numStoredKeys;

        if (numKeysToGenerate > genKeysLimit) {
            numKeysToGenerate = genKeysLimit;
        }

        if (numLocalKeys <= 0 && numKeysToGenerate <= 0) { // we have enough already
            kzo.client.dbg() << "We have enough one-time keys. Ignoring this." << std::endl;
            return { std::move(m), lager::noop };
        }

        if (numKeysToGenerate > 0) {
            crypto.genOneTimeKeysWithRandom(a.random, numKeysToGenerate);
        }
        kzo.client.dbg() << "Generating done." << std::endl;

        auto keys = crypto.unpublishedOneTimeKeys();

        auto cv25519Keys = keys.at(curve25519);
        immer::map<std::string, Variant> oneTimeKeys;
        for (auto [id, keyStr] : cv25519Keys.items()) {
            json keyObject = json::object();
            keyObject["key"] = keyStr;
            keyObject["signatures"] = convertSignature(m, crypto.sign(keyObject));

            oneTimeKeys = std::move(oneTimeKeys).set(signedCurve25519 + ":" + id, JsonWrap(keyObject));
        }

        auto job = m.job<UploadKeysJob>()
            .make(
                std::nullopt, // deviceKeys
                oneTimeKeys)
            .withData(json{{"is", "oneTimeKeys"}});

        kzo.client.dbg() << "Uploading one time keys" << std::endl;

        m.addJob(std::move(job));

        return { std::move(m), lager::noop };

    };

    ClientResult processResponse(ClientModel m, UploadKeysResponse r)
    {
        if (! m.crypto) {
            kzo.client.warn() << "Client::crypto is invalid, ignoring it." << std::endl;
            return { std::move(m), lager::noop };
        }

        auto &crypto = m.crypto.value();

        auto is = r.dataStr("is");

        if (is == "identityKeys") {
            if (! r.success()) {
                kzo.client.dbg() << "Uploading identity keys failed" << std::endl;
                m.addTrigger(UploadIdentityKeysFailed{r.errorCode(), r.errorMessage()});
                return { std::move(m), failWithResponse(r) };
            }

            kzo.client.dbg() << "Uploading identity keys successful" << std::endl;
            m.addTrigger(UploadIdentityKeysSuccessful{});

            m.identityKeysUploaded = true;
        } else {
            if (! r.success()) {
                kzo.client.dbg() << "Uploading one-time keys failed" << std::endl;
                m.addTrigger(UploadOneTimeKeysFailed{r.errorCode(), r.errorMessage()});
                return { std::move(m), failWithResponse(r) };
            }

            kzo.client.dbg() << "Uploading one-time keys successful" << std::endl;
            m.addTrigger(UploadOneTimeKeysSuccessful{});

            crypto.markOneTimeKeysAsPublished();
        }

        crypto.setUploadedOneTimeKeysCount(r.oneTimeKeyCounts());

        return { std::move(m), lager::noop };
    }

    static JsonWrap cannotDecryptEvent(std::string reason)
    {
        return json{
            {"type", "m.room.message"},
            {"content", {
                {"msgtype","moe.kazv.mxc.cannot.decrypt"},
                {"body", "**This message cannot be decrypted due to " + reason + ".**"}}}};
    }

    static bool verifyEvent(ClientModel &m, Event e, const json &plainJson)
    {
        auto crypto = m.crypto.value();

        bool valid = true;

        try {
            std::string senderCurve25519Key = e.originalJson().get()
                .at("content").at("sender_key");

            auto deviceInfoOpt = m.deviceLists.findByCurve25519Key(e.sender(), senderCurve25519Key);

            if (! deviceInfoOpt) {
                kzo.client.dbg() << "Device key " << senderCurve25519Key
                                 << " unknown, thus invalid" << std::endl;
                valid = false;
            }

            auto deviceInfo = deviceInfoOpt.value();

            std::string algo = e.originalJson().get().at("content").at("algorithm");
            if (algo == olmAlgo) {
                if (! (plainJson.at("sender") == e.sender())) {
                    kzo.client.dbg() << "Sender does not match, thus invalid" << std::endl;
                    valid = false;
                }
                if (! (plainJson.at("recipient") == m.userId)) {
                    kzo.client.dbg() << "Recipient does not match, thus invalid" << std::endl;
                    valid = false;
                }
                if (! (plainJson.at("recipient_keys").at(ed25519) == crypto.ed25519IdentityKey())) {
                    kzo.client.dbg() << "Recipient key does not match, thus invalid" << std::endl;
                    valid = false;
                }
                auto thisEd25519Key = plainJson.at("keys").at(ed25519).get<std::string>();
                if (thisEd25519Key != deviceInfo.ed25519Key) {
                    kzo.client.dbg() << "Sender ed25519 key does not match, thus invalid" << std::endl;
                    valid = false;
                }
            } else if (algo == megOlmAlgo) {
                if (! (plainJson.at("room_id").get<std::string>() ==
                       e.originalJson().get().at("room_id").get<std::string>())) {
                    kzo.client.dbg() << "Room id does not match, thus invalid" << std::endl;
                    valid = false;
                }
                if (e.originalJson().get().at("content").at("device_id").get<std::string>()
                    != deviceInfo.deviceId) {
                    kzo.client.dbg() << "Device id does not match, thus invalid" << std::endl;
                    valid = false;
                }
                auto actualEd25519Key = crypto.getInboundGroupSessionEd25519KeyFromEvent(e.originalJson().get());
                if ((! actualEd25519Key)
                    || deviceInfo.ed25519Key != actualEd25519Key.value()) {
                    kzo.client.dbg() << "sender ed25519 key does not match, thus invalid" << std::endl;
                    kzo.client.dbg() << "From group session: "
                                     << (actualEd25519Key ? actualEd25519Key.value() : "<none>") << std::endl;
                    kzo.client.dbg() << "From device info: " << deviceInfo.ed25519Key << std::endl;
                    valid = false;
                }
            } else {
                kzo.client.dbg() << "Unknown algorithm, thus invalid" << std::endl;
                valid = false;
            }
        } catch (const std::exception &) {
            kzo.client.dbg() << "json format is not correct, thus invalid" << std::endl;
            valid = false;
        }

        return valid;
    }

    static Event decryptEvent(ClientModel &m, Event e)
    {
        // no need for decryption
        if (e.decrypted() || (! e.encrypted())) {
            return e;
        }

        auto &crypto = m.crypto.value();

        kzo.client.dbg() << "About to decrypt event: "
                         << e.originalJson().get().dump() << std::endl;

        auto maybePlainText = crypto.decrypt(e.originalJson().get());

        if (! maybePlainText) {
            kzo.client.dbg() << "Cannot decrypt: " << maybePlainText.reason() << std::endl;
            return e.setDecryptedJson(cannotDecryptEvent(maybePlainText.reason()), Event::NotDecrypted);
        } else {
            kzo.client.dbg() << "Decrypted message: " << maybePlainText.value() << std::endl;
            auto plainJson = json::parse(maybePlainText.value());
            auto valid = verifyEvent(m, e, plainJson);
            if (valid) {
                kzo.client.dbg() << "The decrypted event is valid." << std::endl;
            }
            return valid
                ? e.setDecryptedJson(plainJson, Event::Decrypted)
                : e.setDecryptedJson(cannotDecryptEvent("invalid event"), Event::NotDecrypted);
        }
    }

    ClientModel tryDecryptEvents(ClientModel m)
    {
        if (! m.crypto) {
            kzo.client.dbg() << "We have no encryption enabled--ignoring decryption request" << std::endl;
            return m;
        }
        auto &crypto = m.crypto.value();

        kzo.client.dbg() << "Trying to decrypt events..." << std::endl;

        auto decryptFunc = [&](auto e) { return decryptEvent(m, e); };

        auto takeOutRoomKeyEvents =
            [&](auto e) {
                if (e.type() != "m.room_key") {
                    // Leave it as it is
                    return true;
                }

                auto content = e.content();
                std::string roomId = content.get().at("room_id");
                std::string sessionId = content.get().at("session_id");
                std::string sessionKey = content.get().at("session_key");
                std::string senderKey = e.originalJson().get().at("content").at("sender_key");

                auto k = KeyOfGroupSession{roomId, senderKey, sessionId};

                std::string ed25519Key = e.decryptedJson().get().at("keys").at(ed25519);

                if (crypto.createInboundGroupSession(k, sessionKey, ed25519Key)) {
                    return false; // such that this event is removed
                }
                return true;
            };

        m.toDevice = intoImmer(
            EventList{},
            zug::map(decryptFunc)
            | zug::filter(takeOutRoomKeyEvents),
            std::move(m.toDevice));

        auto decryptEventInRoom =
            [&](auto id, auto room) {
                if (! room.encrypted) {
                    return;
                } else {
                    auto messages = room.messages;
                    room.messages = merge(
                        room.messages,
                        intoImmer(
                            EventList{},
                            zug::filter([](auto n) {
                                            auto e = n.second;
                                            return e.encrypted();
                                        })
                            | zug::map([=](auto n) {
                                           auto event = n.second;
                                           return decryptFunc(event);
                                       }),
                            std::move(messages)),
                        keyOfTimeline);
                    m.roomList.rooms = std::move(m.roomList.rooms).set(id, room);
                }
            };

        auto rooms = m.roomList.rooms;
        for (auto [id, room]: rooms) {
            decryptEventInRoom(id, room);
        }

        return m;
    }

    std::optional<BaseJob> clientPerform(ClientModel m, QueryKeysAction a)
    {
        if (! m.crypto) {
            kzo.client.dbg() << "We have no encryption enabled--ignoring this" << std::endl;
            return std::nullopt;
        }

        immer::map<std::string, immer::array<std::string>> deviceKeys;
        auto encryptedUsers = m.deviceLists.outdatedUsers();

        if (encryptedUsers.empty()) {
            kzo.client.dbg() << "Keys are up-to-date." << std::endl;
            return std::nullopt;
        }

        kzo.client.dbg() << "We need to query keys for: " << std::endl;
        for (auto userId: encryptedUsers) {
            kzo.client.dbg() << userId << std::endl;
            deviceKeys = std::move(deviceKeys).set(userId, {});
        }
        kzo.client.dbg() << "^" << std::endl;

        auto job = m.job<QueryKeysJob>()
            .make(std::move(deviceKeys),
                  std::nullopt, // timeout
                  a.isInitialSync ? std::nullopt : m.syncToken
                );
        return job;
    }

    ClientResult updateClient(ClientModel m, QueryKeysAction a)
    {
        auto jobOpt = clientPerform(m, a);
        if (jobOpt) {
            m.addJob(jobOpt.value());
        }

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, QueryKeysResponse r)
    {
        if (! m.crypto) {
            kzo.client.dbg() << "We have no encryption enabled--ignoring this" << std::endl;
            return { std::move(m), simpleFail };
        }

        if (! r.success()) {
            kzo.client.dbg() << "query keys failed: " << r.errorCode() << r.errorMessage() << std::endl;
            return { std::move(m), failWithResponse(r) };
        }

        kzo.client.dbg() << "Received a query key response" << std::endl;
        auto &crypto = m.crypto.value();

        auto usersMap = r.deviceKeys();

        for (auto [userId, deviceMap] : usersMap) {
            for (auto [deviceId, deviceInfo] : deviceMap) {
                kzo.client.dbg() << "Key for " << userId
                                 << "/" << deviceId
                                 << ": " << json(deviceInfo).dump()
                                 << std::endl;
                m.deviceLists.addDevice(userId, deviceId, deviceInfo, crypto);
            }
            m.deviceLists.markUpToDate(userId);
        }

        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, ClaimKeysAction a)
    {
        if (! m.crypto) {
            kzo.client.dbg() << "We have no encryption enabled--ignoring this" << std::endl;
            return { std::move(m), lager::noop };
        }

        auto &c = m.crypto.value();

        kzo.client.dbg() << "claim keys for: " << json(a.devicesToSend).dump() << std::endl;

        auto keyMap = immer::map<std::string, immer::map<std::string /* deviceId */,
                                                         std::string /* curve25519IdentityKey */>>{};


        for (auto [userId, devices] : a.devicesToSend) {
            kzo.client.dbg() << "Iterating through user " << userId << std::endl;
            auto deviceToKey = immer::map<std::string, std::string>{};
            for (auto deviceId : devices) {
                kzo.client.dbg() << "Device: " << deviceId << std::endl;
                auto infoOpt = m.deviceLists.get(userId, deviceId);
                if (infoOpt) {
                    kzo.client.dbg() << "Got device info, curve25519 key is: " << infoOpt.value().curve25519Key << std::endl;
                    deviceToKey = std::move(deviceToKey)
                        .set(deviceId, infoOpt.value().curve25519Key);
                } else {
                    kzo.client.dbg() << "Did not get device info" <<  std::endl;
                }
            }
            keyMap = std::move(keyMap).set(userId, deviceToKey);
        }

        auto devicesToClaimKeys = c.devicesMissingOutboundSessionKey(keyMap);

        kzo.client.dbg() << "Really claim keys for: " << json(devicesToClaimKeys).dump() << std::endl;

        auto oneTimeKeys = immer::map<std::string, immer::map<std::string, std::string>>{};
        for (auto [userId, devices] : devicesToClaimKeys) {
            auto devKeys = immer::map<std::string, std::string>{};
            for (auto deviceId: devices) {
                devKeys = std::move(devKeys).set(deviceId, signedCurve25519);
            }
            oneTimeKeys = std::move(oneTimeKeys).set(userId, devKeys);
        }

        auto job = m.job<ClaimKeysJob>()
            .make(std::move(oneTimeKeys))
            .withData(json{
                    {"roomId", a.roomId},
                    {"sessionId", a.sessionId},
                    {"sessionKey", a.sessionKey},
                    {"devicesToSend", a.devicesToSend},
                    {"random", a.random}
                });
        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, ClaimKeysResponse r)
    {
        if (! m.crypto) {
            kzo.client.dbg() << "We have no encryption enabled--ignoring this" << std::endl;
            return { std::move(m), simpleFail };
        }

        if (! r.success()) {
            kzo.client.dbg() << "claim keys failed" << std::endl;
            m.addTrigger(ClaimKeysFailed{r.errorCode(), r.errorMessage()});
            return { std::move(m), failWithResponse(r) };
        }

        kzo.client.dbg() << "claim keys successful" << std::endl;

        kzo.client.dbg() << "Json body: " << r.jsonBody().get().dump() << std::endl;

        auto &c = m.crypto.value();

        auto roomId = r.dataStr("roomId");
        auto sessionKey = r.dataStr("sessionKey");
        auto sessionId = r.dataStr("sessionId");
        auto devicesToSend =
            immer::map<std::string, immer::flex_vector<std::string>>(r.dataJson("devicesToSend"));
        auto random = r.dataJson("random").template get<RandomData>();

        // create outbound sessions for those devices
        auto oneTimeKeys = r.oneTimeKeys();

        for (auto [userId, deviceMap] : oneTimeKeys) {
            for (auto [deviceId, keyVar] : deviceMap) {
                if (std::holds_alternative<JsonWrap>(keyVar)) {
                    auto keys = std::get<JsonWrap>(keyVar).get();
                    for (auto [keyId, key] : keys.items()) {
                        auto deviceInfoOpt = m.deviceLists.get(userId, deviceId);
                        if (deviceInfoOpt) {
                            auto deviceInfo = deviceInfoOpt.value();
                            kzo.client.dbg() << "Verifying key for " << userId
                                             << "/" << deviceId
                                             << key.dump()
                                             << " with ed25519 key "
                                             << deviceInfo.ed25519Key << std::endl;
                            auto verified = c.verify(key, userId, deviceId, deviceInfo.ed25519Key);
                            kzo.client.dbg() << (verified ? "passed" : "did not pass") << std::endl;
                            if (verified && key.contains("key")) {
                                auto theirOneTimeKey = key.at("key");
                                kzo.client.dbg() << "creating outbound session for it" << std::endl;
                                c.createOutboundSessionWithRandom(random, deviceInfo.curve25519Key, theirOneTimeKey);
                                random.erase(0, Crypto::createOutboundSessionRandomSize());
                                kzo.client.dbg() << "done" << std::endl;
                            }
                        }
                    }
                }
            }
        }

        auto eventJson = json{
            {"content", {{"algorithm", megOlmAlgo},
                         {"room_id", roomId},
                         {"session_id", sessionId},
                         {"session_key", sessionKey}}},
            {"type", "m.room_key"}
        };

        auto event = Event(JsonWrap(eventJson));

        return {
            std::move(m),
            [event](auto &&) { return EffectStatus{ /* success = */ true, json{{ "keyEvent", event.originalJson() }} }; }
        };
    }

    ClientResult updateClient(ClientModel m, EncryptMegOlmEventAction a)
    {
        auto [encryptedEvent, maybeKey] = m.megOlmEncrypt(a.e, a.roomId, a.timeMs, a.random);

        return {
            std::move(m),
            [=](auto && /* ctx */) {
                auto retJson = json::object({
                        {"encrypted", encryptedEvent.originalJson()},
                    });
                if (maybeKey.has_value()) {
                    retJson["key"] = maybeKey.value();
                }
                return EffectStatus(/* succ = */ true, retJson);
            }
        };
    }

    ClientResult updateClient(ClientModel m, EncryptOlmEventAction a)
    {
        auto encryptedEvent = m.olmEncrypt(a.e, a.devices, a.random);

        return {
            std::move(m),
            [=](auto && /* ctx */) {
                auto retJson = json::object({
                        {"encrypted", encryptedEvent.originalJson()},
                    });

                return EffectStatus(/* succ = */ true, retJson);
            }
        };
    }
}
