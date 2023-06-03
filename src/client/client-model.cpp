/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <immer/algorithm.hpp>
#include <lager/util.hpp>
#include <lager/context.hpp>
#include <functional>

#include <zug/transducer/filter.hpp>

#include <immer/flex_vector_transient.hpp>

#include "debug.hpp"

#include "client-model.hpp"

#include "actions/states.hpp"
#include "actions/auth.hpp"
#include "actions/membership.hpp"
#include "actions/paginate.hpp"
#include "actions/send.hpp"
#include "actions/states.hpp"
#include "actions/sync.hpp"
#include "actions/ephemeral.hpp"
#include "actions/content.hpp"
#include "actions/encryption.hpp"
#include "actions/profile.hpp"

namespace Kazv
{
    auto ClientModel::update(ClientModel m, Action a) -> Result
    {
        auto oldDeviceLists = m.deviceLists;

        auto [newClient, effect] = lager::match(std::move(a))(
            [&](RoomListAction a) -> Result {
                m.roomList = RoomListModel::update(std::move(m.roomList), a);
                return {std::move(m), lager::noop};
            },
            [&](ResubmitJobAction a) -> Result {
                m.addJob(std::move(a.job));
                return { std::move(m), lager::noop };
            },
            [&](auto a) -> decltype(updateClient(m, a)) {
                return updateClient(m, a);
            },
#define RESPONSE_FOR(_jobId)                                            \
            if (r.jobId() == #_jobId) {                                 \
                return processResponse(m, _jobId##Response{std::move(r)}); \
            }

            [&](ProcessResponseAction a) -> Result {
                auto r = std::move(a.response);

                // auth
                RESPONSE_FOR(Login);
                RESPONSE_FOR(GetWellknown);
                RESPONSE_FOR(GetVersions);
                // paginate
                RESPONSE_FOR(GetRoomEvents);
                // sync
                RESPONSE_FOR(Sync);
                RESPONSE_FOR(DefineFilter);
                // membership
                RESPONSE_FOR(CreateRoom);
                RESPONSE_FOR(InviteUser);
                RESPONSE_FOR(JoinRoomById);
                RESPONSE_FOR(JoinRoom);
                RESPONSE_FOR(LeaveRoom);
                RESPONSE_FOR(ForgetRoom);
                RESPONSE_FOR(Kick);
                RESPONSE_FOR(Ban);
                RESPONSE_FOR(Unban);
                // send
                RESPONSE_FOR(SendMessage);
                RESPONSE_FOR(SendToDevice);
                // states
                RESPONSE_FOR(GetRoomState);
                RESPONSE_FOR(SetRoomStateWithKey);
                RESPONSE_FOR(GetRoomStateWithKey);
                // ephemeral
                RESPONSE_FOR(SetTyping);
                RESPONSE_FOR(PostReceipt);
                RESPONSE_FOR(SetReadMarker);
                // content
                RESPONSE_FOR(UploadContent);
                RESPONSE_FOR(GetContent);
                RESPONSE_FOR(GetContentThumbnail);
                // encryption
                RESPONSE_FOR(UploadKeys);
                RESPONSE_FOR(QueryKeys);
                RESPONSE_FOR(ClaimKeys);
                // profile
                RESPONSE_FOR(GetUserProfile);
                RESPONSE_FOR(SetAvatarUrl);
                RESPONSE_FOR(SetDisplayName);

                m.addTrigger(UnrecognizedResponse{std::move(r)});
                return { std::move(m), lager::noop };
            }

#undef RESPONSE_FOR
            );

        // Rotate megolm keys for rooms whose users' device list has changed
        auto changedUsers = newClient.deviceLists.diff(oldDeviceLists);
        if (! changedUsers.empty()) {
            auto rooms = newClient.roomList.rooms;
            for (auto [roomId, room] : rooms) {
                auto it = std::find_if(changedUsers.begin(), changedUsers.end(),
                                       [=](auto userId) { return room.hasUser(userId); });
                if (it != changedUsers.end()) {
                    newClient.roomList.rooms =
                        std::move(newClient.roomList.rooms)
                        .update(roomId, [](auto room) {
                                            room.shouldRotateSessionKey = true;
                                            return room;
                                        });
                }
            }
        }

        return { std::move(newClient), std::move(effect) };
    }

    std::pair<Event, std::optional<std::string>> ClientModel::megOlmEncrypt(
        Event e, std::string roomId, Timestamp timeMs, RandomData random)
    {
        if (!crypto) {
            kzo.client.dbg() << "We do not have e2ee, so do not encrypt events" << std::endl;
            return { e, std::nullopt };
        }

        if (e.encrypted()) {
            kzo.client.dbg() << "The event is already encrypted. Ignoring it." << std::endl;
            return { e, std::nullopt };
        }

        auto &c = crypto.value();

        auto j = e.originalJson().get();
        auto r = roomList[roomId];

        if (! r.encrypted) {
            kzo.client.dbg() << "The room " << roomId
                             << " is not encrypted, so do not encrypt events" << std::endl;
            return { e, std::nullopt };
        }

        auto desc = r.sessionRotateDesc();

        auto keyOpt = std::optional<std::string>{};
        if (r.shouldRotateSessionKey) {
            kzo.client.dbg() << "We should rotate this session." << std::endl;
            keyOpt = c.rotateMegOlmSessionWithRandom(random, timeMs, roomId);
        } else {
            keyOpt = c.rotateMegOlmSessionWithRandomIfNeeded(random, timeMs, roomId, desc);
        }

        // we no longer need to rotate session
        // until next time a device change happens
        roomList.rooms = std::move(roomList.rooms)
            .update(roomId, [](auto r) { r.shouldRotateSessionKey = false; return r; });

        // so that Crypto::encryptMegOlm() can find room id
        j["room_id"] = roomId;

        auto content = c.encryptMegOlm(j);
        j["type"] = "m.room.encrypted";
        j["content"] = std::move(content);
        j["content"]["device_id"] = deviceId;

        kzo.client.dbg() << "Encrypted json is " << j.dump() << std::endl;
        kzo.client.dbg() << "Session key is " << (keyOpt ? keyOpt.value() : "<not rotated>") << std::endl;

        return { Event(JsonWrap(j)), keyOpt };
    }

    Event ClientModel::olmEncrypt(Event e,
                                  immer::map<std::string, immer::flex_vector<std::string>> userIdToDeviceIdMap, RandomData random)
    {
        if (!crypto) {
            kzo.client.dbg() << "We do not have e2ee, so do not encrypt events" << std::endl;
            return e;
        }

        if (e.encrypted()) {
            kzo.client.dbg() << "The event is already encrypted. Ignoring it." << std::endl;
            return e;
        }

        auto &c = crypto.value();

        auto origJson = e.originalJson().get();

        auto encJson = json::object();
        encJson["content"] = json{
            {"algorithm", CryptoConstants::olmAlgo},
            {"ciphertext", json::object()},
            {"sender_key", c.curve25519IdentityKey()},
        };

        encJson["type"] = "m.room.encrypted";

        for (auto [userId, devices] : userIdToDeviceIdMap) {
            for (auto dev : devices) {
                auto devInfoOpt = deviceLists.get(userId, dev);
                if (! devInfoOpt) {
                    continue;
                }
                auto devInfo = devInfoOpt.value();
                auto jsonForThisDevice = origJson;
                jsonForThisDevice["sender"] = this->userId;
                jsonForThisDevice["recipient"] = userId;
                jsonForThisDevice["recipient_keys"] = json{
                    {CryptoConstants::ed25519, devInfo.ed25519Key}
                };
                jsonForThisDevice["keys"] = json{
                    {CryptoConstants::ed25519, c.ed25519IdentityKey()}
                };
                encJson["content"]["ciphertext"]
                    .merge_patch(c.encryptOlmWithRandom(random, jsonForThisDevice, devInfo.curve25519Key));
                random.erase(0, Crypto::encryptOlmMaxRandomSize());
            }
        }

        return Event(JsonWrap(encJson));
    }

    immer::flex_vector<std::string /* deviceId */> ClientModel::devicesToSendKeys(std::string userId) const
    {
        auto trustLevelNeeded = DeviceTrustLevel::Unseen;

        // XXX: preliminary approach
        auto shouldSendP = [=](auto deviceInfo, auto /* deviceMap */) {
                               return deviceInfo.trustLevel >= trustLevelNeeded;
                           };


        auto devices = deviceLists.devicesFor(userId);

        return intoImmer(
            immer::flex_vector<std::string>{},
            zug::filter([=](auto n) {
                         auto [id, dev] = n;
                         return shouldSendP(dev, devices);
                     })
            | zug::map([=](auto n) {
                           return n.first;
                       }),
            devices);
    }

    std::size_t ClientModel::numOneTimeKeysNeeded() const
    {
        auto &crypto = this->crypto.value();

        // Keep half of max supported number of keys
        int numUploadedKeys = crypto.uploadedOneTimeKeysCount(CryptoConstants::signedCurve25519);
        int numKeysNeeded = crypto.maxNumberOfOneTimeKeys() / 2
            - numUploadedKeys;

        // Subtract the number of existing one-time keys, in case
        // the previous upload was not successful.
        int numKeysToGenerate = numKeysNeeded - crypto.numUnpublishedOneTimeKeys();

        return numKeysToGenerate;
    }

    std::size_t EncryptMegOlmEventAction::maxRandomSize()
    {
        return Crypto::rotateMegOlmSessionRandomSize();
    }

    std::size_t EncryptMegOlmEventAction::minRandomSize()
    {
        return 0;
    }

    std::size_t EncryptOlmEventAction::randomSize(EncryptOlmEventAction::UserIdToDeviceIdMap devices)
    {
        auto singleRandomSize = Crypto::encryptOlmMaxRandomSize();
        auto deviceNum = accumulate(devices, std::size_t{},
                                    [](auto counter, auto pair) { return counter + pair.second.size(); });
        return deviceNum * singleRandomSize;
    }

    std::size_t GenerateAndUploadOneTimeKeysAction::randomSize(std::size_t numToGen)
    {
        return Crypto::genOneTimeKeysRandomSize(numToGen);
    }

    std::size_t ClaimKeysAction::randomSize(immer::map<std::string, immer::flex_vector<std::string>> devicesToSend)
    {
        auto singleRandomSize = Crypto::createOutboundSessionRandomSize();
        auto deviceNum = accumulate(devicesToSend, std::size_t{},
                                    [](auto counter, auto pair) { return counter + pair.second.size(); });
        return deviceNum * singleRandomSize;
    }
}
