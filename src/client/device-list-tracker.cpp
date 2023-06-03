/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include "device-list-tracker.hpp"

#include <algorithm>

#include <zug/transducer/filter.hpp>
#include <zug/sequence.hpp>
#include <zug/transducer/distinct.hpp>
#include <zug/transducer/chain.hpp>

#include <debug.hpp>

namespace Kazv
{
    immer::flex_vector<std::string> DeviceListTracker::outdatedUsers() const
    {
        return intoImmer(
            immer::flex_vector<std::string>{},
            zug::filter([](auto n) {
                            auto [userId, outdated] = n;
                            return outdated;
                        })
            | zug::map([](auto n) {
                           auto [userId, outdated] = n;
                           return userId;
                       }),
            usersToTrackDeviceLists);
    }


    bool DeviceListTracker::addDevice(std::string userId, std::string deviceId, Api::QueryKeysJob::DeviceInformation deviceInfo, Crypto &crypto)
    {
        using namespace CryptoConstants;
        if (userId != deviceInfo.userId
            || deviceId != deviceInfo.deviceId) {
            return false;
        }

        // if the ed25519 key changed, reject
        auto curEd25519Key = deviceInfo.keys[ed25519 + ":" + deviceId];
        if (deviceLists[userId].find(deviceId)
            && curEd25519Key != deviceLists[userId][deviceId].ed25519Key) {
            return false;
        }

        kzo.client.dbg() << "verifying device info" << std::endl;

        if (crypto.verify(deviceInfo, userId, deviceId, curEd25519Key)) {
            kzo.client.dbg() << "passed verification" << std::endl;
            auto info = DeviceKeyInfo{
                deviceId,
                deviceInfo.keys[ed25519 + ":" + deviceId],
                deviceInfo.keys[curve25519 + ":" + deviceId],
                deviceInfo.unsignedData ? deviceInfo.unsignedData.value().deviceDisplayName : std::nullopt
            };

            deviceLists = std::move(deviceLists)
                .update(userId, [=](auto deviceMap) {
                                    return std::move(deviceMap).set(deviceId, info);
                                });
            return true;
        }

        kzo.client.dbg() << "did not pass verification" << std::endl;
        return false;
    }

    void DeviceListTracker::markUpToDate(std::string userId)
    {
        usersToTrackDeviceLists = std::move(usersToTrackDeviceLists).set(userId, false);
    }

    std::optional<DeviceKeyInfo> DeviceListTracker::get(std::string userId, std::string deviceId) const
    {
        try {
            return deviceLists.at(userId).at(deviceId);
        } catch (const std::exception &) {
            return std::nullopt;
        }
    }

    std::optional<DeviceKeyInfo> DeviceListTracker::findByEd25519Key(
        std::string userId, std::string ed25519Key) const
    {
        auto devices = deviceLists.at(userId);

        auto it = std::find_if(devices.begin(), devices.end(),
                               [=](auto n) {
                                   auto [deviceId, info] = n;
                                   return info.ed25519Key == ed25519Key;
                               });
        if (it != devices.end()) {
            return it->second;
        } else {
            return std::nullopt;
        }
    }

    std::optional<DeviceKeyInfo> DeviceListTracker::findByCurve25519Key(
        std::string userId, std::string curve25519Key) const
    {
        auto devices = deviceLists.at(userId);

        auto it = std::find_if(devices.begin(), devices.end(),
                               [=](auto n) {
                                   auto [deviceId, info] = n;
                                   return info.curve25519Key == curve25519Key;
                               });
        if (it != devices.end()) {
            return it->second;
        } else {
            return std::nullopt;
        }
    }

    immer::flex_vector<std::string> DeviceListTracker::diff(DeviceListTracker that) const
    {
        auto users = zug::sequence(zug::map([](auto n) { return n.first; }), deviceLists);
        auto thatUsers = zug::sequence(zug::map([](auto n) { return n.first; }), that.deviceLists);
        auto changedUsers = intoImmer(
            immer::flex_vector<std::string>{},
            zug::chain(std::move(thatUsers))
            | zug::distinct
            | zug::filter([=](auto userId) {
                              return deviceLists[userId] != that.deviceLists[userId];
                          }),
            std::move(users));
        return changedUsers;
    }

    auto DeviceListTracker::devicesFor(std::string userId) const -> DeviceMapT
    {
        return deviceLists[userId];
    }

    bool operator==(DeviceKeyInfo a, DeviceKeyInfo b)
    {
        return a.deviceId == b.deviceId
            && a.ed25519Key == b.ed25519Key
            && a.curve25519Key == b.curve25519Key
            && a.displayName == b.displayName
            && a.trustLevel == b.trustLevel;
    }
}
