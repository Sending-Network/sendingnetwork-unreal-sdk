/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>
#include <string>

#include <immer/map.hpp>
#include <immer/flex_vector.hpp>

#include <boost/serialization/string.hpp>
#include <serialization/std-optional.hpp>

#include <serialization/immer-map.hpp>

#include <crypto.hpp>
#include <csapi/keys.hpp>

#include "cursorutil.hpp"

namespace Kazv
{
    enum DeviceTrustLevel
    {
        Blocked,
        Unseen,
        Seen,
        Verified,
    };

    struct DeviceKeyInfo
    {
        std::string deviceId;
        std::string ed25519Key;
        std::string curve25519Key;
        std::optional<std::string> displayName;
        DeviceTrustLevel trustLevel{Unseen};
    };

    bool operator==(DeviceKeyInfo a, DeviceKeyInfo b);

    template<class Archive>
    void serialize(Archive &ar, DeviceKeyInfo &i, std::uint32_t const /*version*/)
    {
        ar
            & i.deviceId
            & i.ed25519Key
            & i.curve25519Key
            & i.displayName
            & i.trustLevel
            ;
    }

    struct DeviceListTracker
    {
        using DeviceMapT = immer::map<std::string /* deviceId */, DeviceKeyInfo>;
        immer::map<std::string /* userId */, bool /* outdated */> usersToTrackDeviceLists;
        immer::map<std::string /* userId */, DeviceMapT> deviceLists;

        template<class RangeT>
        void track(RangeT &&userIds) {
            for (auto userId : std::forward<RangeT>(userIds)) {
                usersToTrackDeviceLists = std::move(usersToTrackDeviceLists)
                    .set(userId, true);
            }
        }

        template<class RangeT>
        void untrack(RangeT &&userIds) {
            for (auto userId : std::forward<RangeT>(userIds)) {
                usersToTrackDeviceLists = std::move(usersToTrackDeviceLists).erase(userId);
            }
        }

        immer::flex_vector<std::string> outdatedUsers() const;

        bool addDevice(std::string userId, std::string deviceId, Api::QueryKeysJob::DeviceInformation deviceInfo, Crypto &crypto);

        void markUpToDate(std::string userId);

        DeviceMapT devicesFor(std::string userId) const;

        std::optional<DeviceKeyInfo> get(std::string userId, std::string deviceId) const;

        std::optional<DeviceKeyInfo> findByEd25519Key(std::string userId, std::string ed25519Key) const;
        std::optional<DeviceKeyInfo> findByCurve25519Key(std::string userId, std::string curve25519Key) const;

        /// returns a list of users whose device list has changed
        immer::flex_vector<std::string> diff(DeviceListTracker that) const;
    };

    template<class Archive>
    void serialize(Archive &ar, DeviceListTracker &t, std::uint32_t const /*version*/)
    {
        ar
            & t.usersToTrackDeviceLists
            & t.deviceLists
            ;
    }
}

BOOST_CLASS_VERSION(Kazv::DeviceKeyInfo, 0)
BOOST_CLASS_VERSION(Kazv::DeviceListTracker, 0)
