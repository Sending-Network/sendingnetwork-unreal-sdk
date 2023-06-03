/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include <libkazv-config.hpp>

#include <string>
#include <variant>
#include <immer/flex_vector.hpp>
#include <immer/map.hpp>

#include <serialization/immer-flex-vector.hpp>
#include <serialization/immer-box.hpp>
#include <serialization/immer-map.hpp>
#include <serialization/immer-array.hpp>

#include <csapi/sync.hpp>
#include <event.hpp>

#include <crypto.hpp>

#include "clientutil.hpp"

namespace Kazv
{
    struct AddStateEventsAction
    {
        immer::flex_vector<Event> stateEvents;
    };

    struct AppendTimelineAction
    {
        immer::flex_vector<Event> events;
    };

    struct PrependTimelineAction
    {
        immer::flex_vector<Event> events;
        std::string paginateBackToken;
    };

    struct AddToTimelineAction
    {
        /// Events from oldest to latest
        immer::flex_vector<Event> events;
        std::optional<std::string> prevBatch;
        std::optional<bool> limited;
        std::optional<std::string> gapEventId;
    };

    struct AddAccountDataAction
    {
        immer::flex_vector<Event> events;
    };

    struct ChangeMembershipAction
    {
        RoomMembership membership;
    };

    struct ChangeInviteStateAction
    {
        immer::flex_vector<Event> events;
    };

    struct AddEphemeralAction
    {
        EventList events;
    };

    struct SetLocalDraftAction
    {
        std::string localDraft;
    };

    struct SetRoomEncryptionAction
    {
    };

    struct MarkMembersFullyLoadedAction
    {
    };

    struct SetHeroIdsAction
    {
        immer::flex_vector<std::string> heroIds;
    };

    struct RoomModel
    {
        using Membership = RoomMembership;

        std::string roomId;
        immer::map<KeyOfState, Event> stateEvents;
        immer::map<KeyOfState, Event> inviteState;
        // Smaller indices mean earlier events
        // (oldest) 0 --------> n (latest)
        immer::flex_vector<std::string> timeline;
        immer::map<std::string, Event> messages;
        immer::map<std::string, Event> accountData;
        Membership membership{};
        std::string paginateBackToken;
        /// whether this room has earlier events to be fetched
        bool canPaginateBack{true};

        immer::map<std::string /* eventId */, std::string /* prevBatch */> timelineGaps;

        immer::map<std::string, Event> ephemeral;

        std::string localDraft;

        bool encrypted{false};
        /// a marker to indicate whether we need to rotate
        /// the session key earlier than it expires
        /// (e.g. when a user in the room's device list changed
        /// or when someone joins or leaves)
        bool shouldRotateSessionKey{true};

        bool membersFullyLoaded{false};
        immer::flex_vector<std::string> heroIds;

        immer::flex_vector<std::string> joinedMemberIds() const;

        MegOlmSessionRotateDesc sessionRotateDesc() const;

        bool hasUser(std::string userId) const;

        using Action = std::variant<
            AddStateEventsAction,
            AppendTimelineAction,
            PrependTimelineAction,
            AddToTimelineAction,
            AddAccountDataAction,
            ChangeMembershipAction,
            ChangeInviteStateAction,
            AddEphemeralAction,
            SetLocalDraftAction,
            SetRoomEncryptionAction,
            MarkMembersFullyLoadedAction,
            SetHeroIdsAction
            >;

        static RoomModel update(RoomModel r, Action a);
    };

    using RoomAction = RoomModel::Action;

    inline bool operator==(RoomModel a, RoomModel b)
    {
        return a.roomId == b.roomId
            && a.stateEvents == b.stateEvents
            && a.inviteState == b.inviteState
            && a.timeline == b.timeline
            && a.messages == b.messages
            && a.accountData == b.accountData
            && a.membership == b.membership
            && a.paginateBackToken == b.paginateBackToken
            && a.canPaginateBack == b.canPaginateBack
            && a.timelineGaps == b.timelineGaps
            && a.ephemeral == b.ephemeral
            && a.localDraft == b.localDraft
            && a.encrypted == b.encrypted
            && a.shouldRotateSessionKey == b.shouldRotateSessionKey
            && a.membersFullyLoaded == b.membersFullyLoaded
            && a.heroIds == b.heroIds;
    }

    struct UpdateRoomAction
    {
        std::string roomId;
        RoomAction roomAction;
    };

    struct RoomListModel
    {
        immer::map<std::string, RoomModel> rooms;

        inline auto at(std::string id) const { return rooms.at(id); }
        inline auto operator[](std::string id) const { return rooms[id]; }
        inline bool has(std::string id) const { return rooms.find(id); }

        using Action = std::variant<
            UpdateRoomAction
            >;
        static RoomListModel update(RoomListModel l, Action a);
    };

    using RoomListAction = RoomListModel::Action;

    inline bool operator==(RoomListModel a, RoomListModel b)
    {
        return a.rooms == b.rooms;
    }

    template<class Archive>
    void serialize(Archive &ar, RoomModel &r, std::uint32_t const version)
    {
        ar
            & r.roomId
            & r.stateEvents
            & r.inviteState

            & r.timeline
            & r.messages
            & r.accountData
            & r.membership
            & r.paginateBackToken
            & r.canPaginateBack

            & r.timelineGaps
            & r.ephemeral

            & r.localDraft

            & r.encrypted
            & r.shouldRotateSessionKey

            & r.membersFullyLoaded
            ;

        if (version >= 1) {
            ar
                & r.heroIds
                ;
        }
    }

    template<class Archive>
    void serialize(Archive &ar, RoomListModel &l, std::uint32_t const /*version*/)
    {
        ar & l.rooms;
    }
}

BOOST_CLASS_VERSION(Kazv::RoomModel, 1)
BOOST_CLASS_VERSION(Kazv::RoomListModel, 0)
