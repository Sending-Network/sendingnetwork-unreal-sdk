/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include <lager/util.hpp>
#include <zug/sequence.hpp>
#include <zug/transducer/map.hpp>
#include <zug/transducer/filter.hpp>

#include "debug.hpp"

#include "room-model.hpp"
#include "cursorutil.hpp"


namespace Kazv
{
    RoomModel RoomModel::update(RoomModel r, Action a)
    {
        return lager::match(std::move(a))(
            [&](AddStateEventsAction a) {
                r.stateEvents = merge(std::move(r.stateEvents), a.stateEvents, keyOfState);

                // If m.room.encryption state event appears,
                // configure the room to use encryption.
                if (r.stateEvents.find(KeyOfState{"m.room.encryption", ""})) {
                    auto newRoom = update(std::move(r), SetRoomEncryptionAction{});
                    r = std::move(newRoom);
                }
                return r;
            },
            [&](AppendTimelineAction a) {
                auto eventIds = intoImmer(immer::flex_vector<std::string>(),
                                          zug::map(keyOfTimeline), a.events);
                r.timeline = r.timeline + eventIds;
                r.messages = merge(std::move(r.messages), a.events, keyOfTimeline);
                return r;
            },
            [&](PrependTimelineAction a) {
                auto eventIds = intoImmer(immer::flex_vector<std::string>(),
                                          zug::map(keyOfTimeline), a.events);
                r.timeline = eventIds + r.timeline;
                r.messages = merge(std::move(r.messages), a.events, keyOfTimeline);
                r.paginateBackToken = a.paginateBackToken;
                // if there are no more events we should not allow further paginating
                r.canPaginateBack = a.events.size() != 0;
                return r;
            },
            [&](AddToTimelineAction a) {
                auto eventIds = intoImmer(immer::flex_vector<std::string>(),
                                          zug::map(keyOfTimeline), a.events);

                auto oldMessages = r.messages;
                r.messages = merge(std::move(r.messages), a.events, keyOfTimeline);
                auto exists =
                    [=](auto eventId) -> bool {
                        return !! oldMessages.find(eventId);
                    };
                auto key =
                    [=](auto eventId) {
                        // sort first by timestamp, then by id
                        return std::make_tuple(r.messages[eventId].originServerTs(), eventId);
                    };

                r.timeline = sortedUniqueMerge(r.timeline, eventIds, exists, key);

                // TODO need other way to determine whether it is limited
                // in a pagination request (/messages does not have that field)
                if ((! a.limited.has_value() || a.limited.value())
                    && a.prevBatch.has_value()) {
                    // this sync is limited, add a Gap here
                    if (!eventIds.empty()) {
                        r.timelineGaps = std::move(r.timelineGaps).set(eventIds[0], a.prevBatch.value());
                    }
                }

                // remove the original Gap, as it is resolved
                if (a.gapEventId.has_value()) {
                    r.timelineGaps = std::move(r.timelineGaps).erase(a.gapEventId.value());
                }

                // remove all Gaps between the gapped event and the first event in this batch
                if (!eventIds.empty() && a.gapEventId.has_value()) {
                    auto cmp = [=](auto a, auto b) {
                                   return key(a) < key(b);
                               };
                    auto thisBatchStart = std::equal_range(r.timeline.begin(), r.timeline.end(), eventIds[0], cmp).first;
                    auto origBatchStart = std::equal_range(thisBatchStart, r.timeline.end(), a.gapEventId.value(), cmp).first;

                    std::for_each(thisBatchStart + 1, origBatchStart,
                                  [&](auto eventId) {
                                      r.timelineGaps = std::move(r.timelineGaps).erase(eventId);
                                  });
                }

                return r;
            },
            [&](AddAccountDataAction a) {
                r.accountData = merge(std::move(r.accountData), a.events, keyOfAccountData);
                return r;
            },
            [&](ChangeMembershipAction a) {
                r.membership = a.membership;
                return r;
            },
            [&](ChangeInviteStateAction a) {
                r.inviteState = merge(immer::map<KeyOfState, Event>{}, a.events, keyOfState);
                return r;
            },
            [&](AddEphemeralAction a) {
                r.ephemeral = merge(std::move(r.ephemeral), a.events, keyOfEphemeral);
                return r;
            },
            [&](SetLocalDraftAction a) {
                r.localDraft = a.localDraft;
                return r;
            },
            [&](SetRoomEncryptionAction) {
                r.encrypted = true;
                return r;
            },
            [&](MarkMembersFullyLoadedAction) {
                r.membersFullyLoaded = true;
                return r;
            },
            [&](SetHeroIdsAction a) {
                r.heroIds = a.heroIds;
                return r;
            }
            );
    }

    RoomListModel RoomListModel::update(RoomListModel l, Action a)
    {
        return lager::match(std::move(a))(
            [&](UpdateRoomAction a) {
                l.rooms = std::move(l.rooms)
                    .update(a.roomId,
                            [=](RoomModel oldRoom) {
                                oldRoom.roomId = a.roomId; // in case it is a new room
                                return RoomModel::update(std::move(oldRoom), a.roomAction);
                            });
                return l;
            }
            );
    }

    immer::flex_vector<std::string> RoomModel::joinedMemberIds() const
    {
        using MemberNode = std::pair<std::string, Kazv::Event>;

        auto memberNameTransducer =
            zug::filter(
                [](auto val) {
                    auto [k, v] = val;
                    auto [type, stateKey] = k;
                    return type == "m.room.member"s;
                })
            | zug::map(
                [](auto val) {
                    auto [k, v] = val;
                    auto [type, stateKey] = k;
                    return MemberNode{stateKey, v};
                })
            | zug::filter(
                [](auto val) {
                    auto [stateKey, ev] = val;
                    return ev.content().get()
                        .at("membership"s) == "join"s;
                })
            | zug::map(
                [](auto val) {
                    auto [stateKey, ev] = val;
                    return stateKey;
                });

        return intoImmer(
            immer::flex_vector<std::string>{},
            memberNameTransducer,
            stateEvents);
    }

    static Timestamp defaultRotateMs = 604800000;
    static int defaultRotateMsgs = 100;

    MegOlmSessionRotateDesc RoomModel::sessionRotateDesc() const
    {
        auto k = KeyOfState{"m.room.encryption", ""};
        auto content = stateEvents[k].content().get();
        auto ms = content.contains("rotation_period_ms")
            ? content["rotation_period_ms"].get<Timestamp>()
            : defaultRotateMs;
        auto msgs = content.contains("rotation_period_msgs")
            ? content["rotation_period_msgs"].get<int>()
            : defaultRotateMsgs;
        return MegOlmSessionRotateDesc{ ms, msgs };
    }

    bool RoomModel::hasUser(std::string userId) const
    {
        try {
            auto ev = stateEvents.at(KeyOfState{"m.room.member", userId});
            if (ev.content().get().at("membership") == "join") {
                return true;
            }
        } catch (const std::exception &) {
            return false;
        }
        return false;
    }
}
