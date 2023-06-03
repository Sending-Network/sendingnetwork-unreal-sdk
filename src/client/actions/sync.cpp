/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <lager/util.hpp>
#include <zug/transducer/map.hpp>
#include <zug/transducer/cat.hpp>
#include <zug/transducer/filter.hpp>
#include <zug/sequence.hpp>

#include <jobinterface.hpp>
#include <debug.hpp>

#include "cursorutil.hpp"

#include "sync.hpp"

#include "encryption.hpp"
#include "status-utils.hpp"

namespace Kazv
{
    // Atomicity guaranteed: if the sync action is created
    // before an action that reasonably changes Client
    // (e.g. roll back to an earlier state, obtain other
    // events), but executed
    // after that action, the sync will still give continuous
    // data about the events. (Sync will not "skip" events)
    // This is because this function takes the sync token
    // from the ClientModel model it is passed.
    ClientResult updateClient(ClientModel m, SyncAction)
    {
        kzo.client.dbg() << "Start syncing with token " <<
            (m.syncToken ? m.syncToken.value() : "<null>") << std::endl;

        bool isInitialSync = ! m.syncToken;

        m.syncing = true;

        std::string filter = m.syncToken ? m.incrementalSyncFilterId : m.initialSyncFilterId;
        m.addJob(m.job<SyncJob>()
                 .make(filter,
                       m.syncToken,
                       std::nullopt, // fullState
                       std::nullopt, // setPresence
                       // Let initial sync return immediately
                       isInitialSync ? 0 : m.syncTimeoutMs
                     )
                 .withData(json{{"is", isInitialSync ? "initial" : "incremental"}}));
        return { m, lager::noop };
    }


    static KazvEventList loadRoomsFromSyncInPlace(ClientModel &m, SyncJob::Rooms rooms)
    {
        auto l = std::move(m.roomList);
        auto eventsToEmit = KazvEventList{}.transient();

        auto updateRoomImpl =
            [&l](auto id, auto a) {
                l = RoomListModel::update(
                    std::move(l),
                    UpdateRoomAction{std::move(id), std::move(a)});
            };
        auto updateSingleRoom =
            [&, updateRoomImpl](const auto &id, const auto &room, auto membership) {
                if (!l.has(id) || l[id].membership != membership) {
                    eventsToEmit.push_back(RoomMembershipChanged{membership, id});
                }
                updateRoomImpl(id, ChangeMembershipAction{membership});

                auto timelineEvents =
                    intoImmer(
                        EventList{},
                        zug::map([=](Event e) {
                                     return Event::fromSync(e, id);
                                 }),
                        room.timeline.events);
                eventsToEmit.append(
                    intoImmer(
                        KazvEventList{},
                        zug::map([=](Event e) -> KazvEvent {
                                     return ReceivingRoomTimelineEvent{std::move(e), id};
                                 }),
                        timelineEvents).transient());
                updateRoomImpl(id, AddToTimelineAction{timelineEvents,
                            room.timeline.prevBatch,
                            room.timeline.limited,
                            std::nullopt // we do not have a gapEventId
                            });
                if (room.state) {
                    eventsToEmit.append(
                        intoImmer(
                            KazvEventList{},
                            zug::map([=](Event e) -> KazvEvent {
                                         return ReceivingRoomStateEvent{std::move(e), id};
                                     }),
                            room.state.value().events).transient());
                    updateRoomImpl(id, AddStateEventsAction{room.state.value().events});
                }

                // Process state events in timeline, which should have arrived later
                // than those in room.state .
                updateRoomImpl(id, AddStateEventsAction{
                        intoImmer(EventList{},
                                  zug::filter([=](Event e) {
                                                  return e.isState();
                                              }),
                                  timelineEvents)});

                if (room.accountData) {
                    eventsToEmit.append(
                        intoImmer(
                            KazvEventList{},
                            zug::map([=](Event e) -> KazvEvent {
                                         return ReceivingRoomAccountDataEvent{std::move(e), id};
                                     }),
                            room.state.value().events).transient());
                    updateRoomImpl(id, AddAccountDataAction{room.accountData.value().events});
                }
            };

        auto updateRoomSummary =
            [=](const auto &id, const auto &room) {
                if (!room.summary.has_value()) {
                    return;
                }
                if (!room.summary->mHeroes.empty()) {
                    auto newHeroes = room.summary->mHeroes;
                    updateRoomImpl(id, SetHeroIdsAction{immer::flex_vector<std::string>(newHeroes.begin(), newHeroes.end())});
                }
            };

        auto updateJoinedRoom =
            [=](const auto &id, const auto &room) {
                updateSingleRoom(id, room, RoomMembership::Join);
                if (room.ephemeral) {
                    updateRoomImpl(id, AddEphemeralAction{room.ephemeral.value().events});
                }
                // TODO update other info such as
                // notification and summary

                updateRoomSummary(id, room);
            };

        auto updateInvitedRoom =
            [=](const auto &id, const auto &room) {
                updateRoomImpl(id, ChangeMembershipAction{RoomMembership::Invite});
                if (room.inviteState) {
                    updateRoomImpl(id, ChangeInviteStateAction{room.inviteState.value().events});
                }
            };

        auto updateLeftRoom =
            [=](const auto &id, const auto &room) {
                updateSingleRoom(id, room, RoomMembership::Leave);
            };

        for (const auto &[id, room]: rooms.join) {
            updateJoinedRoom(id, room);
        }

        // TODO update info for invited rooms
        for (const auto &[id, room]: rooms.invite) {
            updateInvitedRoom(id, room);
        }

        for (const auto &[id, room]: rooms.leave) {
            updateLeftRoom(id, room);
        }

        m.roomList = std::move(l);
        return eventsToEmit.persistent();
    }

    static KazvEventList loadPresenceFromSyncInPlace(ClientModel &m, EventList presence)
    {
        auto eventsToEmit = intoImmer(
            KazvEventList{},
            zug::map([](Event e) { return ReceivingPresenceEvent{e}; }),
            presence);
        m.presence = merge(std::move(m.presence), presence, keyOfPresence);
        return eventsToEmit;
    }

    static KazvEventList loadAccountDataFromSyncInPlace(ClientModel &m, EventList accountData)
    {
        auto eventsToEmit = intoImmer(
            KazvEventList{},
            zug::map([](Event e) { return ReceivingPresenceEvent{e}; }),
            accountData);
        m.accountData = merge(std::move(m.accountData), accountData, keyOfAccountData);
        return eventsToEmit;
    }

    static KazvEventList loadToDeviceFromSyncInPlace(ClientModel &m, JsonWrap toDevice)
    {
        if (toDevice.get().contains("events")) {
            auto events = toDevice.get()["events"];
            auto msgs = intoImmer(
                EventList{},
                zug::map([](const json &j) { return Event(j); }),
                events);

            m.toDevice = std::move(m.toDevice) + msgs;

            return intoImmer(
                KazvEventList{},
                zug::map([](Event e) { return ReceivingToDeviceMessage{e}; }),
                msgs);
        }
        return {};
    }

    ClientResult processResponse(ClientModel m, SyncResponse r)
    {
        if (! r.success()) {
            m.addTrigger(SyncFailed{});
            kzo.client.dbg() << "Sync failed" << std::endl;
            kzo.client.dbg() << r.statusCode << std::endl;
            if (isBodyJson(r.body)) {
                auto j = r.jsonBody();
                kzo.client.dbg() << "Json says: " << j.get().dump() << std::endl;
            } else {
                kzo.client.dbg() << "Response body: "
                          << std::get<BaseJob::BytesBody>(r.body) << std::endl;
            }
            return { std::move(m), failWithResponse(r) };
        }

        kzo.client.dbg() << "Sync successful" << std::endl;

        auto rooms = r.rooms();
        auto accountData = r.accountData();
        auto presence = r.presence();
        // load the info that has been sync'd

        m.syncToken = r.nextBatch();

        if (rooms) {
            m.addTriggers(loadRoomsFromSyncInPlace(m, std::move(rooms.value())));
        }

        if (presence) {
            m.addTriggers(loadPresenceFromSyncInPlace(m, std::move(presence.value().events)));
        }

        if (accountData) {
            m.addTriggers(loadAccountDataFromSyncInPlace(m, std::move(accountData.value().events)));
        }

        m.addTriggers(loadToDeviceFromSyncInPlace(m, r.toDevice()));

        auto is = r.dataStr("is");
        auto isInitialSync = is == "initial";

        if (m.crypto) {
            kzo.client.dbg() << "E2EE is on. Processing device lists and one-time key counts." << std::endl;
            auto &crypto = m.crypto.value();
            // process deviceLists
            if (isInitialSync) {
                auto encryptedUsers =
                    zug::sequence(
                        zug::map([](auto n) { return n.second; })
                        | zug::filter([](auto room) { return room.encrypted; })
                        | zug::map([](auto room) { return room.joinedMemberIds(); })
                        | zug::cat,
                        // no need to use distinct here as the map will overwrite
                        m.roomList.rooms);

                m.deviceLists.track(std::move(encryptedUsers));

            } else {
                const auto &l = r.deviceLists().get();
                if (l.contains("changed")) {
                    const auto &changed = l.at("changed");
                    m.deviceLists.track(changed);
                }

                if (l.contains("left")) {
                    const auto &left = l.at("left");
                    m.deviceLists.untrack(left);
                }
            }

            // deviceOneTimeKeysCount
            crypto.setUploadedOneTimeKeysCount(r.deviceOneTimeKeysCount());

            auto model = tryDecryptEvents(std::move(m));
            m = std::move(model);
        }

        m.addTrigger(SyncSuccessful{r.nextBatch()});

        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, SetShouldSyncAction a)
    {
        m.shouldSync = a.shouldSync;
        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, PostInitialFiltersAction)
    {
        if (m.syncing) {
            return { std::move(m), lager::noop };
        }

        Filter initialSyncFilter;
        initialSyncFilter.room.timeline.limit = 1;
        initialSyncFilter.room.state.lazyLoadMembers = true;
        auto firstJob = m.job<DefineFilterJob>()
            .make(m.userId, initialSyncFilter)
            .withData(json{{"is", "initialSyncFilter"}})
            .withQueue("post-filter", CancelFutureIfFailed);

        m.addJob(firstJob);
        Filter incrementalSyncFilter;
        incrementalSyncFilter.room.timeline.limit = 20;
        incrementalSyncFilter.room.state.lazyLoadMembers = true;
        m.addJob(m.job<DefineFilterJob>()
                 .make(m.userId, incrementalSyncFilter)
                 .withData(json{{"is", "incrementalSyncFilter"}})
                 .withQueue("post-filter", CancelFutureIfFailed));

        m.syncing = true;

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, DefineFilterResponse r)
    {
        auto is = r.dataStr("is");
        if (! r.success()) {
            m.syncing = false;
            kzo.client.dbg() << "posting filter failed: " << r.errorCode() << r.errorMessage() << std::endl;
            m.addTrigger(PostInitialFiltersFailed{r.errorCode(), r.errorMessage()});
            return { std::move(m), lager::noop };
        }

        kzo.client.dbg() << "filter " << is << " is posted" << std::endl;

        if (is == "incrementalSyncFilter") {
            m.incrementalSyncFilterId = r.filterId();
            m.addTrigger(PostInitialFiltersSuccessful{});
        } else {
            m.initialSyncFilterId = r.filterId();
        }

        return { std::move(m), lager::noop };
    }
}
