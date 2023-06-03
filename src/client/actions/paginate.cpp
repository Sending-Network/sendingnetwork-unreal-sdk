/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

// eager requires tuplify but did not include it.
// This is a bug.
#include <zug/tuplify.hpp>
#include <zug/transducer/eager.hpp>
#include <zug/into.hpp>

#include <lager/util.hpp>

#include <types.hpp>
#include <debug.hpp>

#include <cursorutil.hpp>

#include <status-utils.hpp>
#include "paginate.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, PaginateTimelineAction a)
    {
        auto roomId = a.roomId;
        auto room = m.roomList.at(roomId);

        if (! room.timelineGaps.find(a.fromEventId)) {
            kzo.client.dbg() << "There is no such gap at " << a.fromEventId << std::endl;
            return { m, simpleFail };
        }

        auto paginateBackToken = room.timelineGaps[a.fromEventId];

        auto job = m.job<GetRoomEventsJob>().make(
            roomId,
            paginateBackToken, // from
            "b"s, // dir
            std::nullopt, // to
            a.limit).withData(json{{"roomId", roomId},
                                   {"gapEventId", a.fromEventId}});

        m.addJob(std::move(job));

        return { m, lager::noop };
    }

    ClientResult processResponse(ClientModel m, GetRoomEventsResponse r)
    {
        auto roomId = r.dataStr("roomId");
        auto gapEventId = r.dataStr("gapEventId");

        if (! r.success()) {
            kzo.client.dbg() << "Get room events failed" << std::endl;
            m.addTrigger(PaginateFailed{roomId});
            return { m, failWithResponse(r) };
        }

        auto paginateBackToken = r.end();
        auto chunk = r.chunk();

        try {
            // kzo.client.dbg() << "We got " << chunk.size() << " events here" << std::endl;
            auto room = m.roomList.at(roomId);
            immer::flex_vector_transient<Event> events{};
            // The timeline from paginate backwards is returned
            // in reversed order, so restore the order.
            zug::into(events, zug::reversed, chunk);

            AddToTimelineAction action
                {events.persistent(), paginateBackToken, std::nullopt, gapEventId};

            m.roomList = RoomListModel::update(
                std::move(m.roomList),
                UpdateRoomAction{roomId, action});

            m.addTrigger(PaginateSuccessful{roomId});

            return { std::move(m), lager::noop };
        } catch (const std::out_of_range &e) {
            // Ignore it, the client model is modified
            // such that it knows nothing about this room.
            // May happen in debugger.
            return { std::move(m), simpleFail };
        }
    }
}
