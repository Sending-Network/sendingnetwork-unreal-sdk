/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <status-utils.hpp>
#include "ephemeral.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, SetTypingAction a)
    {
        auto job = m.job<SetTypingJob>().make(
            m.userId,
            a.roomId,
            a.typing,
            a.timeoutMs)
            .withData(json{{"roomId", a.roomId}});

        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, SetTypingResponse r)
    {
        auto roomId = r.dataStr("roomId");
        if (! r.success()) {
            m.addTrigger(SetTypingFailed{roomId, r.errorCode(), r.errorMessage()});

            return { std::move(m), failWithResponse(r) };
        }

        m.addTrigger(SetTypingSuccessful{roomId});

        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, PostReceiptAction a)
    {
        auto job = m.job<PostReceiptJob>().make(
            a.roomId,
            /* receiptType = */ "m.read"s,
            a.eventId)
            .withData(json{{"roomId", a.roomId}});

        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, PostReceiptResponse r)
    {
        auto roomId = r.dataStr("roomId");
        if (! r.success()) {
            m.addTrigger(PostReceiptFailed{roomId, r.errorCode(), r.errorMessage()});

            return { std::move(m), lager::noop };
        }

        m.addTrigger(PostReceiptSuccessful{roomId});

        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, SetReadMarkerAction a)
    {
        auto job = m.job<SetReadMarkerJob>().make(
            a.roomId,
            /* mFullyRead = */ a.eventId)
            .withData(json{{"roomId", a.roomId}});

        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, SetReadMarkerResponse r)
    {
        auto roomId = r.dataStr("roomId");
        if (! r.success()) {
            m.addTrigger(SetReadMarkerFailed{roomId, r.errorCode(), r.errorMessage()});

            return { std::move(m), lager::noop };
        }

        m.addTrigger(SetReadMarkerSuccessful{roomId});

        return { std::move(m), lager::noop };
    }
}
