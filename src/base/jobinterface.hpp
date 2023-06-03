/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include "libkazv-config.hpp"
#include <functional>

#include "basejob.hpp"

namespace Kazv
{
    inline const std::string headFailureCancelledErrorCode{"MOE_KAZV_MXC_HEAD_FAILURE_CANCELLED"};
    inline const std::string headFailureCancelledErrorMsg{"This job is cancelled because one before it failed."};
    inline const int headFailureCancelledStatusCode{490};

    struct JobInterface
    {
        virtual ~JobInterface() = default;
        virtual void async(std::function<void()> func) = 0;
        virtual void setTimeout(std::function<void()> func, int ms,
                                std::optional<std::string> timerId = std::nullopt) = 0;
        virtual void setInterval(std::function<void()> func, int ms,
                                 std::optional<std::string> timerId = std::nullopt) = 0;

        /// cancels all pending timers with timerId
        virtual void cancel(std::string timerId) = 0;

        /// makes an async fetch.
        /// callback should not block the current thread.
        /// if job has a `queueId`, it must be queued and executed only after
        /// every job before it in the queue `queueId` returned.
        /// if job has a `queuePolicy` of CancelFutureIfFailed, the failure of
        /// this job must remove every other job after it in the queue `queueId`.
        virtual void submit(BaseJob job, std::function<void(Response)> callback) = 0;
    };

}
