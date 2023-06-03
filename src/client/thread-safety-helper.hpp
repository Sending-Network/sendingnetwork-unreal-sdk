/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <libkazv-config.hpp>

#if LIBKAZV_BUILT_WITH_DEBUG
#ifndef KAZV_USE_THREAD_SAFETY_HELPER
#define KAZV_USE_THREAD_SAFETY_HELPER
#endif
#endif

#ifdef KAZV_USE_THREAD_SAFETY_HELPER
#include <mutex>
struct ThreadNotMatchException // Don't derive from std::exception to avoid catch-all catch clauses
{
    std::string m_what;

    std::string what() const;
};

struct EventLoopThreadIdKeeper
{
    mutable std::mutex m_mutex;
    std::optional<std::thread::id> m_id;

    /// This should only be called in the event loop thread.
    void set(std::thread::id id) {
        std::lock_guard<std::mutex> g(m_mutex);
        m_id = id;
    }

    std::optional<std::thread::id> get() const {
        std::lock_guard<std::mutex> g(m_mutex);
        return m_id;
    }
};
#define KAZV_THREAD_ID_VAR _threadSafetyHelper_threadId
#define KAZV_ON_EVENT_LOOP_VAR _threadSafetyHelper_onEventLoop
#define KAZV_EVENT_LOOP_THREAD_ID_KEEPER_VAR _threadSafetyHelper_eventLoopThreadIdKeeper
#define KAZV_DECLARE_THREAD_ID() bool KAZV_ON_EVENT_LOOP_VAR{false};    \
    std::thread::id KAZV_THREAD_ID_VAR = std::this_thread::get_id();
#define KAZV_DECLARE_EVENT_LOOP_THREAD_ID_KEEPER(_initializer) \
    EventLoopThreadIdKeeper *KAZV_EVENT_LOOP_THREAD_ID_KEEPER_VAR = _initializer
//#define KAZV_INIT_THREAD_ID_FROM_KEEPER() KAZV_THREAD_ID_VAR(KAZV_EVENT_LOOP_THREAD_ID_KEEPER_VAR.get())
#define KAZV_VERIFY_THREAD_ID()                                         \
    do {                                                                \
        auto _threadSafetyHelper_local_idActual = std::this_thread::get_id(); \
                                                                        \
        if (KAZV_ON_EVENT_LOOP_VAR) {                                   \
            auto _threadSafetyHelper_local_idExpected =                 \
                KAZV_EVENT_LOOP_THREAD_ID_KEEPER_VAR ? KAZV_EVENT_LOOP_THREAD_ID_KEEPER_VAR->get() : std::nullopt; \
            auto cond = \
                _threadSafetyHelper_local_idExpected.has_value()        \
                ? _threadSafetyHelper_local_idExpected.value() == _threadSafetyHelper_local_idActual \
                /* if the id is not set yet it means the event loop is not yet run, so it does not matter anyway */ \
                : true;                                                 \
            if (!cond) {                                                \
                throw ThreadNotMatchException{"Current object belongs to the event loop, but method is called outside the event loop"}; \
            }                                                           \
        } else {                                                        \
            if (! (KAZV_THREAD_ID_VAR == _threadSafetyHelper_local_idActual)) { \
                throw ThreadNotMatchException{"Current thread id does not match the id of the thread where it belongs"}; \
            }                                                           \
        }                                                               \
    } while (false)

#else
#define KAZV_DECLARE_THREAD_ID()
#define KAZV_VERIFY_THREAD_ID()
#define KAZV_DECLARE_EVENT_LOOP_THREAD_ID_KEEPER(_initializer)
#endif
