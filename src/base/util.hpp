/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include "libkazv-config.hpp"

#include "basejob.hpp"

namespace Kazv
{
    /// Returns whether we should retry for this (unsuccessful) event,
    /// and the suggested interval in ms before retrying from the server.
    /// If the server has not provided a suggested interval, -1 will be
    /// used to indicate that the client should choose an interval instead.
    inline std::pair<bool, int> shouldRetryFor(BaseJob::Response res) {
        bool shouldRetry = false;
        int retryAfterMs = -1;
        bool errorCodeFromJson = false;
        if (BaseJob::isBodyJson(res.body)) {
            const auto &j = jsonBody(res).get();
            if (j.contains("errcode"s)) {
                errorCodeFromJson = true;
                auto code = j["errcode"s];
                if (code == "M_LIMIT_EXCEEDED"s) {
                    shouldRetry = true;
                    if (j.contains("retry_after_ms"s)) {
                        retryAfterMs = j["retry_after_ms"s];
                    }
                }
            }
        }
        if (! errorCodeFromJson) {
            auto c = res.statusCode;
            if (c == 408 // Request Timeout
                || c == 429 // Too many requests
                || c == 500 // Internal Server Error
                || c == 502 // Bad Gateway
                || c == 503 // Service Unavailable
                || c == 504 // Gateway Timeout
                ) {
                shouldRetry = true;
            }
        }
        return {shouldRetry, retryAfterMs};
    }
}
