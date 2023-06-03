/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#include "basejob.hpp"

namespace Kazv
{
    class GetLoginFlowsJob : public BaseJob
    {
    public:
        GetLoginFlowsJob(std::string serverUrl);
    };
    class LoginJob : public BaseJob
    {
    public:
        LoginJob(std::string serverUrl,
                 std::string username,
                 std::string password,
                 std::optional<std::string> deviceName);
    };
};
