/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include "constants.hpp"
#include "login.hpp"

namespace Kazv
{
    GetLoginFlowsJob::GetLoginFlowsJob(std::string serverUrl)
        : BaseJob(std::move(serverUrl), BASE_PATH + "/login"s, GET)
    {
    }


    json loginDataToJson(std::string serverUrl,
                         std::string username,
                         std::string password,
                         std::optional<std::string> deviceName)
    {
        json j = json::object();
        j["type"] = "m.login.password";
        j["identifier"] = json::object();
        j["identifier"]["type"] = "m.id.user";
        j["identifier"]["user"] = std::move(username);
        j["password"] = std::move(password);
        j["initial_device_display_name"] = deviceName
            ? std::move(deviceName.value())
            : "libkazv"s;

        return j;
    }


    LoginJob::LoginJob(std::string serverUrl,
                       std::string username,
                       std::string password,
                       std::optional<std::string> deviceName)
        : BaseJob(serverUrl,
                  BASE_PATH + "/login"s,
                  POST,
                  std::string{},
                  ReturnType::Json,
                  JsonBody(loginDataToJson(serverUrl,
                                           std::move(username),
                                           std::move(password),
                                           std::move(deviceName))))
    {
    }
};
