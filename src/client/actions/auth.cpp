/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2022 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <debug.hpp>
#include <jobinterface.hpp>
#include <eventinterface.hpp>

#include "auth.hpp"
#include "status-utils.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, LoginAction a)
    {
        m.addJob(LoginJob{a.serverUrl,
                          "m.login.password"s, // type
                          UserIdentifier{ "m.id.user"s, json{{"user", a.username}} }, // identifier
                          a.password,
                          {}, // token, not used
                          {}, // device id, not used
                          a.deviceName.value_or("libkazv")}
            .withData(json{
                    {"serverUrl", a.serverUrl},
                }));
        return { m, lager::noop };
    }

    ClientResult processResponse(ClientModel m, LoginResponse r)
    {
        if (! r.success()) {
            m.addTrigger(LoginFailed{r.errorCode(), r.errorMessage()});
            return { std::move(m), failWithResponse(r) };
        }

        kzo.client.dbg() << "Job success" << std::endl;
        const json &j = r.jsonBody().get();
        // TODO: replace this with r.wellKnown()
        std::string serverUrl = j.contains("well_known")
            ? j.at("well_known").at("m.node").at("base_url").get<std::string>()
            : r.dataStr("serverUrl");

        // Synapse will return the server url with trailing slash
        // and not recognize double slashes in the middle
        while (serverUrl.back() == '/') {
            serverUrl.pop_back();
        }

        m.serverUrl = serverUrl;
        m.userId = r.userId().value_or(DEFVAL);
        m.token = r.accessToken().value_or(DEFVAL);
        m.deviceId = r.deviceId().value_or(DEFVAL);
        m.loggedIn = true;

        m.addTrigger(LoginSuccessful{});

        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, TokenLoginAction a)
    {
        m.serverUrl = a.serverUrl;
        m.userId = a.username;
        m.token = a.token;
        m.deviceId = a.deviceId;
        m.loggedIn = true;

        m.addTrigger(LoginSuccessful{});
        return { std::move(m), lager::noop };
    }


    ClientResult updateClient(ClientModel m, LogoutAction)
    {
        // Note: this only performs a soft-logout.
        m.serverUrl = "";
        m.userId = "";
        m.token = "";
        m.deviceId = "";
        m.loggedIn = false;

        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, GetWellknownAction a)
    {
        auto pos = a.userId.find(':');
        if (pos == std::string::npos || pos == a.userId.size() - 1) {
            return { std::move(m), simpleFail };
        }

        auto serverUrl = "https://" + a.userId.substr(pos + 1);

        m.addJob(GetWellknownJob{serverUrl}
            .withData(json{{"serverUrl", serverUrl}}));
        return { m, lager::noop };
    }

    ClientResult processResponse(ClientModel m, GetWellknownResponse r)
    {
        auto success = r.success() || r.statusCode == 404;
        auto error = std::string();

        std::string serverUrl = r.dataStr("serverUrl");

        if (r.success()) {
            auto data = r.data();
            if (data.node.baseUrl.empty()) {
                success = false;
                error = "FAIL_PROMPT";
            } else {
                serverUrl = data.node.baseUrl;
            }
        } else {
            error = "FAIL_PROMPT";
        }

        return {
            std::move(m),
            [success, serverUrl, error, r](auto &&) {
                auto data = json{
                    {"nodeUrl", serverUrl},
                    {"error", error},
                    {"errorCode", r.errorCode()},
                };
                return EffectStatus(success, data);
            }
        };
    }

    ClientResult updateClient(ClientModel m, GetVersionsAction a)
    {
        m.addJob(GetVersionsJob{a.serverUrl});
        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, GetVersionsResponse r)
    {
        return {
            std::move(m),
            [r](auto &&ctx) {
                if (r.success()) {
                    return EffectStatus(r.success(), json{
                        {"versions", r.versions()},
                    });
                } else {
                    return failWithResponse(r)(std::forward<decltype(ctx)>(ctx));
                }
            }
        };
    }

}
