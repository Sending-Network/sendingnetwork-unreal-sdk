/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include "status-utils.hpp"
#include "profile.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, GetUserProfileAction a)
    {
        m.addJob(m.job<GetUserProfileJob>().make(a.userId));
        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, GetUserProfileResponse r)
    {
        if (!r.success()) {
            return { std::move(m), failWithResponse(std::move(r)) };
        }

        auto d = json{
            {"displayName", r.displayname().value_or("")},
            {"avatarUrl", r.avatarUrl().value_or("")},
        };

        return {
            std::move(m),
            [data=JsonWrap(d)](auto &&) {
                return EffectStatus(true, data);
            }
        };
    }

    ClientResult updateClient(ClientModel m, SetAvatarUrlAction a)
    {
        m.addJob(m.job<SetAvatarUrlJob>().make(m.userId, a.avatarUrl));
        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, SetAvatarUrlResponse r)
    {
        if (!r.success()) {
            return { std::move(m), failWithResponse(std::move(r)) };
        }
        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, SetDisplayNameAction a)
    {
        m.addJob(m.job<SetDisplayNameJob>().make(m.userId, a.displayName));
        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, SetDisplayNameResponse r)
    {
        if (!r.success()) {
            return { std::move(m), failWithResponse(std::move(r)) };
        }
        return { std::move(m), lager::noop };
    }
}
