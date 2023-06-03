/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include "client-test-util.hpp"

#include <asio-promise-handler.hpp>

ClientModel createTestClientModel()
{
    ClientModel m;
    m.serverUrl = "example.com";
    m.userId = "@bob:example.com";
    m.token = "exampletoken";
    m.deviceId = "exampledevice";
    m.loggedIn = true;
    return m;
}


bool hasAccessToken(const BaseJob &job)
{
    auto header = job.requestHeader();
    return header->find("Authorization") != header->end();
}

struct DumbPromise : public TypelessPromise
{
    using DataT = EffectStatus;

    template<class Func>
    DumbPromise then(Func &&) { return DumbPromise(); }
    bool ready() const { return true; }
    DataT get() const { return DataT(); }
};

struct DumbPromiseHandler
{
    using DataT = EffectStatus;

    template<class Data, class Func>
    auto create(Func &&) { return DumbPromise(); }

    template<class Ignore>
    auto createResolved(Ignore &&) { return DumbPromise(); }
};

Context<SdkAction> dumbContext()
{
    return Context<SdkAction>(
        [](auto &&) { return DumbPromise(); },
        DumbPromiseHandler(),
        lager::make_deps()
    );
}
