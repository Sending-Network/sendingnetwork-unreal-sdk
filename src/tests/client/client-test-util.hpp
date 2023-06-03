/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <lager/store.hpp>
#include <lager/event_loop/manual.hpp>

#include <store.hpp>
#include <sdk.hpp>

#include <client/client-model.hpp>
#include <base/basejob.hpp>
using namespace Kazv;

ClientModel createTestClientModel();

template<class DataT>
inline Response createResponse(std::string jobId, DataT body, JsonWrap data = {})
{
    Response r;
    r.statusCode = 200;
    r.body = body;
    json origData = data.get();
    origData["-job-id"] = jobId;
    r.extraData = origData;
    return r;
}

template<>
inline Response createResponse(std::string jobId, json j, JsonWrap data)
{
    return createResponse(jobId, JsonWrap(j), data);
}

inline auto createTestClientStore(SingleTypePromiseInterface<DefaultRetType> ph)
{
    return makeStore<ClientAction>(
        createTestClientModel(),
        &ClientModel::update,
        std::move(ph));
}

inline auto createTestClientStoreFrom(ClientModel m, SingleTypePromiseInterface<DefaultRetType> ph)
{
    return makeStore<ClientAction>(
        std::move(m),
        &ClientModel::update,
        std::move(ph));
}

bool hasAccessToken(const BaseJob &job);

template<class Model>
void assert1Job(Model &&model)
{
    REQUIRE(std::forward<Model>(model).nextJobs.size() == 1);
}

template<class Model, class Pred>
void for1stJob(Model &&model, Pred &&pred)
{
    std::forward<Pred>(pred)(std::forward<Model>(model).nextJobs[0]);
}

Context<SdkAction> dumbContext();
