/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <zug/into_vector.hpp>

#include "sdk-model.hpp"

#include <debug.hpp>

#include "actions/encryption.hpp"
#include "actions/states.hpp"

namespace Kazv
{

    static const int syncInterval = 2000; // ms

    SdkResult SdkModel::update(SdkModel s, SdkAction a)
    {
        return lager::match(a)(
            [&](ClientAction a) -> SdkResult {
                auto [newClient, clientEff] =
                    ClientModel::update(std::move(s.client), a);
                s.client = std::move(newClient);

                auto jobs = s.client.popAllJobs();
                auto triggers = s.client.popAllTriggers();

                auto eff =
                    [=](auto &&ctx) {
                        auto sdkEffect = SdkEffect(clientEff);
                        auto effectPromise = sdkEffect(ctx);

                        auto &jh = getJobHandler(ctx);
                        auto &ee = getEventEmitter(ctx);

                        auto ph = ctx.promiseInterface();

                        auto promises = zug::into_vector(
                            zug::map([=, &jh](auto j) {
                                         return ctx.createWaitingPromise(
                                             [=, &jh](auto resolve) {
                                                 jh.submit(
                                                     j,
                                                     [=](Response r) {
                                                         resolve(ctx.dispatch(ProcessResponseAction{r}));
                                                     });
                                             });
                                     }), jobs);

                        auto combinedPromise = promises.size() ? ph.all(promises) : effectPromise;

                        for (auto t : triggers) {
                            ee.emit(t);
                        }
                        return combinedPromise;
                    };

                return { std::move(s), eff };
            }
            );
    }
}
