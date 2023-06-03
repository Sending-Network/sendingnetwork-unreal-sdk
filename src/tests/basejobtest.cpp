/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include <catch2/catch_all.hpp>

#include <iostream>
#include <future>

#include <basejob.hpp>
#include <cprjobhandler.hpp>
#include "tests.hpp"

using namespace Kazv;

TEST_CASE("Base job should fetch correctly", "[basejob]")
{
    boost::asio::io_context ioContext;
    BaseJob job(TEST_SERVER_URL, "/.well-known/sdn/client", BaseJob::Get{}, "TestJob");

    CprJobHandler h(ioContext.get_executor());
    h.submit(
        job.withData(json{{"test", "bar"}}),
        [&h](auto r) {
            if (r.statusCode == 200) {
                REQUIRE( isBodyJson(r.body) );

                json j = r.jsonBody().get();

                REQUIRE_NOTHROW( (j["m.node"]["base_url"]) );
                REQUIRE( (j["m.node"]["base_url"].size() > 0) );

                REQUIRE( r.dataStr("test") == "bar" );
            }
            h.stop();
        });
    ioContext.run();
}
