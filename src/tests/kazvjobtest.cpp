/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <vector>
#include <iostream>
#include <filesystem>

#include <catch2/catch_all.hpp>
#include <cprjobhandler.hpp>

#include "tests.hpp"
#include "kazvtest-respath.hpp"
#include "file-guard.hpp"

using namespace Kazv;

TEST_CASE("setTimeout should behave properly", "[kazvjob]")
{
    boost::asio::io_context ioContext;
    CprJobHandler h(ioContext.get_executor());

    std::vector<int> v;

    h.setTimeout(
        [&v, &h] {
            v.push_back(500);
            h.stop();
        }, 500);

    h.setTimeout(
        [&v] {
            v.push_back(100);
        }, 100);

    ioContext.run();

    REQUIRE( v.size() == 2 );
    REQUIRE( v[0] == 100 );
    REQUIRE( v[1] == 500 );
}

TEST_CASE("setInterval should behave properly", "[kazvjob]")
{
    boost::asio::io_context ioContext;
    CprJobHandler h(ioContext.get_executor());

    std::vector<int> v;

    h.setInterval(
        [&v, &h] {
            v.push_back(50);
            std::cout << "timer executed" << std::endl;
            if (v.size() >= 2) {
                h.stop();
            }
        }, 100);

    ioContext.run();

    REQUIRE( v.size() == 2 );
    REQUIRE( v[0] == 50 );
    REQUIRE( v[1] == 50 );
}

TEST_CASE("setInterval can be cancelled", "[kazvjob]")
{
    boost::asio::io_context ioContext;
    CprJobHandler h(ioContext.get_executor());

    std::vector<int> v;

    std::string id{"testTimerId"};

    h.setInterval(
        [&v, &h, id] {
            v.push_back(50);
            std::cout << "timer executed" << std::endl;
            if (v.size() >= 2) {
                h.cancel(id);
            }
        }, 100, id);

    h.setTimeout(
        [&h] {
            h.stop();
        }, 300);

    ioContext.run();

    REQUIRE( v.size() == 2 );
    REQUIRE( v[0] == 50 );
    REQUIRE( v[1] == 50 );
}

static BaseJob succJob =
    BaseJob(TEST_SERVER_URL, "/.well-known/sdn/client", BaseJob::Get{}, "TestJob")
    .withQueue("testjob");

static BaseJob failJob =
    BaseJob(TEST_SERVER_URL, "/.well-known/jfasjewfn/awejioaewjgjaad/fawre", BaseJob::Get{}, "AnotherTestJob")
    .withQueue("testjob");

static BaseJob failJobWithCancel =
    failJob.withQueue("testjob", CancelFutureIfFailed);

TEST_CASE("Job queue should behave properly", "[kazvjob]")
{
    std::vector<bool> v;

    std::function<void(Response)> callback =
        [&v](Response r) {
            std::cout << "callback called" << std::endl;
            v.push_back(r.success());
        };

    boost::asio::io_context ioContext;
    CprJobHandler h(ioContext.get_executor());

    h.submit(succJob, callback); // true
    h.submit(failJob, callback); // false
    h.submit(failJobWithCancel, callback); // false
    h.submit(succJob, callback); // false (because this is cancelled)
    h.submit(succJob, [&h](Response) {
                          h.stop();
                      }); // nothing added

    ioContext.run();

    REQUIRE( v.size() == 4 );
    REQUIRE( v[0] == true );
    REQUIRE( v[1] == false );
    REQUIRE( v[2] == false );
    REQUIRE( v[3] == false );
}

static const std::string httpbinServer = "http://www.httpbin.org";
static const std::string httpbinEndpoint = "/post";

TEST_CASE("Stream uploads should work properly", "[kazvjob]")
{
    auto filename = std::filesystem::path(resPath) / "kazvjob-test-res1";
    auto desc = FileDesc(filename.native(), "text/plain");
    BaseJob job(httpbinServer,
                httpbinEndpoint,
                BaseJob::POST,
                "TestJob",
                std::string{}, // token
                BaseJob::ReturnType::Json,
                desc);

    boost::asio::io_context ioContext;
    CprJobHandler h(ioContext.get_executor());

    h.submit(job, [&h](Response r) {
                      REQUIRE(isBodyJson(r.body));
                      auto body = r.jsonBody();
                      std::cout << "Ret= " << body.get().dump() << std::endl;
                      REQUIRE(body.get().at("data").template get<std::string>() == "foobar");
                      REQUIRE(body.get().at("headers").at("Content-Type").template get<std::string>() == "text/plain");
                      h.stop();
                  });

    ioContext.run();
}

TEST_CASE("Streaming binary data should be ok", "[kazvjob]")
{
    auto filename = std::filesystem::path(resPath) / "kazvjob-test-res2";
    auto desc = FileDesc(filename.native(), "application/octet-stream");
    BaseJob job(httpbinServer,
                httpbinEndpoint,
                BaseJob::POST,
                "TestJob",
                std::string{}, // token
                BaseJob::ReturnType::Json,
                desc);

    boost::asio::io_context ioContext;
    CprJobHandler h(ioContext.get_executor());

    h.submit(job, [&h](Response r) {
                      REQUIRE(isBodyJson(r.body));
                      auto body = r.jsonBody();
                      std::cout << "Ret= " << body.get().dump() << std::endl;
                      REQUIRE(body.get().at("data").template get<std::string>() == "\n\r\n\0\t\n"s);
                      REQUIRE(body.get().at("headers").at("Content-Type").template get<std::string>() == "application/octet-stream");
                      h.stop();
                  });

    ioContext.run();
}

TEST_CASE("Stream downloads should work properly", "[kazvjob]")
{
    auto filename = std::filesystem::path(resPath) / "kazvjob-test-tmp1";
    auto desc = FileDesc(filename.native());

    auto guard = FileGuard{filename};

    BaseJob job(httpbinServer,
                httpbinEndpoint,
                BaseJob::POST,
                "TestJob",
                std::string{}, // token
                BaseJob::ReturnType::File,
                "foobar"s,
                {}, // query
                Header(Header::value_type{{"Content-Type", "text/plain"}}), // header
                desc);

    boost::asio::io_context ioContext;
    CprJobHandler h(ioContext.get_executor());

    h.submit(job, [&h, filename](Response r) {
                      REQUIRE(std::holds_alternative<FileDesc>(r.body));
                      auto body = std::get<FileDesc>(r.body);

                      REQUIRE(body.name().has_value());
                      REQUIRE(body.name().value() == filename);

                      auto fh = DumbFileInterface{};

                      auto stream = body.provider(fh).getStream();

                      stream.read(1024, [](auto retCode, auto data) {
                                            REQUIRE(retCode == FileOpRetCode::Success);
                                            auto j = json::parse(data.begin(), data.end());

                                            std::cout << j.dump() << std::endl;

                                            REQUIRE(j.at("data") == "foobar");
                                            REQUIRE(j.at("headers").at("Content-Type") == "text/plain");
                                        });
                      h.stop();
                  });

    ioContext.run();
}
