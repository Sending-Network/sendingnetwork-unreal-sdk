/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include <catch2/catch_all.hpp>

#include <boost/asio.hpp>

#include <asio-promise-handler.hpp>
#include <cursorutil.hpp>
#include <sdk-model.hpp>
#include <client/client.hpp>

#include "client-test-util.hpp"

// The example response
static json uploadContentResponseJson = R"({
  "content_uri": "mxc://example.com/AQwafuaFswefuhsfAFAgsw"
})"_json;

TEST_CASE("Upload content should give the mxc uri", "[client][content]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    auto resp = createResponse("UploadContent", uploadContentResponseJson, json{{"uploadId", "whatever"}});

    store.dispatch(ProcessResponseAction{resp})
        .then([](auto stat) {
                  REQUIRE(stat.success());
                  auto mxcUri = stat.dataStr("mxcUri");
                  REQUIRE(mxcUri == std::string("mxc://example.com/AQwafuaFswefuhsfAFAgsw"));
              });

    io.run();
}

TEST_CASE("Download content without streaming should give out data", "[client][content]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    auto resp = createResponse("GetContent", Bytes("foobar"),
                               json{{"mxcUri", "mxc://example.org/whatever"}, {"streaming", false}});
    resp.header = Header::value_type({{"Content-Type", "text/plain"}});

    store.dispatch(ProcessResponseAction{resp})
        .then([](auto stat) {
                  REQUIRE(stat.success());
                  auto data = stat.dataStr("content");
                  REQUIRE(data == std::string("foobar"));
              });

    io.run();
}

TEST_CASE("Download content with streaming should not give out data", "[client][content]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    auto resp = createResponse("GetContent", FileDesc{"examplefile"},
                               json{{"mxcUri", "mxc://example.org/whatever"}, {"streaming", true}});
    resp.header = Header::value_type({{"Content-Type", "text/plain"}});

    store.dispatch(ProcessResponseAction{resp})
        .then([](auto stat) {
                  REQUIRE(stat.success());
                  REQUIRE(! stat.data().get().contains("content"));
              });

    io.run();
}

TEST_CASE("A response for download content without content type should fail without exception", "[client][content]")
{
    using namespace Kazv::CursorOp;

    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};

    auto store = createTestClientStore(ph);

    auto resp = createResponse("GetContent", FileDesc{"examplefile"},
                               json{{"mxcUri", "mxc://example.org/whatever"}, {"streaming", true}});

    store.dispatch(ProcessResponseAction{resp})
        .then([](auto stat) {
                  REQUIRE(!stat.success());
              });

    io.run();
}
