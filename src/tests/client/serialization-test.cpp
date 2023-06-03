/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <catch2/catch_all.hpp>
#include <boost/asio.hpp>

#include <sstream>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>

#include <sdk-model.hpp>
#include <client.hpp>

#include <asio-promise-handler.hpp>

#include "client-test-util.hpp"

using namespace Kazv;
using IAr = boost::archive::text_iarchive;
using OAr = boost::archive::text_oarchive;

TEST_CASE("Serialize SdkModel", "[client][serialization]")
{
    SdkModel m1;
    SdkModel m2;

    std::stringstream stream;

    {
        auto ar = OAr(stream);
        ar << m1;
    }

    {
        auto ar = IAr(stream);
        ar >> m2;
    }

}

TEST_CASE("Serialize from Client to archive", "[client][serialization]")
{
    boost::asio::io_context io;
    AsioPromiseHandler ph{io.get_executor()};
    auto store = createTestClientStore(ph);

    auto c = Client(store.reader().map([](auto c) { return SdkModel{c}; }), store,
                    std::nullopt);

    std::stringstream stream;

    {
        auto ar = OAr(stream);
        c.serializeTo(ar);
    }
}
