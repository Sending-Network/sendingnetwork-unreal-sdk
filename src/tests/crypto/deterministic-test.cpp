/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include <catch2/catch_all.hpp>

#include <crypto.hpp>
#include <outbound-group-session.hpp>
#include <random-generator.hpp>

using namespace Kazv;

TEST_CASE("Deterministic constructors of Crypto and OutboundGroupSession", "[crypto][deterministic]")
{
    auto rg = RandomInterface{RandomDeviceGenerator{}};
    auto random = rg.generateRange<RandomData>(Crypto::constructRandomSize());
    Crypto crypto1(RandomTag{}, random);
    Crypto crypto2(RandomTag{}, random);

    REQUIRE(crypto1.toJson() == crypto2.toJson());

    random = rg.generateRange<RandomData>(OutboundGroupSession::constructRandomSize());
    auto creationTime = currentTimeMs();

    OutboundGroupSession ogs1(RandomTag{}, random, creationTime);
    OutboundGroupSession ogs2(RandomTag{}, random, creationTime);

    REQUIRE(nlohmann::json(ogs1) == nlohmann::json(ogs2));
}

TEST_CASE("Deterministic generating of one-time keys", "[crypto][deterministic]")
{
    auto rg = RandomInterface{RandomDeviceGenerator{}};
    auto random = rg.generateRange<RandomData>(Crypto::constructRandomSize());
    Crypto crypto1(RandomTag{}, random);
    Crypto crypto2(crypto1);

    auto numKeysToGen = 2;
    random = rg.generateRange<RandomData>(Crypto::genOneTimeKeysRandomSize(numKeysToGen));
    crypto1.genOneTimeKeysWithRandom(random, numKeysToGen);
    crypto2.genOneTimeKeysWithRandom(random, numKeysToGen);

    REQUIRE(crypto1.toJson() == crypto2.toJson());
}
