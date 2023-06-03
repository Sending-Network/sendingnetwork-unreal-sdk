/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include <catch2/catch_all.hpp>

#include <string>
#include <vector>

#include <random-generator.hpp>

using namespace Kazv;

TEST_CASE("RandomInterface with a const generator", "[client][random]")
{
    auto generator = [] { return 1; };
    auto iface = RandomInterface{generator};

    REQUIRE(iface() == 1);

    auto range = iface.generateRange<std::vector<unsigned int>>(5);
    REQUIRE(range == std::vector<unsigned int>(5, 1));

    auto range2 = iface.fillRange(std::vector<unsigned int>(5));
    REQUIRE(range2 == std::vector<unsigned int>(5, 1));
}

TEST_CASE("RandomInterface with a non-const generator", "[client][random]")
{
    unsigned int cur = 0;
    auto generator = [cur]() mutable { ++cur; return cur; };
    auto iface = RandomInterface{generator};

    REQUIRE(iface() == 1);

    auto range = iface.generateRange<std::vector<unsigned int>>(5);
    REQUIRE(range == std::vector<unsigned int>{2, 3, 4, 5, 6});

    auto range2 = iface.fillRange(std::vector<unsigned int>(5));
    REQUIRE(range2 == std::vector<unsigned int>{7, 8, 9, 10, 11});
}

TEST_CASE("RandomInterface generating ranges with element type narrower than unsigned int", "[client][random]")
{
    auto ucharMax = static_cast<unsigned int>(static_cast<unsigned char>(-1));
    auto generator = [=] { return (ucharMax + 1) + 1; };
    auto iface = RandomInterface{generator};

    auto range = iface.generateRange<std::string>(5);
    REQUIRE(range == std::string(5, 1));
}

namespace
{
    struct NonCopyableCallable
    {
        NonCopyableCallable() {}
        NonCopyableCallable(const NonCopyableCallable &that) = delete;
        NonCopyableCallable(NonCopyableCallable &&that) = default;
        NonCopyableCallable &operator=(const NonCopyableCallable &that) = delete;
        NonCopyableCallable &operator=(NonCopyableCallable &&that) = default;

        unsigned int operator()() { return 1; }
    };
}

TEST_CASE("RandomInterface should work with non-copyable types", "[client][random]")
{
    auto iface = RandomInterface{NonCopyableCallable()};

    REQUIRE(iface() == 1);

    auto range = iface.generateRange<std::vector<unsigned int>>(5);
    REQUIRE(range == std::vector<unsigned int>(5, 1));

    auto range2 = iface.fillRange(std::vector<unsigned int>(5));
    REQUIRE(range2 == std::vector<unsigned int>(5, 1));
}

TEST_CASE("RandomDeviceGenerator should be movable", "[client][random]")
{
    auto rdg = RandomDeviceGenerator{};
    auto rdg2 = std::move(rdg);
}
