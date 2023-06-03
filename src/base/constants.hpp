/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#include <string>

namespace Kazv
{
    using namespace std::string_literals;
    const std::string CLIENT_MAJOR_VERSION = "r0"s;
    const std::string BASE_PATH = "/_api/client/"s + CLIENT_MAJOR_VERSION;
}
