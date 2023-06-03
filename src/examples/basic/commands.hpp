/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include <libkazv-config.hpp>

#include <string>

#include <client/client.hpp>
#include <client/sdn.hpp>

void parse(Kazv::SDNHttpRequest s, std::string l, Kazv::Client c);
