/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2022 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <csapi/login.hpp>
#include <csapi/wellknown.hpp>
#include <csapi/versions.hpp>

#include "client-model.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, LoginAction a);
    ClientResult updateClient(ClientModel m, TokenLoginAction a);
    ClientResult processResponse(ClientModel m, LoginResponse r);
    ClientResult updateClient(ClientModel m, LogoutAction a);

    ClientResult updateClient(ClientModel m, GetWellknownAction a);
    ClientResult processResponse(ClientModel m, GetWellknownResponse r);

    ClientResult updateClient(ClientModel m, GetVersionsAction a);
    ClientResult processResponse(ClientModel m, GetVersionsResponse r);
}
