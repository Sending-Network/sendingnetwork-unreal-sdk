/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <csapi/profile.hpp>

#include "client-model.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, GetUserProfileAction a);
    ClientResult processResponse(ClientModel m, GetUserProfileResponse r);

    ClientResult updateClient(ClientModel m, SetAvatarUrlAction a);
    ClientResult processResponse(ClientModel m, SetAvatarUrlResponse r);

    ClientResult updateClient(ClientModel m, SetDisplayNameAction a);
    ClientResult processResponse(ClientModel m, SetDisplayNameResponse r);
}
