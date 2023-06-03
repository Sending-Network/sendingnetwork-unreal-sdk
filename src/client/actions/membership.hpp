/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include "client-model.hpp"
#include <csapi/create_room.hpp>
#include <csapi/inviting.hpp>
#include <csapi/joining.hpp>
#include <csapi/leaving.hpp>
#include <csapi/kicking.hpp>
#include <csapi/banning.hpp>

namespace Kazv
{
    ClientResult updateClient(ClientModel m, CreateRoomAction a);
    ClientResult processResponse(ClientModel m, CreateRoomResponse r);

    ClientResult updateClient(ClientModel m, InviteToRoomAction a);
    ClientResult processResponse(ClientModel m, InviteUserResponse r);

    ClientResult updateClient(ClientModel m, JoinRoomByIdAction a);
    ClientResult processResponse(ClientModel m, JoinRoomByIdResponse r);

    ClientResult updateClient(ClientModel m, JoinRoomAction a);
    ClientResult processResponse(ClientModel m, JoinRoomResponse r);

    ClientResult updateClient(ClientModel m, LeaveRoomAction a);
    ClientResult processResponse(ClientModel m, LeaveRoomResponse r);

    ClientResult updateClient(ClientModel m, ForgetRoomAction a);
    ClientResult processResponse(ClientModel m, ForgetRoomResponse r);

    ClientResult updateClient(ClientModel m, KickAction a);
    ClientResult processResponse(ClientModel m, KickResponse r);

    ClientResult updateClient(ClientModel m, BanAction a);
    ClientResult processResponse(ClientModel m, BanResponse r);

    ClientResult updateClient(ClientModel m, UnbanAction a);
    ClientResult processResponse(ClientModel m, UnbanResponse r);
}
