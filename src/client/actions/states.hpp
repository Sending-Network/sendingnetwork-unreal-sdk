/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <csapi/rooms.hpp>
#include <csapi/room_state.hpp>

#include "client-model.hpp"

namespace Kazv
{
    BaseJob clientPerform(ClientModel m, GetRoomStatesAction a);
    ClientResult updateClient(ClientModel m, GetRoomStatesAction a);
    ClientResult processResponse(ClientModel m, GetRoomStateResponse r);
    ClientResult updateClient(ClientModel m, GetStateEventAction a);
    ClientResult processResponse(ClientModel m, GetRoomStateWithKeyResponse r);
    ClientResult updateClient(ClientModel m, SendStateEventAction a);
    ClientResult processResponse(ClientModel m, SetRoomStateWithKeyResponse r);
}
