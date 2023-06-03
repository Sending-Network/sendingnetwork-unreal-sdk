/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <csapi/room_send.hpp>
#include <csapi/to_device.hpp>

#include "client-model.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, SendMessageAction a);
    ClientResult processResponse(ClientModel m, SendMessageResponse r);

    ClientResult updateClient(ClientModel m, SendToDeviceMessageAction a);
    ClientResult processResponse(ClientModel m, SendToDeviceResponse r);
}
