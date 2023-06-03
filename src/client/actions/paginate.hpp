/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <csapi/message_pagination.hpp>

#include "client-model.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, PaginateTimelineAction a);
    ClientResult processResponse(ClientModel m, GetRoomEventsResponse a);
}
