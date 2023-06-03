/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <csapi/typing.hpp>
#include <csapi/receipts.hpp>
#include <csapi/read_markers.hpp>

#include "client-model.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, SetTypingAction a);
    ClientResult processResponse(ClientModel m, SetTypingResponse r);
    ClientResult updateClient(ClientModel m, PostReceiptAction a);
    ClientResult processResponse(ClientModel m, PostReceiptResponse r);
    ClientResult updateClient(ClientModel m, SetReadMarkerAction a);
    ClientResult processResponse(ClientModel m, SetReadMarkerResponse r);
}
