/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <csapi/sync.hpp>
#include <csapi/filter.hpp>

#include "client-model.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, SyncAction a);
    ClientResult processResponse(ClientModel m, SyncResponse r);

    ClientResult updateClient(ClientModel m, SetShouldSyncAction a);

    ClientResult updateClient(ClientModel m, PostInitialFiltersAction a);
    ClientResult processResponse(ClientModel m, DefineFilterResponse r);
}
