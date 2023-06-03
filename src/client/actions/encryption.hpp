/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include "client-model.hpp"

#include "csapi/keys.hpp"

namespace Kazv
{
    ClientResult updateClient(ClientModel m, UploadIdentityKeysAction a);
    ClientResult updateClient(ClientModel m, GenerateAndUploadOneTimeKeysAction a);
    ClientResult processResponse(ClientModel m, UploadKeysResponse r);

    ClientModel tryDecryptEvents(ClientModel m);

    std::optional<BaseJob> clientPerform(ClientModel m, QueryKeysAction a);
    ClientResult updateClient(ClientModel m, QueryKeysAction a);
    ClientResult processResponse(ClientModel m, QueryKeysResponse r);

    ClientResult updateClient(ClientModel m, ClaimKeysAction a);
    ClientResult processResponse(ClientModel m, ClaimKeysResponse r);

    ClientResult updateClient(ClientModel m, EncryptMegOlmEventAction a);

    ClientResult updateClient(ClientModel m, EncryptOlmEventAction a);
}
