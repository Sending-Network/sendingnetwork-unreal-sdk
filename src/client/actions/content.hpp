/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include <libkazv-config.hpp>

#include "client-model.hpp"

#include "csapi/content-repo.hpp"

namespace Kazv
{
    std::pair<std::string, std::string> mxcUriToMediaDesc(std::string mxcUri);

    ClientResult updateClient(ClientModel m, UploadContentAction a);
    ClientResult processResponse(ClientModel m, UploadContentResponse r);

    ClientResult updateClient(ClientModel m, DownloadContentAction a);
    ClientResult processResponse(ClientModel m, GetContentResponse r);

    ClientResult updateClient(ClientModel m, DownloadThumbnailAction a);
    ClientResult processResponse(ClientModel m, GetContentThumbnailResponse r);
}
