/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <libkazv-config.hpp>

#include <memory>

#include <lager/deps.hpp>
#include <lager/reader.hpp>

namespace Kazv
{
    struct SdkModel;

    struct SdkModelCursorTag {};
    using SdkModelCursorKey =
        lager::dep::key<SdkModelCursorTag,
                        lager::dep::fn<std::shared_ptr<lager::reader<SdkModel>>>>;
}
