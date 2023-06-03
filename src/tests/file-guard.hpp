/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <filesystem>

struct FileGuard
{
    inline ~FileGuard() {
        std::filesystem::remove(m_filename);
    }
    std::filesystem::path m_filename;
};
