/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

namespace Kazv
{
    namespace Base64Opts
    {
        /**
         * Bit flags for encodeBase64 and decodeBase64
         */
        enum Base64Opts : int
        {
            none = 0x0, /// The default, not url-safe, unpadded
            urlSafe = 0x1, /// Url-safe
            padded = 0x2, /// Add padding
        };
    }
    /**
     * Encodes the original string to base64.
     *
     * @param original The original string to encode.
     * @param flags Options for the encoder. See Base64Opts.
     */
    std::string encodeBase64(std::string original, int flags = Base64Opts::none);

    /**
     * Decode base64 string.
     *
     * @param encoded The base64-encoded string.
     * @param flags Options for the decoder. See Base64Opts.
     */
    std::string decodeBase64(std::string encoded, int flags = Base64Opts::none);
}
