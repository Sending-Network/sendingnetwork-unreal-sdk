/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <cryptopp/base64.h>

#include "base64.hpp"

namespace Kazv
{
    std::string encodeBase64(std::string original, int flags)
    {
        using CryptoPP::Name::Pad;
        using CryptoPP::Name::InsertLineBreaks;

        std::unique_ptr<CryptoPP::BufferedTransformation> tf;

        if (flags & Base64Opts::urlSafe) {
            auto encoder = std::make_unique<CryptoPP::Base64URLEncoder>();
            if (! (flags & Base64Opts::padded)) {
                auto params = CryptoPP::MakeParameters(Pad(), false)(InsertLineBreaks(), false);
                encoder->IsolatedInitialize(params);
            }
            tf = std::move(encoder);
        } else {
            auto encoder = std::make_unique<CryptoPP::Base64Encoder>();
            if (! (flags & Base64Opts::padded)) {
                auto params = CryptoPP::MakeParameters(Pad(), false)(InsertLineBreaks(), false);
                encoder->IsolatedInitialize(params);
            }
            tf = std::move(encoder);
        }
        std::string res;

        tf->Attach(new CryptoPP::StringSink(res));

        {
            CryptoPP::StringSource ss(original, /* pumpAll = */ true, tf.release());
        }

        return res;
    }

    std::string decodeBase64(std::string encoded, int flags)
    {
        using CryptoPP::Name::Pad;
        using CryptoPP::Name::InsertLineBreaks;

        std::unique_ptr<CryptoPP::BufferedTransformation> tf;

        if (flags & Base64Opts::urlSafe) {
            tf = std::make_unique<CryptoPP::Base64URLDecoder>();
        } else {
            tf = std::make_unique<CryptoPP::Base64Decoder>();
        }
        std::string res;

        tf->Attach(new CryptoPP::StringSink(res));

        {
            CryptoPP::StringSource ss(encoded, /* pumpAll = */ true, tf.release());
        }

        return res;
    }
}
