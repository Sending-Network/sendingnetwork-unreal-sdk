/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <memory>


#include <copy-helper.hpp>

#include "crypto-util.hpp"


namespace Kazv
{
    namespace
    {
        using std::begin;
        using std::end;
    }

    class AES256CTRDesc
    {
    public:
        /// The optimal block size for this cipher.
        inline static const int optimalBlockSize{16};
        /// The key size for this cipher.
        inline static const int keySize{32};
        /// The iv size for this cipher.
        inline static const int ivSize{16}; // AES block size
        /// Random size to generate a new cipher, provided in fromRandom().
        inline static const int randomSize{keySize + ivSize};
        using DataT = std::string;

    private:
        struct RawTag {};

        /**
         * Constructs an AES-256-CTR cipher using `key` and `iv`.
         *
         * `key` and `iv` are provided as-is.
         *
         * `key` must be of size `keySize` and `iv` must be of size `ivSize`.
         * Otherwise, the constructed cipher is invalid.
         */
        AES256CTRDesc(RawTag, DataT key, DataT iv);

    public:
        /**
         * Constructs an AES-256-CTR cipher using `key` and `iv`.
         *
         * `key` is provided as urlsafe unpadded base64.
         * `iv` is provided as unpadded base64.
         *
         * One must check with `valid()` before actual processing with
         * the object if the key and iv comes from a remote SDN event.
         */
        AES256CTRDesc(std::string key, std::string iv);

        /**
         * Generate a new AES-256-CTR cipher from random data.
         *
         * @param random The random data provided as-is. `random.size()`
         * must be at least `randomSize`.
         *
         * The first keySize bytes will be used as the key, and the
         * next ivSize bytes will be used as the iv.
         *
         * @return An AES-256-CTR cipher generated with the random data.
         */
        template<class RangeT>
        static AES256CTRDesc fromRandom(RangeT random) {
            if (random.size() < randomSize) {
                // Not enough random, return an invalid one
                return AES256CTRDesc(RawTag{}, DataT(), DataT());
            }
            return AES256CTRDesc(RawTag{},
                                 DataT(random.begin(), random.begin() + keySize),
                                 DataT(random.begin() + keySize, random.begin() + keySize + ivSize));
        }

        KAZV_DECLARE_COPYABLE(AES256CTRDesc)

        ~AES256CTRDesc();

        /**
         * @return whether this cipher is valid. If the cipher is invalid, you
         * must not use any method except destructor or operator=().
         */
        bool valid() const;

        /// @return The key encoded as urlsafe unpadded base64.
        std::string key() const;

        /// @return The iv encoded as unpadded base64.
        std::string iv() const;

        template<class RangeT>
        using ResultBase = std::pair<AES256CTRDesc, RangeT>;

        using Result = ResultBase<DataT>;

        /**
         * Encrypts or decrypts `data` and derives the next cipher state.
         *
         * @param data The data to encrypt or decrypt.
         *
         * Example:
         *
         *     auto cipher = Kazv::AES256CTRDesc(
         *         Kazv::genRandom(Kazv::AES256CTRDesc::keySize),
         *         Kazv::genRandom(Kazv::AES256CTRDesc::ivSize)
         *     );
         *     std::string original = "Some test here";
         *     auto [next, encrypted] = cipher.process(original);
         *     auto [next2, encrypted2] = cipher.process(original);
         *     REQUIRE(encrypted == encrypted2);
         *
         * @return an object that can be destructured into the next cipher state
         * (as AES256CTRDesc) and the encrypted or decrypted data (as DataT).
         */
        Result process(DataT data) const &;
        /**
         * Encrypts or decrypts `data` and derives the next cipher state.
         *
         * This function only differs from the above in that it takes any range type
         * and the second component of returned object is of the same type as the argument.
         */
        template<class RangeT,
                 class = std::enable_if_t<!std::is_same_v<std::decay_t<RangeT>, DataT>, int>>
        ResultBase<std::decay_t<RangeT>> process(RangeT data) const & {
            using ActualRangeT = std::decay_t<RangeT>;
            auto [next, res] = process(DataT(begin(data), end(data)));
            return { next, ActualRangeT(res.begin(), res.end()) };
        }

        /**
         * Encrypts or decrypts `data` and derives the next cipher state.
         *
         * This function differs from the above two only in that its calling object
         * is an rvalue reference (a.k.a casted using std::move()).
         */
        Result process(DataT data) &&;
        /**
         * Encrypts or decrypts `data` and derives the next cipher state.
         *
         * This function differs from the above only in that it takes any range type
         * and the second component of returned object is of the same type as the argument.
         */
        template<class RangeT,
                 class = std::enable_if_t<!std::is_same_v<std::decay_t<RangeT>, DataT>, int>>
        ResultBase<std::decay_t<RangeT>> process(RangeT data) && {
            using ActualRangeT = std::decay_t<RangeT>;
            auto [next, res] = std::move(*this).process(DataT(begin(data), end(data)));
            return { next, ActualRangeT(res.begin(), res.end()) };
        }

        /**
         * Encrypt or decrypt `data` and modify the state of the cipher in-place.
         *
         * @param data The data to encrypt or decrypt.
         */
        DataT processInPlace(DataT data);
        /**
         * Encrypt or decrypt `data` and modify the state of the cipher in-place.
         *
         * This function differs from the above only in that it takes any range type
         * and returns the processed data as the same range type.
         */
        template<class RangeT,
                 class = std::enable_if_t<!std::is_same_v<std::decay_t<RangeT>, DataT>, int>>
        std::decay_t<RangeT> processInPlace(RangeT data) {
            using ActualRangeT = std::decay_t<RangeT>;
            auto res = processInPlace(DataT(begin(data), end(data)));
            return ActualRangeT(res.begin(), res.end());
        }

    private:
        struct Private;

        std::unique_ptr<Private> m_d;
    };
}
