/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <boost/serialization/string.hpp>
#include <boost/serialization/split_member.hpp>

#include <types.hpp>
#include <copy-helper.hpp>

namespace Kazv
{
    class EncryptedFileDesc
    {
    public:
        /**
         * Constructs an empty EncryptedFileDesc.
         *
         * The mxcUri, key, iv, and sha256Hash are guaranteed to be empty.
         */
        EncryptedFileDesc();

        /**
         * Constructs an EncryptedFileDesc from mxcUri, key, iv and sha256Hash.
         *
         * @param mxcUri The mxc uri to the file.
         * @param key The key encoded as urlsafe unpadded base64.
         * @param iv The iv encoded as unpadded base64.
         * @param sha256Hash The SHA256 hash encoded as unpadded base64.
         */
        EncryptedFileDesc(std::string mxcUri, std::string key, std::string iv, std::string sha256Hash);

        KAZV_DECLARE_COPYABLE(EncryptedFileDesc)

        ~EncryptedFileDesc();

        /**
         * Constructs an EncryptedFileDesc from an EncryptedFile json object.
         *
         * @return An EncryptedFileDesc object representing the EncryptedFile object,
         * if `encryptedFile` is valid; a default-constructed EncryptedFileDesc otherwise.
         */
        static EncryptedFileDesc fromJson(JsonWrap encryptedFile);

        /**
         * Convert the encrypted file metadata to an EncryptedFile json object.
         *
         * @return An EncryptedFile json object representing this.
         */
        JsonWrap toJson() const;

        /// @return The mxc uri for this file.
        std::string mxcUri() const;
        /// @return The key encoded as urlsafe unpadded base64.
        std::string key() const;
        /// @return The iv encoded as unpadded base64.
        std::string iv() const;
        /// @return The SHA256 hash encoded as unpadded base64.
        std::string sha256Hash() const;

        /**
         * @return Whether all of mxcUri, key, iv, and sha256Hash of this
         * and that are equal.
         */
        bool operator==(const EncryptedFileDesc &that) const;

        template<class Archive>
        void save(Archive &ar, const unsigned int /* version */) const {
            ar << mxcUri()
               << key()
               << iv()
               << sha256Hash();
        }

        template<class Archive>
        void load(Archive &ar, const unsigned int /* version */) {
            std::string mxcUri;
            std::string key;
            std::string iv;
            std::string sha256Hash;
            ar >> mxcUri
               >> key
               >> iv
               >> sha256Hash;

            *this = EncryptedFileDesc(mxcUri, key, iv, sha256Hash);
        }

        BOOST_SERIALIZATION_SPLIT_MEMBER()

    private:
        struct Private;
        std::unique_ptr<Private> m_d;
    };
}
