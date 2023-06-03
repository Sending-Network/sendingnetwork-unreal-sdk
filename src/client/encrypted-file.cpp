/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "encrypted-file.hpp"

namespace Kazv
{
    struct EncryptedFileDesc::Private
    {
        std::string mxcUri;
        std::string key;
        std::string iv;
        std::string sha256Hash;
    };

    EncryptedFileDesc::EncryptedFileDesc()
        : m_d(std::make_unique<Private>())
    {
    }

    EncryptedFileDesc::EncryptedFileDesc(std::string mxcUri, std::string key, std::string iv, std::string sha256Hash)
        : m_d(std::make_unique<Private>(Private{mxcUri, key, iv, sha256Hash}))
    {
    }

    KAZV_DEFINE_COPYABLE_UNIQUE_PTR(EncryptedFileDesc, m_d)

    EncryptedFileDesc::~EncryptedFileDesc() = default;

    EncryptedFileDesc EncryptedFileDesc::fromJson(JsonWrap encryptedFile)
    {
        try {
            // First, verify EncryptedFile object
            auto jwk = encryptedFile.get().at("key");
            auto keyOps = jwk.at("key_ops");
            if (! (encryptedFile.get().at("v").template get<std::string>() == "v2"
                   && jwk.at("kty").template get<std::string>() == "oct"
                   && jwk.at("alg").template get<std::string>() == "A256CTR"
                   && jwk.at("ext").template get<bool>() == true
                   && std::find(keyOps.cbegin(), keyOps.cend(), "encrypt") != keyOps.cend()
                   && std::find(keyOps.cbegin(), keyOps.cend(), "decrypt") != keyOps.cend())) {
                // invalid EncryptedFile object
                return EncryptedFileDesc();
            }

            auto mxcUri = encryptedFile.get().at("url").template get<std::string>();
            auto key = encryptedFile.get().at("key").at("k").template get<std::string>();
            auto iv = encryptedFile.get().at("iv").template get<std::string>();
            auto sha256Hash = encryptedFile.get().at("hashes").at("sha256").template get<std::string>();

            return EncryptedFileDesc(mxcUri, key, iv, sha256Hash);
        } catch (const std::exception &) {
            return EncryptedFileDesc();
        }
    }

    JsonWrap EncryptedFileDesc::toJson() const
    {
        return json::object({
                {"url", mxcUri()},
                {"key", json::object({
                            {"kty", "oct"},
                            {"key_ops", json::array({"encrypt", "decrypt"})},
                            {"alg", "A256CTR"},
                            {"k", key()},
                            {"ext", true},
                        })},
                {"iv", iv()},
                {"hashes", json::object({
                            {"sha256", sha256Hash()}
                        })},
                {"v", "v2"},
            });
    }

    std::string EncryptedFileDesc::mxcUri() const
    {
        if (! m_d) { return ""; }
        return m_d->mxcUri;
    }

    std::string EncryptedFileDesc::key() const
    {
        if (! m_d) { return ""; }
        return m_d->key;
    }

    std::string EncryptedFileDesc::iv() const
    {
        if (! m_d) { return ""; }
        return m_d->iv;
    }

    std::string EncryptedFileDesc::sha256Hash() const
    {
        if (! m_d) { return ""; }
        return m_d->sha256Hash;
    }

    bool EncryptedFileDesc::operator==(const EncryptedFileDesc &that) const
    {
        return (m_d == that.m_d
                || (mxcUri() == that.mxcUri()
                    && key() == that.key()
                    && iv() == that.iv()
                    && sha256Hash() == that.sha256Hash()));
    }
}
