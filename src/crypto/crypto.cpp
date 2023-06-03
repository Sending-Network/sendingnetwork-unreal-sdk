/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <vector>

#include <zug/transducer/filter.hpp>

#include <olm/olm.h>

#include <nlohmann/json.hpp>

#include <debug.hpp>
#include <event.hpp>
#include <cursorutil.hpp>
#include <types.hpp>

#include "crypto-p.hpp"
#include "session-p.hpp"

#include "crypto-util.hpp"
#include "time-util.hpp"

namespace Kazv
{
    using namespace CryptoConstants;

    CryptoPrivate::CryptoPrivate()
        : accountData(olm_account_size(), 0)
        , account(olm_account(accountData.data()))
        , utilityData(olm_utility_size(), '\0')
        , utility(olm_utility(utilityData.data()))
        , valid(false)
    {
    }

    CryptoPrivate::CryptoPrivate(RandomTag, RandomData data)
        : accountData(olm_account_size(), 0)
        , account(olm_account(accountData.data()))
        , utilityData(olm_utility_size(), '\0')
        , utility(olm_utility(utilityData.data()))
    {
        auto randLenNeeded = Crypto::constructRandomSize();
        checkError(olm_create_account(account, data.data(), randLenNeeded));
    }


    CryptoPrivate::~CryptoPrivate()
    {
        olm_clear_account(account);
    }

    CryptoPrivate::CryptoPrivate(const CryptoPrivate &that)
        : accountData(olm_account_size(), 0)
        , account(olm_account(accountData.data()))
        , uploadedOneTimeKeysCount(that.uploadedOneTimeKeysCount)
        , numUnpublishedKeys(that.numUnpublishedKeys)
        , knownSessions(that.knownSessions)
        , inboundGroupSessions(that.inboundGroupSessions)
        , outboundGroupSessions(that.outboundGroupSessions)
        , utilityData(olm_utility_size(), '\0')
        , utility(olm_utility(utilityData.data()))
    {
        unpickle(that.pickle());
    }

    std::string CryptoPrivate::pickle() const
    {
        auto key = ByteArray(3, 'x');
        auto pickleData = std::string(olm_pickle_account_length(account), '\0');
        checkError(olm_pickle_account(account, key.data(), key.size(),
                                      pickleData.data(), pickleData.size()));
        return pickleData;
    }

    void CryptoPrivate::unpickle(std::string pickleData)
    {
        auto key = ByteArray(3, 'x');
        checkError(olm_unpickle_account(account, key.data(), key.size(),
                                        pickleData.data(), pickleData.size()));
    }

    std::size_t CryptoPrivate::checkError(std::size_t code) const
    {
        if (code == olm_error()) {
            kzo.crypto.warn() << "Olm error: " << olm_account_last_error(account) << std::endl;
        }
        return code;
    }

    std::size_t CryptoPrivate::checkUtilError(std::size_t code) const
    {
        if (code == olm_error()) {
            kzo.crypto.warn() << "Olm utility error: " << olm_utility_last_error(utility) << std::endl;
        }
        return code;
    }


    MaybeString CryptoPrivate::decryptOlm(nlohmann::json content)
    {
        auto theirCurve25519IdentityKey = content.at("sender_key").get<std::string>();

        auto ourCurve25519IdentityKey = curve25519IdentityKey();

        if (! content.at("ciphertext").contains(ourCurve25519IdentityKey)) {
            return NotBut("Message not intended for us");
        }

        auto type = content.at("ciphertext").at(ourCurve25519IdentityKey).at("type").get<int>();
        auto body = content.at("ciphertext").at(ourCurve25519IdentityKey).at("body").get<std::string>();

        auto hasKnownSession = knownSessions.find(theirCurve25519IdentityKey) != knownSessions.end();

        if (type == 0) { // pre-key message
            bool shouldCreateNewSession =
                // there is no possible session
                (! hasKnownSession)
                // the possible session does not match this message
                || (! knownSessions.at(theirCurve25519IdentityKey).matches(body));

            if (shouldCreateNewSession) {
                auto created = createInboundSession(theirCurve25519IdentityKey, body);
                if (! created) { // cannot create session, thus cannot decrypt
                    return NotBut("Cannot create session");
                }
            }

            auto &session = knownSessions.at(theirCurve25519IdentityKey);

            return session.decrypt(type, body);
        } else {
            if (! hasKnownSession) {
                return NotBut("No available session");
            }

            auto &session = knownSessions.at(theirCurve25519IdentityKey);
            return session.decrypt(type, body);
        }
    }

    MaybeString CryptoPrivate::decryptMegOlm(nlohmann::json eventJson)
    {
        auto content = eventJson.at("content");

        auto senderKey = content.at("sender_key").get<std::string>();
        auto sessionId = content.at("session_id").get<std::string>();
        auto roomId = eventJson.at("room_id").get<std::string>();

        auto k = KeyOfGroupSession{roomId, senderKey, sessionId};

        if (inboundGroupSessions.find(k) == inboundGroupSessions.end()) {
            return NotBut("We do not have the keys for this");
        } else {
            auto msg = content.at("ciphertext").get<std::string>();
            auto eventId = eventJson.at("event_id").get<std::string>();
            auto originServerTs = eventJson.at("origin_server_ts").get<Timestamp>();
            auto &session = inboundGroupSessions.at(k);

            return session.decrypt(msg, eventId, originServerTs);
        }
    }

    bool CryptoPrivate::createInboundSession(std::string theirCurve25519IdentityKey,
                                             std::string message)
    {
        auto s = Session(InboundSessionTag{}, account,
                         theirCurve25519IdentityKey, message);

        if (s.valid()) {
            checkError(olm_remove_one_time_keys(account, s.m_d->session));
            knownSessions.insert_or_assign(theirCurve25519IdentityKey, std::move(s));
            return true;
        }

        return false;
    }

    bool CryptoPrivate::reuseOrCreateOutboundGroupSession(
        RandomData random, Timestamp timeMs,
        std::string roomId, std::optional<MegOlmSessionRotateDesc> desc)
    {
        bool valid = true;
        if (! desc.has_value()) { // force rotate
            valid = false;
        } else {
            auto it = outboundGroupSessions.find(roomId);
            if (it == outboundGroupSessions.end()) {
                valid = false;
            } else {
                auto &session = it->second;
                if (timeMs - session.creationTimeMs() >= desc.value().ms) {
                    valid = false;
                } else if (session.messageIndex() >= desc.value().messages) {
                    valid = false;
                }
            }
        }

        if (! valid) {
            outboundGroupSessions.insert_or_assign(roomId, OutboundGroupSession(RandomTag{}, random, timeMs));
            auto &session = outboundGroupSessions.at(roomId);
            auto sessionId = session.sessionId();
            auto sessionKey = session.sessionKey();
            auto senderKey = curve25519IdentityKey();

            auto k = KeyOfGroupSession{roomId, senderKey, sessionId};

            if (! createInboundGroupSession(k, sessionKey, ed25519IdentityKey())) {
                kzo.client.warn() << "Create inbound group session from outbound group session failed. We may not be able to read our own messages." << std::endl;
            }
        }
        return valid;
    }


    std::size_t Crypto::constructRandomSize()
    {
        static std::size_t s =
            [] {
                std::vector<char> acc(olm_account_size(), 0);
                OlmAccount *account = olm_account(acc.data());
                return olm_create_account_random_length(account);
            }();
        return s;
    }

    Crypto::Crypto()
        : m_d(new CryptoPrivate{})
    {
    }

    Crypto::Crypto(RandomTag, RandomData data)
        : m_d(new CryptoPrivate(RandomTag{}, std::move(data)))
    {
    }

    Crypto::~Crypto() = default;

    Crypto::Crypto(const Crypto &that)
        : m_d(new CryptoPrivate(*that.m_d))
    {
    }

    Crypto::Crypto(Crypto &&that)
        : m_d(std::move(that.m_d))
    {
    }

    Crypto &Crypto::operator=(const Crypto &that)
    {
        m_d.reset(new CryptoPrivate(*that.m_d));
        return *this;
    }

    Crypto &Crypto::operator=(Crypto &&that)
    {
        m_d = std::move(that.m_d);
        return *this;
    }

    bool Crypto::valid() const
    {
        return m_d->valid;
    }

    ByteArray CryptoPrivate::identityKeys()
    {
        auto ret = ByteArray(olm_account_identity_keys_length(account), '\0');
        checkError(olm_account_identity_keys(account, ret.data(), ret.size()));
        return ret;
    }

    std::string CryptoPrivate::ed25519IdentityKey()
    {
        auto keys = identityKeys();
        auto keyStr = std::string(keys.begin(), keys.end());
        auto keyJson = nlohmann::json::parse(keyStr);
        return keyJson.at(ed25519);
    }

    std::string CryptoPrivate::curve25519IdentityKey()
    {
        auto keys = identityKeys();
        auto keyStr = std::string(keys.begin(), keys.end());
        auto keyJson = nlohmann::json::parse(keyStr);
        return keyJson.at(curve25519);
    }

    std::string Crypto::ed25519IdentityKey()
    {
        return m_d->ed25519IdentityKey();
    }

    std::string Crypto::curve25519IdentityKey()
    {
        return m_d->curve25519IdentityKey();
    }

    std::string Crypto::sign(nlohmann::json j)
    {
        j.erase("signatures");
        j.erase("unsigned");

        auto str = j.dump();

        auto ret = ByteArray(olm_account_signature_length(m_d->account), '\0');

        kzo.crypto.dbg() << "We are about to sign: " << str << std::endl;

        m_d->checkError(olm_account_sign(m_d->account,
                                         str.data(), str.size(),
                                         ret.data(), ret.size()));

        return std::string{ret.begin(), ret.end()};
    }

    void Crypto::setUploadedOneTimeKeysCount(immer::map<std::string /* algorithm */, int> uploadedOneTimeKeysCount)
    {
        m_d->uploadedOneTimeKeysCount = uploadedOneTimeKeysCount;
    }

    std::size_t Crypto::maxNumberOfOneTimeKeys() const
    {
        return olm_account_max_number_of_one_time_keys(m_d->account);
    }

    std::size_t Crypto::genOneTimeKeysRandomSize(int num)
    {
        static std::size_t oneKeyRandomSize =
            [] {
                std::vector<char> acc(olm_account_size(), 0);
                OlmAccount *account = olm_account(acc.data());
                return olm_account_generate_one_time_keys_random_length(account, 1);
            }();

        return oneKeyRandomSize * num;
    }

    void Crypto::genOneTimeKeysWithRandom(RandomData random, int num)
    {
        assert(random.size() >= genOneTimeKeysRandomSize(num));

        auto res = m_d->checkError(
            olm_account_generate_one_time_keys(
                m_d->account,
                num,
                random.data(), random.size()));

        if (res != olm_error()) {
            m_d->numUnpublishedKeys += num;
        }
    }


    nlohmann::json Crypto::unpublishedOneTimeKeys()
    {
        auto keys = ByteArray(olm_account_one_time_keys_length(m_d->account), '\0');
        m_d->checkError(olm_account_one_time_keys(m_d->account, keys.data(), keys.size()));

        return nlohmann::json::parse(std::string(keys.begin(), keys.end()));
    }

    void Crypto::markOneTimeKeysAsPublished()
    {
        auto ret = m_d->checkError(olm_account_mark_keys_as_published(m_d->account));
        if (ret != olm_error()) {
            m_d->numUnpublishedKeys = 0;
        }
    }

    int Crypto::numUnpublishedOneTimeKeys() const
    {
        return m_d->numUnpublishedKeys;
    }

    int Crypto::uploadedOneTimeKeysCount(std::string algorithm) const
    {
        return m_d->uploadedOneTimeKeysCount[algorithm];
    }

    MaybeString Crypto::decrypt(nlohmann::json eventJson)
    {
        auto content = eventJson.at("content");
        auto algo = content.contains("algorithm") ? content.at("algorithm").template get<std::string>() : std::string();
        if (algo == olmAlgo) {
            return m_d->decryptOlm(std::move(content));
        } else if (algo == megOlmAlgo) {
            return m_d->decryptMegOlm(eventJson);
        }
        return NotBut("Algorithm " + algo + " not supported");
    }

    bool Crypto::createInboundGroupSession(KeyOfGroupSession k, std::string sessionKey, std::string ed25519Key)
    {
        return m_d->createInboundGroupSession(std::move(k), std::move(sessionKey), std::move(ed25519Key));
    }

    bool CryptoPrivate::createInboundGroupSession(KeyOfGroupSession k, std::string sessionKey, std::string ed25519Key)
    {
        auto session = InboundGroupSession(sessionKey, ed25519Key);
        if (session.valid()) {
            inboundGroupSessions.insert_or_assign(k, std::move(session));
            return true;
        }
        return false;
    }

    bool Crypto::verify(nlohmann::json object, std::string userId, std::string deviceId, std::string ed25519Key)
    {
        if (! object.contains("signatures")) {
            return false;
        }
        std::string signature;
        try {
            signature = object.at("signatures").at(userId).at(ed25519 + ":" + deviceId);
        } catch(const std::exception &) {
            return false;
        }
        object.erase("signatures");
        object.erase("unsigned");

        auto message = object.dump();

        auto res = m_d->checkUtilError(
            olm_ed25519_verify(m_d->utility,
                               ed25519Key.c_str(), ed25519Key.size(),
                               message.c_str(), message.size(),
                               signature.data(), signature.size()));

        return res != olm_error();
    }

    MaybeString Crypto::getInboundGroupSessionEd25519KeyFromEvent(const nlohmann::json &eventJson) const
    {
        auto content = eventJson.at("content");

        auto senderKey = content.at("sender_key").get<std::string>();
        auto sessionId = content.at("session_id").get<std::string>();
        auto roomId = eventJson.at("room_id").get<std::string>();

        auto k = KeyOfGroupSession{roomId, senderKey, sessionId};

        if (m_d->inboundGroupSessions.find(k) == m_d->inboundGroupSessions.end()) {
            return NotBut("We do not have the keys for this");
        } else {
            auto &session = m_d->inboundGroupSessions.at(k);
            return session.ed25519Key();
        }
    }

    std::size_t Crypto::encryptOlmRandomSize(std::string /* theirCurve25519IdentityKey */) const
    {
        // HACK: To prevent a possible race condition where we call
        // encryptedOlmRandomSize() -> randomGenerator.generateRange() ~> [encryptOlm()]
        //
        // Here, encryptOlm() must be called in the reducer,
        // as it changes the status of
        // Crypto (so we should not risk any infomation lose in Crypto).
        // Also, for the reducer to be pure, we may not call generateRange() in the reducer,
        // as *that* is not a pure function. This means it can only be called in an effect,
        // or .then() continuation. This means, the sequence from encryptedOlmRandomSize()
        // to encryptOlm() can never be atomic. That is, there may be other encryptOlm()
        // calls within, and that may increase the random data needed, and as a result,
        // we will not have enough random data.
        //
        // The maximum random size needed to encrypt is 32. We use this to ensure we
        // will always have enough random data fot the encryption.
        return encryptOlmMaxRandomSize();
    }

    std::size_t Crypto::encryptOlmMaxRandomSize()
    {
        static std::size_t maxRandomSizeNeeded = 32;
        return maxRandomSizeNeeded;
    }

    nlohmann::json Crypto::encryptOlmWithRandom(
        RandomData random, nlohmann::json eventJson, std::string theirCurve25519IdentityKey)
    {
        assert(random.size() >= encryptOlmRandomSize(theirCurve25519IdentityKey));
        try {
            auto &session = m_d->knownSessions.at(theirCurve25519IdentityKey);
            auto [type, body] = session.encryptWithRandom(random, eventJson.dump());
            return nlohmann::json{
                {
                    theirCurve25519IdentityKey, {
                        {"type", type},
                        {"body", body}
                    }
                }
            };
        } catch (const std::exception &) {
            return nlohmann::json::object();
        }
    }

    nlohmann::json Crypto::encryptMegOlm(nlohmann::json eventJson)
    {
        auto roomId = eventJson.at("room_id").get<std::string>();
        auto content = eventJson.at("content");
        auto type = eventJson.at("type").get<std::string>();

        auto jsonToEncrypt = nlohmann::json::object();
        jsonToEncrypt["room_id"] = roomId;
        jsonToEncrypt["content"] = std::move(content);
        jsonToEncrypt["type"] = type;

        auto textToEncrypt = std::move(jsonToEncrypt).dump();

        auto &session = m_d->outboundGroupSessions.at(roomId);

        auto ciphertext = session.encrypt(std::move(textToEncrypt));

        return
            json{
                {"algorithm", CryptoConstants::megOlmAlgo},
                {"sender_key", curve25519IdentityKey()},
                {"ciphertext", ciphertext},
                {"session_id", session.sessionId()},
            };
    }

    std::size_t Crypto::rotateMegOlmSessionRandomSize()
    {
        return OutboundGroupSession::constructRandomSize();
    }

    std::string Crypto::rotateMegOlmSessionWithRandom(RandomData random, Timestamp timeMs, std::string roomId)
    {
        m_d->reuseOrCreateOutboundGroupSession(
            random, timeMs,
            roomId, std::nullopt);
        return outboundGroupSessionCurrentKey(roomId);
    }

    std::optional<std::string> Crypto::rotateMegOlmSessionWithRandomIfNeeded(
        RandomData random, Timestamp timeMs,
        std::string roomId, MegOlmSessionRotateDesc desc)
    {
        auto oldSessionValid = m_d->reuseOrCreateOutboundGroupSession(random, timeMs, roomId, std::move(desc));
        return oldSessionValid ? std::nullopt : std::optional(outboundGroupSessionCurrentKey(roomId));
    }

    std::string Crypto::outboundGroupSessionInitialKey(std::string roomId)
    {
        auto &session = m_d->outboundGroupSessions.at(roomId);
        return session.initialSessionKey();
    }

    std::string Crypto::outboundGroupSessionCurrentKey(std::string roomId)
    {
        auto &session = m_d->outboundGroupSessions.at(roomId);
        return session.sessionKey();
    }

    auto Crypto::devicesMissingOutboundSessionKey(
        immer::map<std::string, immer::map<std::string /* deviceId */,
        std::string /* curve25519IdentityKey */>> keyMap) const -> UserIdToDeviceIdMap
    {
        auto ret = UserIdToDeviceIdMap{};
        for (auto [userId, devices] : keyMap) {
            auto unknownDevices =
                intoImmer(immer::flex_vector<std::string>{},
                          zug::filter([=](auto kv) {
                                          auto [deviceId, theirCurve25519IdentityKey] = kv;
                                          return m_d->knownSessions.find(theirCurve25519IdentityKey)
                                              == m_d->knownSessions.end();
                                      })
                          | zug::map([=](auto kv) {
                                         auto [deviceId, key] = kv;
                                         return deviceId;
                                     }),
                          devices);
            if (! unknownDevices.empty()) {
                ret = std::move(ret).set(userId, std::move(unknownDevices));
            }
        }
        return ret;
    }

    std::size_t Crypto::createOutboundSessionRandomSize()
    {
        return Session::constructOutboundRandomSize();
    }

    void Crypto::createOutboundSessionWithRandom(
        RandomData random,
        std::string theirIdentityKey,
        std::string theirOneTimeKey)
    {
        assert(random.size() >= createOutboundSessionRandomSize());
        auto session = Session(OutboundSessionTag{},
                               RandomTag{},
                               random,
                               m_d->account,
                               theirIdentityKey,
                               theirOneTimeKey);

        if (session.valid()) {
            m_d->knownSessions.insert_or_assign(theirIdentityKey,
                                                std::move(session));
        }
    }

    nlohmann::json Crypto::toJson() const
    {
        std::string pickledData = m_d->valid ? m_d->pickle() : std::string();
        auto j =  nlohmann::json::object({
                {"valid", m_d->valid},
                {"account", std::move(pickledData)},
                {"uploadedOneTimeKeysCount", m_d->uploadedOneTimeKeysCount},
                {"numUnpublishedKeys", m_d->numUnpublishedKeys},
                {"knownSessions", nlohmann::json(m_d->knownSessions)},
                {"inboundGroupSessions", nlohmann::json(m_d->inboundGroupSessions)},
                {"outboundGroupSessions", nlohmann::json(m_d->outboundGroupSessions)},
            });

        return j;
    }

    void Crypto::loadJson(const nlohmann::json &j)
    {
        m_d->valid = j.contains("valid") ? j["valid"].template get<bool>() : true;
        const auto &pickledData = j.at("account").template get<std::string>();
        if (m_d->valid) { m_d->unpickle(pickledData); }

        m_d->uploadedOneTimeKeysCount = j.at("uploadedOneTimeKeysCount");
        m_d->numUnpublishedKeys = j.at("numUnpublishedKeys");
        m_d->knownSessions = j.at("knownSessions").template get<decltype(m_d->knownSessions)>();
        m_d->inboundGroupSessions = j.at("inboundGroupSessions").template get<decltype(m_d->inboundGroupSessions)>();
        m_d->outboundGroupSessions = j.at("outboundGroupSessions").template get<decltype(m_d->outboundGroupSessions)>();
    }
}
