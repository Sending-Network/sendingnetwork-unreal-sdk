/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>


#include <catch2/catch_all.hpp>

#include <sstream>

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>


#include <crypto/crypto.hpp>
#include <aes-256-ctr.hpp>
#include <base64.hpp>
#include <sha256.hpp>

using namespace Kazv;
using namespace Kazv::CryptoConstants;

using IAr = boost::archive::text_iarchive;
using OAr = boost::archive::text_oarchive;

template<class T>
static void serializeDup(const T &in, T &out)
{
    std::stringstream stream;

    {
        auto ar = OAr(stream);
        ar << in;
    }

    {
        auto ar = IAr(stream);
        ar >> out;
    }
}

TEST_CASE("Crypto constructors", "[crypto]")
{
    Crypto crypto;
    REQUIRE(!crypto.valid());

    Crypto crypto2(RandomTag{}, genRandomData(Crypto::constructRandomSize()));
    REQUIRE(crypto2.valid());
}

TEST_CASE("Crypto should be copyable", "[crypto]")
{
    Crypto crypto(RandomTag{}, genRandomData(Crypto::constructRandomSize()));

    crypto.genOneTimeKeysWithRandom(genRandomData(Crypto::genOneTimeKeysRandomSize(1)), 1);
    auto oneTimeKeys = crypto.unpublishedOneTimeKeys();
    Crypto cryptoClone(crypto);

    REQUIRE(crypto.ed25519IdentityKey() == cryptoClone.ed25519IdentityKey());
    REQUIRE(crypto.curve25519IdentityKey() == cryptoClone.curve25519IdentityKey());

    auto oneTimeKeys2 = cryptoClone.unpublishedOneTimeKeys();

    REQUIRE(oneTimeKeys == oneTimeKeys2);
    REQUIRE(crypto.numUnpublishedOneTimeKeys() == cryptoClone.numUnpublishedOneTimeKeys());
}

TEST_CASE("Crypto should be serializable", "[crypto]")
{
    Crypto crypto(RandomTag{}, genRandomData(Crypto::constructRandomSize()));

    crypto.genOneTimeKeysWithRandom(genRandomData(Crypto::genOneTimeKeysRandomSize(1)), 1);
    auto oneTimeKeys = crypto.unpublishedOneTimeKeys();

    Crypto cryptoClone;

    serializeDup(crypto, cryptoClone);

    REQUIRE(crypto.ed25519IdentityKey() == cryptoClone.ed25519IdentityKey());
    REQUIRE(crypto.curve25519IdentityKey() == cryptoClone.curve25519IdentityKey());

    auto oneTimeKeys2 = cryptoClone.unpublishedOneTimeKeys();

    REQUIRE(oneTimeKeys == oneTimeKeys2);
    REQUIRE(crypto.numUnpublishedOneTimeKeys() == cryptoClone.numUnpublishedOneTimeKeys());
}

TEST_CASE("Invalid Crypto should be serializable", "[crypto]")
{
    Crypto crypto;
    Crypto cryptoClone;
    serializeDup(crypto, cryptoClone);
    REQUIRE(!cryptoClone.valid());
}

TEST_CASE("Serialize Crypto with an OutboundGroupSession", "[crypto]")
{
    Crypto crypto(RandomTag{}, genRandomData(Crypto::constructRandomSize()));

    std::string roomId = "!example:example.org";
    auto desc = MegOlmSessionRotateDesc{500000 /* ms */, 100 /* messages */};

    crypto.rotateMegOlmSessionWithRandom(genRandomData(Crypto::rotateMegOlmSessionRandomSize()), currentTimeMs(), roomId);

    Crypto cryptoClone;

    serializeDup(crypto, cryptoClone);

    REQUIRE(! cryptoClone.rotateMegOlmSessionWithRandomIfNeeded(
                genRandomData(Crypto::rotateMegOlmSessionRandomSize()), currentTimeMs(),
                roomId, desc).has_value());
}

TEST_CASE("Generating and publishing keys should work", "[crypto]")
{
    Crypto crypto(RandomTag{}, genRandomData(Crypto::constructRandomSize()));

    crypto.genOneTimeKeysWithRandom(genRandomData(Crypto::genOneTimeKeysRandomSize(1)), 1);

    REQUIRE(crypto.numUnpublishedOneTimeKeys() == 1);

    crypto.genOneTimeKeysWithRandom(genRandomData(Crypto::genOneTimeKeysRandomSize(1)), 1);
    REQUIRE(crypto.numUnpublishedOneTimeKeys() == 2);

    crypto.markOneTimeKeysAsPublished();
    REQUIRE(crypto.numUnpublishedOneTimeKeys() == 0);
}

TEST_CASE("Should reuse existing inbound session to encrypt", "[crypto]")
{
    Crypto a(RandomTag{}, genRandomData(Crypto::constructRandomSize()));
    Crypto b(RandomTag{}, genRandomData(Crypto::constructRandomSize()));

    a.genOneTimeKeysWithRandom(genRandomData(Crypto::genOneTimeKeysRandomSize(1)), 1);
    // Get A publish the key and send to B
    auto k = a.unpublishedOneTimeKeys();
    a.markOneTimeKeysAsPublished();

    auto oneTimeKey = std::string{};

    for (auto [id, key] : k[curve25519].items()) {
        oneTimeKey = key;
    }

    auto aIdKey = a.curve25519IdentityKey();
    b.createOutboundSessionWithRandom(genRandomData(Crypto::createOutboundSessionRandomSize()), aIdKey, oneTimeKey);

    auto origJson = json{{"test", "mew"}};
    auto encryptedMsg = b.encryptOlmWithRandom(genRandomData(Crypto::encryptOlmMaxRandomSize()), origJson, aIdKey);
    auto encJson = json{
        {"content",
         {
             {"algorithm", olmAlgo},
             {"ciphertext", encryptedMsg},
             {"sender_key", b.curve25519IdentityKey()}
         }
        }
    };

    auto decryptedOpt = a.decrypt(encJson);

    REQUIRE(decryptedOpt);

    auto decryptedJson = json::parse(decryptedOpt.value());

    REQUIRE(decryptedJson == origJson);

    using StrMap = immer::map<std::string, std::string>;
    auto devMap = immer::map<std::string, StrMap>()
        .set("b", StrMap().set("dev", b.curve25519IdentityKey()));

    Crypto aClone{a};

    auto devices = a.devicesMissingOutboundSessionKey(devMap);
    auto devicesAClone = aClone.devicesMissingOutboundSessionKey(devMap);

    // No device should be missing an olm session, as A has received an
    // inbound olm session before.
    auto expected = immer::map<std::string, immer::flex_vector<std::string>>();

    REQUIRE(devices == expected);
    REQUIRE(devicesAClone == expected);
}

TEST_CASE("Encrypt and decrypt AES-256-CTR", "[crypto][aes256ctr]")
{
    auto r = genRandom(AES256CTRDesc::randomSize);

    auto desc = AES256CTRDesc::fromRandom(r);
    auto desc2 = desc;

    std::string original = "test for aes-256-ctr";

    auto encrypted = desc.processInPlace(original);

    auto decrypted = desc2.processInPlace(encrypted);

    REQUIRE(original == decrypted);
}

TEST_CASE("Encrypt and decrypt AES-256-CTR with any sequence type", "[crypto][aes256ctr]")
{
    auto r = genRandom(AES256CTRDesc::randomSize);

    auto desc = AES256CTRDesc::fromRandom(r);
    auto desc2 = desc;

    std::string oStr = "test for aes-256-ctr";
    std::vector<unsigned char> original(oStr.begin(), oStr.end());

    auto encrypted = desc.processInPlace(original);

    auto decrypted = desc2.processInPlace(encrypted);

    REQUIRE(original == decrypted);
}

TEST_CASE("Encrypt and decrypt AES-256-CTR in a non-destructive way", "[crypto][aes256ctr]")
{
    auto r = genRandom(AES256CTRDesc::randomSize);

    auto desc = AES256CTRDesc::fromRandom(r);

    std::string original = "test for aes-256-ctr";

    auto [next, encrypted] = desc.process(original);

    auto [next2, encrypted2] = desc.process(original);

    REQUIRE(encrypted == encrypted2);

    auto [next3, decrypted] = desc.process(encrypted);

    REQUIRE(original == decrypted);
}

TEST_CASE("Encrypt and decrypt AES-256-CTR in batches", "[crypto][aes256ctr]")
{
    auto r = genRandom(AES256CTRDesc::randomSize);

    auto desc = AES256CTRDesc::fromRandom(r);

    std::string original = "test for aes-256-ctr";

    std::string orig2 = "another test string...";

    auto [next, encrypted] = desc.process(original);
    auto [next2, encrypted2] = next.process(orig2);

    auto [next3, decrypted] = desc.process(encrypted + encrypted2);

    REQUIRE(original + orig2 == decrypted);
}

TEST_CASE("AES-256-CTR should be movable", "[crypto][aes256ctr]")
{
    auto r = genRandom(AES256CTRDesc::randomSize);

    auto desc = AES256CTRDesc::fromRandom(r);

    auto desc2 = std::move(desc);

    REQUIRE(desc2.valid());
    REQUIRE(! desc.valid());

    std::string original = "test for aes-256-ctr";

    std::string encrypted;

    // Can be moved from itself
    desc2 = std::move(desc2);
    REQUIRE(desc2.valid());

    std::tie(desc2, encrypted) = std::move(desc2).process(original);

    REQUIRE(desc2.valid());
}

TEST_CASE("Construct AES-256-CTR from known key and iv", "[crypto][aes256ctr]")
{
    auto r = genRandom(AES256CTRDesc::randomSize);

    auto desc = AES256CTRDesc::fromRandom(r);

    auto desc2 = AES256CTRDesc(desc.key(), desc.iv());

    REQUIRE(desc2.valid());
    REQUIRE(desc.key() == desc2.key());
    REQUIRE(desc.iv() == desc2.iv());
}

TEST_CASE("AES-256-CTR validity check", "[crypto][aes256ctr]")
{
    SECTION("Not enough random, should reject") {
        ByteArray random = genRandom(AES256CTRDesc::randomSize - 1);

        auto desc = AES256CTRDesc::fromRandom(random);

        REQUIRE(! desc.valid());
    }

    SECTION("More than enough random, should accept") {
        ByteArray random = genRandom(AES256CTRDesc::randomSize + 1);

        auto desc = AES256CTRDesc::fromRandom(random);

        REQUIRE(desc.valid());
    }

}


TEST_CASE("Base64 encoder and decoder", "[crypto][base64]")
{
    std::string orig = "The Quick Brown Fox Jumps Over the Lazy Dog";
    // no padding
    std::string expected = "VGhlIFF1aWNrIEJyb3duIEZveCBKdW1wcyBPdmVyIHRoZSBMYXp5IERvZw";
    std::string encoded = encodeBase64(orig);
    REQUIRE(encoded == expected);

    std::string decoded = decodeBase64(encoded);
    REQUIRE(decoded == orig);
}

TEST_CASE("Urlsafe base64 encoder and decoder", "[crypto][base64]")
{
    std::string orig = "The Quick Brown Fox Jumps Over the Lazy Dog";
    // no padding
    std::string expected = "VGhlIFF1aWNrIEJyb3duIEZveCBKdW1wcyBPdmVyIHRoZSBMYXp5IERvZw";
    std::string encoded = encodeBase64(orig, Base64Opts::urlSafe);
    REQUIRE(encoded == expected);

    std::string decoded = decodeBase64(encoded, Base64Opts::urlSafe);
    REQUIRE(decoded == orig);
}

TEST_CASE("Base64 encoder and decoder", "[crypto][base64]")
{
    std::string orig = "JGLn/yafz74HB2AbPLYJWIVGnKAtqECOBf11yyXac2Y";

    std::string decoded = decodeBase64(orig);
    std::string encoded = encodeBase64(decoded);
    REQUIRE(encoded == orig);
}

TEST_CASE("Urlsafe base64 encoder and decoder", "[crypto][base64]")
{
    std::string orig = "JGLn_yafz74HB2AbPLYJWIVGnKAtqECOBf11yyXac2Y";

    std::string decoded = decodeBase64(orig, Base64Opts::urlSafe);
    std::string encoded = encodeBase64(decoded, Base64Opts::urlSafe);
    REQUIRE(encoded == orig);
}

TEST_CASE("SHA256 hashing support", "[crypto][sha256]")
{
    auto hash = SHA256Desc{};

    auto message1 = std::string("12345678910");
    hash.processInPlace(message1);

    auto res = hash.get();
    auto expected = std::string("Y2QCZISah8kDVhKdmeoWXjeqX6vB/qRpBt8afKUNtJI");

    REQUIRE(res == expected);
}

TEST_CASE("SHA256 hashing streaming", "[crypto][sha256]")
{
    auto hash = SHA256Desc{};

    auto message1 = std::string("12345678910");
    auto message2 = std::string("abcdefghijklmn");
    hash.processInPlace(message1);
    hash.processInPlace(message2);

    auto res = hash.get();

    auto hash2 = SHA256Desc{};

    hash2.processInPlace(message1 + message2);
    auto expected = hash2.get();

    REQUIRE(res == expected);
}

TEST_CASE("SHA256Desc should be copyable", "[crypto][sha256]")
{
    auto hash = SHA256Desc{};

    auto message1 = std::string("12345678910");
    auto message2 = std::string("abcdefghijklmn");
    hash.processInPlace(message1);

    auto hash2 = hash;

    hash.processInPlace(message2);
    hash2.processInPlace(message2);

    auto res = hash.get();
    auto res2 = hash2.get();

    REQUIRE(res == res2);
}

TEST_CASE("SHA256Desc should be self-copyable and -movable", "[crypto][sha256]")
{
    auto hash = SHA256Desc{};

    auto message1 = std::string("12345678910");
    hash = hash.process(message1);

    auto message2 = std::string("abcdefghijklmn");
    hash = std::move(hash).process(message2);

    auto hash2 = SHA256Desc{};

    hash2.processInPlace(message1 + message2);

    auto res = hash.get();
    auto res2 = hash2.get();

    REQUIRE(res == res2);
}

TEST_CASE("SHA256 should accept any range type", "[crypto][sha256]")
{
    std::string msg = "12345678910";
    std::vector<char> arr(msg.begin(), msg.end());

    auto hash = SHA256Desc{};

    auto res1 = hash.process(arr).get();

    auto res2 = std::move(hash).process(arr).get();

    // after moving, hash is no longer valid, reset it here
    hash = SHA256Desc{};

    hash.processInPlace(arr);
    auto res3 = hash.get();

    hash = SHA256Desc{};
    auto reference = hash.process(msg).get();

    REQUIRE(res1 == res2);
    REQUIRE(res1 == res3);
    REQUIRE(res1 == reference);
}
