//
// Created by qmk on 2023/9/23.
//
#include <iostream>
#include <vector>
#include <sstream> //for std::ostringstream
#include <iomanip> //for std::setw, std::hex, and std::setfill
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "sdnclient/crypto/ecdsa.hpp"

namespace sdn {
namespace crypto {

std::string bytes_to_hex_string(const std::vector<uint8_t>& bytes) {
    std::ostringstream stream;
    for (uint8_t b : bytes){
        stream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(b);
    }
    return stream.str();
}

std::string hex_to_bytes_string(const std::string& hex_string) {
    auto len = hex_string.length();
    std::string bytes_string;
    for(size_t i=0; i< len; i+=2) {
        std::string byte = hex_string.substr(i,2);
        auto chr = (char) (int)std::stoul(byte, nullptr, 16);
        bytes_string.push_back(chr);
    }
    return bytes_string;
}

//perform the keccak-256 hash
std::string keccak_256(const std::string& input) {
    uint32_t digest_length = SHA256_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_sha3_256();
    auto* digest = static_cast<uint8_t*>(OPENSSL_malloc(digest_length));
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, algorithm, nullptr);

    auto* keccak256 = reinterpret_cast<KECCAK1600_CTX*>((reinterpret_cast<EVP_MD_CTX_t*>(context))->md_data);
    keccak256->pad = 0x01;

    EVP_DigestUpdate(context, input.c_str(), input.size());
    EVP_DigestFinal_ex(context, digest, &digest_length);
    EVP_MD_CTX_destroy(context);
    std::string output = bytes_to_hex_string(std::vector<uint8_t>(digest, digest + digest_length));
    OPENSSL_free(digest);
    return output;
}

std:: string text_hash(const std::string& message) {
    std::string prefix = "\x19";
    std::string prefixed_msg = prefix + "Ethereum Signed Message:\n" + std::to_string(message.size()) + message;
    std::string msg_digest = keccak_256(prefixed_msg);
    return msg_digest;
}

std::string get_ethereum_signature(const unsigned char *sig, int recid) {
    std::stringstream stream;
    stream << "0x" << std::hex;
    for(int i=0; i<64; ++i) {
        stream << std::setw(2) << std::setfill('0') << int(sig[i]);
    }
    stream << std::setw(2) << std::setfill('0') << recid;
    return stream.str();
}

bool hash_and_sign(const std::string& key, const std::string& message, std::string& signature) {
    std::string decodedKey = hex_to_bytes_string(key);
    std::string msg_hash = hex_to_bytes_string(text_hash(message));

    const auto *msg_digest = reinterpret_cast<const unsigned char *>(msg_hash.data());
    const auto *sec_key = reinterpret_cast<unsigned char *>(decodedKey.data());

    unsigned char randomize[32];
    int return_val;
    secp256k1_ecdsa_recoverable_signature recoverable_signature;
    unsigned char serialized_signature[64];

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize))) {
        return false;
    }
    /* Randomizing the context is recommended to protect against side-channel
     * leakage See `secp256k1_context_randomize` in secp256k1.h for more
     * information about it. This should never fail. */
    return_val = secp256k1_context_randomize(ctx, randomize);
    if (!return_val) {
        return false;
    }

    /*** Signing ***/
    /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
     * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
     * Signing with a valid context, verified secret key
     * and the default nonce function should never fail. */
    return_val = secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_signature, msg_digest, sec_key, nullptr, nullptr);
    assert(return_val);

    /* Serialize the signature in a compact form. Should always return 1
     * according to the documentation in secp256k1.h. */
    int recid;
    return_val = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, serialized_signature, &recid, &recoverable_signature);
    assert(return_val);

    signature = get_ethereum_signature(serialized_signature, recid);

    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);
    return true;
}

}
}
