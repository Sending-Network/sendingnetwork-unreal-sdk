//
// Created by qmk on 2023/9/23.
//

#ifndef SDN_CLIENT_ECDSA_HPP
#define SDN_CLIENT_ECDSA_HPP

#if defined(_WIN32)
/*
 * The defined WIN32_NO_STATUS macro disables return code definitions in
 * windows.h, which avoids "macro redefinition" MSVC warnings in ntstatus.h.
 */
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/random.h>
#elif defined(__OpenBSD__)
#include <unistd.h>
#else
#error "Couldn't identify the OS"
#endif

#include <cstddef>
#include <climits>
#include <cstdio>
#include <openssl/evp.h> //for all other OpenSSL function calls
#include <openssl/sha.h> //for SHA256_DIGEST_LENGTH

namespace sdn {
namespace crypto {

struct EVP_MD_CTX_t {
    const EVP_MD *digest;
    ENGINE *engine;             /* functional reference if 'digest' is
								            * ENGINE-provided */
    unsigned long flags;
    void *md_data;
    /* Public key context for sign/verify */
    EVP_PKEY_CTX *pctx;
    /* Update function: usually copied from EVP_MD */
    int(*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVP_MD_CTX */;

struct KECCAK1600_CTX {
    uint64_t A[5][5];
    size_t block_size;          /* cached ctx->digest->block_size */
    size_t md_size;             /* output length, variable in XOF */
    size_t num;                 /* used bytes in below buffer */
    unsigned char buf[1600 / 8 - 32];
    unsigned char pad;
};

/* Returns 1 on success, and 0 on failure. */
static int
fill_random(unsigned char *data, size_t size)
{
#if defined(_WIN32)
    NTSTATUS res = BCryptGenRandom(NULL, data, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (res != STATUS_SUCCESS || size > ULONG_MAX) {
        return 0;
    } else {
        return 1;
    }
#elif defined(__linux__) || defined(__FreeBSD__)
    /* If `getrandom(2)` is not available you should fallback to /dev/urandom */
    ssize_t res = getrandom(data, size, 0);
    if (res < 0 || (size_t)res != size) {
        return 0;
    } else {
        return 1;
    }
#elif defined(__APPLE__) || defined(__OpenBSD__)
    /* If `getentropy(2)` is not available you should fallback to either
     * `SecRandomCopyBytes` or /dev/urandom */
    int res = getentropy(data, size);
    if (res == 0) {
        return 1;
    } else {
        return 0;
    }
#endif
    return 0;
}

bool
hash_and_sign(const std::string &key, const std::string &message, std::string &signature);

}
}

#endif // SDN_CLIENT_ECDSA_HPP
