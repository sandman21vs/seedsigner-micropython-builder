// mbedtls-backed implementation of aes_ext.h (AES ECB/CBC/CTR/GCM + PBKDF2-SHA256)
// for the KEF port. Compiled inside the esp-hashlib-ext IDF component, which
// REQUIRES mbedtls, so it sees mbedtls's exact config + headers.

#include "aes_ext.h"

#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"

int hlx_pbkdf2_sha256(const uint8_t *password, size_t plen,
                      const uint8_t *salt, size_t slen,
                      unsigned int iterations, uint8_t *out, size_t dklen) {
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, password, plen,
                                         salt, slen, iterations,
                                         (uint32_t)dklen, out);
}

static int valid_key_len(size_t key_len) {
    return key_len == 16 || key_len == 24 || key_len == 32;
}

int hlx_aes_ecb(const uint8_t *key, size_t key_len, int encrypt,
                const uint8_t *in, size_t len, uint8_t *out) {
    if (!valid_key_len(key_len) || len % 16 != 0) {
        return -1;
    }
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int rc = encrypt ? mbedtls_aes_setkey_enc(&ctx, key, (unsigned)(key_len * 8))
                     : mbedtls_aes_setkey_dec(&ctx, key, (unsigned)(key_len * 8));
    for (size_t off = 0; rc == 0 && off < len; off += 16) {
        rc = mbedtls_aes_crypt_ecb(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                                   in + off, out + off);
    }
    mbedtls_aes_free(&ctx);
    return rc;
}

int hlx_aes_cbc(const uint8_t *key, size_t key_len, int encrypt,
                const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out) {
    if (!valid_key_len(key_len) || len % 16 != 0) {
        return -1;
    }
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, sizeof(iv_copy));
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int rc = encrypt ? mbedtls_aes_setkey_enc(&ctx, key, (unsigned)(key_len * 8))
                     : mbedtls_aes_setkey_dec(&ctx, key, (unsigned)(key_len * 8));
    if (rc == 0) {
        rc = mbedtls_aes_crypt_cbc(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                                   len, iv_copy, in, out);
    }
    mbedtls_aes_free(&ctx);
    mbedtls_platform_zeroize(iv_copy, sizeof(iv_copy));
    return rc;
}

int hlx_aes_ctr(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                const uint8_t *in, size_t len, uint8_t *out) {
    if (!valid_key_len(key_len)) {
        return -1;
    }
    uint8_t counter[16] = {0};
    uint8_t stream_block[16] = {0};
    size_t nc_off = 0;
    memcpy(counter, nonce, 12);
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    // CTR always uses the forward (encrypt) key schedule.
    int rc = mbedtls_aes_setkey_enc(&ctx, key, (unsigned)(key_len * 8));
    if (rc == 0) {
        rc = mbedtls_aes_crypt_ctr(&ctx, len, &nc_off, counter, stream_block, in, out);
    }
    mbedtls_aes_free(&ctx);
    mbedtls_platform_zeroize(stream_block, sizeof(stream_block));
    mbedtls_platform_zeroize(counter, sizeof(counter));
    return rc;
}

int hlx_aes_gcm(const uint8_t *key, size_t key_len, int encrypt,
                const uint8_t *iv, size_t iv_len,
                const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[16]) {
    if (!valid_key_len(key_len) || iv_len == 0) {
        return -1;
    }
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, (unsigned)(key_len * 8));
    if (rc == 0) {
        // crypt_and_tag in DECRYPT mode decrypts and computes the tag over the
        // ciphertext; verification is left to the caller (truncated KEF tags).
        rc = mbedtls_gcm_crypt_and_tag(&ctx, encrypt ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT,
                                       len, iv, iv_len, NULL, 0, in, out, 16, tag);
    }
    mbedtls_gcm_free(&ctx);
    return rc;
}
