// Plain-C AES (ECB/CBC/CTR/GCM) + PBKDF2-HMAC-SHA256 API, backed by mbedtls.
// Used by the KEF (Krux Encryption Format) port for NFC card storage. Same
// plain-C-lib split as hashlib_ext.h: the MicroPython binding
// (bindings/modaesext.c) includes ONLY this header, so no mbedtls
// generator-expression include dirs leak into the usermod QSTR scan.
//
// All functions return 0 on success, non-zero on failure. key_len is in bytes
// (16, 24 or 32). Contexts are zeroized before returning.
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// PBKDF2-HMAC-SHA256. dklen bytes written to out.
int hlx_pbkdf2_sha256(const uint8_t *password, size_t plen,
                      const uint8_t *salt, size_t slen,
                      unsigned int iterations, uint8_t *out, size_t dklen);

// AES-ECB over len bytes (len must be a multiple of 16).
int hlx_aes_ecb(const uint8_t *key, size_t key_len, int encrypt,
                const uint8_t *in, size_t len, uint8_t *out);

// AES-CBC with a 16-byte IV (len must be a multiple of 16). iv is not modified.
int hlx_aes_cbc(const uint8_t *key, size_t key_len, int encrypt,
                const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out);

// AES-CTR. Counter block = 12-byte nonce || 4-byte big-endian counter from 0
// (the layout Krux/Kern KEF use). Encrypt and decrypt are the same operation.
int hlx_aes_ctr(const uint8_t *key, size_t key_len, const uint8_t nonce[12],
                const uint8_t *in, size_t len, uint8_t *out);

// AES-GCM, no AAD. Writes len bytes to out and the full 16-byte tag to tag.
// In decrypt mode the tag is computed over the ciphertext and NOT verified here:
// the caller compares its (possibly truncated) expected tag in constant time.
int hlx_aes_gcm(const uint8_t *key, size_t key_len, int encrypt,
                const uint8_t *iv, size_t iv_len,
                const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[16]);

#ifdef __cplusplus
}
#endif
