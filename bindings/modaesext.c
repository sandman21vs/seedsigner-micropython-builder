// Native AES + PBKDF2-HMAC-SHA256, exposed as the private helper module `_aes_ext`.
//
// This firmware is built without networking, so MicroPython's `cryptolib` (which
// depends on MICROPY_PY_SSL) is absent. The KEF (Krux Encryption Format) port used
// by NFC card storage needs AES in ECB/CBC/CTR/GCM modes and PBKDF2-HMAC-SHA256.
// A frozen `ucryptolib.py` / `uhashlib_hw.py` shim (deps/third-party) wraps these
// one-shot functions into the MaixPy-style API that Krux's kef.py expects.
//
// The crypto lives in the __idf_esp-hashlib-ext component (mbedtls); this TU only
// calls its plain-C API (aes_ext.h) so no mbedtls headers enter the QSTR scan.

#include <string.h>

#include "py/objstr.h"
#include "py/runtime.h"

#include "aes_ext.h"

#ifndef MP_ERROR_TEXT
#define MP_ERROR_TEXT(x) (x)
#endif

static void wipe(void *buf, size_t len) {
    volatile unsigned char *p = buf;
    while (len--) {
        *p++ = 0;
    }
}

static void get_key(mp_obj_t key_in, mp_buffer_info_t *key) {
    mp_get_buffer_raise(key_in, key, MP_BUFFER_READ);
    if (key->len != 16 && key->len != 24 && key->len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("key must be 16, 24 or 32 bytes"));
    }
}

// pbkdf2_hmac_sha256(password, salt, iterations, dklen=32) -> bytes
static mp_obj_t mod_pbkdf2_hmac_sha256(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t pw, salt;
    mp_get_buffer_raise(args[0], &pw, MP_BUFFER_READ);
    mp_get_buffer_raise(args[1], &salt, MP_BUFFER_READ);
    mp_int_t iters = mp_obj_get_int(args[2]);
    if (iters <= 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("iterations must be positive"));
    }
    mp_int_t dklen = 32;
    if (n_args > 3 && args[3] != mp_const_none) {
        dklen = mp_obj_get_int(args[3]);
        if (dklen <= 0) {
            mp_raise_ValueError(MP_ERROR_TEXT("dklen must be positive"));
        }
    }
    vstr_t vstr;
    vstr_init_len(&vstr, dklen);
    if (hlx_pbkdf2_sha256(pw.buf, pw.len, salt.buf, salt.len, (unsigned int)iters,
                          (uint8_t *)vstr.buf, dklen) != 0) {
        vstr_clear(&vstr);
        mp_raise_ValueError(MP_ERROR_TEXT("pbkdf2 failed"));
    }
    return mp_obj_new_bytes_from_vstr(&vstr);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_pbkdf2_hmac_sha256_obj, 3, 4, mod_pbkdf2_hmac_sha256);

// ecb(key, data, encrypt) -> bytes
static mp_obj_t mod_ecb(mp_obj_t key_in, mp_obj_t data_in, mp_obj_t enc_in) {
    mp_buffer_info_t key, data;
    get_key(key_in, &key);
    mp_get_buffer_raise(data_in, &data, MP_BUFFER_READ);
    if (data.len % 16 != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("data not aligned to 16 bytes"));
    }
    vstr_t vstr;
    vstr_init_len(&vstr, data.len);
    if (hlx_aes_ecb(key.buf, key.len, mp_obj_is_true(enc_in), data.buf, data.len,
                    (uint8_t *)vstr.buf) != 0) {
        vstr_clear(&vstr);
        mp_raise_ValueError(MP_ERROR_TEXT("aes ecb failed"));
    }
    return mp_obj_new_bytes_from_vstr(&vstr);
}
static MP_DEFINE_CONST_FUN_OBJ_3(mod_ecb_obj, mod_ecb);

// cbc(key, iv, data, encrypt) -> bytes
static mp_obj_t mod_cbc(size_t n_args, const mp_obj_t *args) {
    (void)n_args;
    mp_buffer_info_t key, iv, data;
    get_key(args[0], &key);
    mp_get_buffer_raise(args[1], &iv, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &data, MP_BUFFER_READ);
    if (iv.len != 16) {
        mp_raise_ValueError(MP_ERROR_TEXT("iv must be 16 bytes"));
    }
    if (data.len % 16 != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("data not aligned to 16 bytes"));
    }
    vstr_t vstr;
    vstr_init_len(&vstr, data.len);
    if (hlx_aes_cbc(key.buf, key.len, mp_obj_is_true(args[3]), iv.buf, data.buf, data.len,
                    (uint8_t *)vstr.buf) != 0) {
        vstr_clear(&vstr);
        mp_raise_ValueError(MP_ERROR_TEXT("aes cbc failed"));
    }
    return mp_obj_new_bytes_from_vstr(&vstr);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_cbc_obj, 4, 4, mod_cbc);

// ctr(key, nonce12, data) -> bytes
static mp_obj_t mod_ctr(mp_obj_t key_in, mp_obj_t nonce_in, mp_obj_t data_in) {
    mp_buffer_info_t key, nonce, data;
    get_key(key_in, &key);
    mp_get_buffer_raise(nonce_in, &nonce, MP_BUFFER_READ);
    mp_get_buffer_raise(data_in, &data, MP_BUFFER_READ);
    if (nonce.len != 12) {
        mp_raise_ValueError(MP_ERROR_TEXT("nonce must be 12 bytes"));
    }
    vstr_t vstr;
    vstr_init_len(&vstr, data.len);
    if (hlx_aes_ctr(key.buf, key.len, nonce.buf, data.buf, data.len, (uint8_t *)vstr.buf) != 0) {
        vstr_clear(&vstr);
        mp_raise_ValueError(MP_ERROR_TEXT("aes ctr failed"));
    }
    return mp_obj_new_bytes_from_vstr(&vstr);
}
static MP_DEFINE_CONST_FUN_OBJ_3(mod_ctr_obj, mod_ctr);

// gcm(key, iv, data, encrypt) -> (bytes out, bytes tag16)
static mp_obj_t mod_gcm(size_t n_args, const mp_obj_t *args) {
    (void)n_args;
    mp_buffer_info_t key, iv, data;
    get_key(args[0], &key);
    mp_get_buffer_raise(args[1], &iv, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &data, MP_BUFFER_READ);
    if (iv.len == 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("iv required"));
    }
    uint8_t tag[16];
    vstr_t vstr;
    vstr_init_len(&vstr, data.len);
    if (hlx_aes_gcm(key.buf, key.len, mp_obj_is_true(args[3]), iv.buf, iv.len,
                    data.buf, data.len, (uint8_t *)vstr.buf, tag) != 0) {
        vstr_clear(&vstr);
        wipe(tag, sizeof(tag));
        mp_raise_ValueError(MP_ERROR_TEXT("aes gcm failed"));
    }
    mp_obj_t items[2] = {
        mp_obj_new_bytes_from_vstr(&vstr),
        mp_obj_new_bytes(tag, sizeof(tag)),
    };
    wipe(tag, sizeof(tag));
    return mp_obj_new_tuple(2, items);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_gcm_obj, 4, 4, mod_gcm);

static const mp_rom_map_elem_t aes_ext_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR__aes_ext)},
    {MP_ROM_QSTR(MP_QSTR_pbkdf2_hmac_sha256), MP_ROM_PTR(&mod_pbkdf2_hmac_sha256_obj)},
    {MP_ROM_QSTR(MP_QSTR_ecb), MP_ROM_PTR(&mod_ecb_obj)},
    {MP_ROM_QSTR(MP_QSTR_cbc), MP_ROM_PTR(&mod_cbc_obj)},
    {MP_ROM_QSTR(MP_QSTR_ctr), MP_ROM_PTR(&mod_ctr_obj)},
    {MP_ROM_QSTR(MP_QSTR_gcm), MP_ROM_PTR(&mod_gcm_obj)},
};
static MP_DEFINE_CONST_DICT(aes_ext_globals, aes_ext_globals_table);

const mp_obj_module_t aes_ext_user_cmodule = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&aes_ext_globals,
};

MP_REGISTER_MODULE(MP_QSTR__aes_ext, aes_ext_user_cmodule);
