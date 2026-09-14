"""MaixPy-style `ucryptolib` shim over the native `_aes_ext` module.

Krux's kef.py (ported into the SeedSigner app for NFC card storage) was written
against MaixPy's `ucryptolib`, which offers AES in ECB/CBC/CTR/GCM with a
pycryptodome-like object API. This firmware has no `cryptolib` at all (it depends
on MICROPY_PY_SSL, and networking is stripped), so this frozen shim provides
exactly the subset kef.py uses, backed by mbedtls through `_aes_ext`:

    aes(key, MODE_ECB)
    aes(key, MODE_CBC, iv)            # 16-byte iv
    aes(key, MODE_CTR, nonce=nonce)   # 12-byte nonce, 4-byte counter from 0
    aes(key, MODE_GCM, iv, mac_len=n) # tag truncated to n bytes
    .encrypt(data) / .decrypt(data)   # one call per object, like kef.py does
    .digest()                         # GCM tag (after encrypt or decrypt)
    .verify(tag)                      # GCM: raises ValueError on mismatch
"""

import _aes_ext

MODE_ECB = 1
MODE_CBC = 2
MODE_CTR = 6
MODE_GCM = 11


def _ct_equal(a, b):
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


class aes:
    def __init__(self, key, mode, iv=None, nonce=None, mac_len=16):
        if mode not in (MODE_ECB, MODE_CBC, MODE_CTR, MODE_GCM):
            raise ValueError("Unsupported mode")
        if mode == MODE_CBC and (iv is None or len(iv) != 16):
            raise ValueError("CBC needs a 16-byte iv")
        if mode == MODE_CTR:
            nonce = nonce if nonce is not None else iv
            if nonce is None or len(nonce) != 12:
                raise ValueError("CTR needs a 12-byte nonce")
        if mode == MODE_GCM:
            if iv is None or len(iv) == 0:
                raise ValueError("GCM needs an iv")
            if not 4 <= mac_len <= 16:
                raise ValueError("Invalid mac_len")
        self._key = bytes(key)
        self._mode = mode
        self._iv = iv
        self._nonce = nonce
        self._mac_len = mac_len
        self._tag = None
        self._used = False

    def _once(self):
        if self._used:
            raise ValueError("Cipher object already used")
        self._used = True

    def encrypt(self, data):
        self._once()
        if self._mode == MODE_ECB:
            return _aes_ext.ecb(self._key, data, True)
        if self._mode == MODE_CBC:
            return _aes_ext.cbc(self._key, self._iv, data, True)
        if self._mode == MODE_CTR:
            return _aes_ext.ctr(self._key, self._nonce, data)
        out, self._tag = _aes_ext.gcm(self._key, self._iv, data, True)
        return out

    def decrypt(self, data):
        self._once()
        if self._mode == MODE_ECB:
            return _aes_ext.ecb(self._key, data, False)
        if self._mode == MODE_CBC:
            return _aes_ext.cbc(self._key, self._iv, data, False)
        if self._mode == MODE_CTR:
            return _aes_ext.ctr(self._key, self._nonce, data)
        out, self._tag = _aes_ext.gcm(self._key, self._iv, data, False)
        return out

    def digest(self):
        if self._mode != MODE_GCM or self._tag is None:
            raise ValueError("No tag available")
        return self._tag[: self._mac_len]

    def verify(self, tag):
        if self._mode != MODE_GCM or self._tag is None:
            raise ValueError("No tag available")
        tag = bytes(tag)
        if not 4 <= len(tag) <= self._mac_len or not _ct_equal(tag, self._tag[: len(tag)]):
            raise ValueError("MAC check failed")
