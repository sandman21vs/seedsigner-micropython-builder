"""MaixPy-style `uhashlib_hw` shim for Krux's kef.py.

Provides the two names kef.py uses: `sha256` (MicroPython's built-in) and
`pbkdf2_hmac_sha256(password, salt, iterations)` returning a 32-byte AES-256 key,
computed natively with mbedtls via `_aes_ext`.
"""

import hashlib
import _aes_ext


def sha256(data=b""):
    return hashlib.sha256(data)


def pbkdf2_hmac_sha256(password, salt, iterations):
    return _aes_ext.pbkdf2_hmac_sha256(password, salt, iterations, 32)
