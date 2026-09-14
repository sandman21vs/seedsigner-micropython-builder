# ESP-IDF component: mbedtls-backed SHA-512 + PBKDF2-HMAC for MicroPython's hashlib.
# Also AES ECB/CBC/CTR/GCM + PBKDF2-HMAC-SHA256 (aes_ext.h) for the KEF port.
#
# Exposes a plain-C API (hashlib_ext.h). The MicroPython binding
# (bindings/modhashlibext.c) is compiled in the usermod and links
# __idf_esp-hashlib-ext; mbedtls stays REQUIRED here so its headers/config never
# reach the usermod QSTR scan (which can't evaluate mbedtls's genex include dirs).
# Same plain-C-lib split as cUR / esp-secp256k1.
idf_component_register(
    SRCS
        "hashlib_ext.c"
        "aes_ext.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        mbedtls
)
