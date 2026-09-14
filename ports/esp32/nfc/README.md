# nfc — NFC card storage driver (WS1850S / M5Stack RFID Unit 2)

Ported from [Kern](https://github.com/odudex/Kern) (`components/nfc`, branch
`nfc-card-storage` of `sandman21vs/Kern`), MIT License, Copyright (c) 2025 Kern
Contributors. The card format (`KRN1` header, record types 1–4) is kept byte for
byte so cards stay interchangeable with Kern and the Krux fork.

Changes from the Kern component:

- Kconfig symbols renamed `KERN_NFC*` → `SEEDSIGNER_NFC*`.
- The reader is bound to the board I2C bus via `board_i2c_get_handle()`
  (esp-board-common) from the MicroPython binding `bindings/modnfc.c`, instead
  of Kern's `bsp_i2c_get_handle()`.

On the Waveshare ESP32-P4-WIFI6-Touch-LCD-4.3 the reader hangs off the main
I2C bus (SDA GPIO7, SCL GPIO8) at 0x28, shared with the GT911 touch (0x5D/0x14)
and the camera SCCB. Supply 3.3 V.

Host tests for the record header (golden vectors shared with Krux):

```bash
make -C ports/esp32/nfc/test run
```

See Kern's `docs/nfc.md` for the design, threat model and the proof-of-concept
warning, which applies here too.
