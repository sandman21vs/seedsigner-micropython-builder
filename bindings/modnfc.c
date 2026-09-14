// MicroPython binding for NFC card storage: module `nfc`.
//
// Thin wrapper over the plain-C `nfc` component (ports/esp32/nfc, ported from
// Kern). The reader (WS1850S / M5Stack RFID Unit 2) sits on the board's main I2C
// bus, which esp-board-common already owns for touch + camera SCCB, so the bus
// handle comes from board_i2c_get_handle() — never open machine.I2C on it.
//
// One reader, one card at a time: the tag selected by the last poll() is kept
// here, and has_record()/read_record()/write_record() act on it.
//
//   init()                      bind the reader; OSError(ENODEV) if absent
//   deinit()                    release it (drops the RF field first)
//   is_ready() -> bool
//   field(on)                   energize / drop the antenna
//   poll() -> dict | None       {"type", "uid", "sak", "capacity"} or None
//   has_record() -> bool        any known record type on the last polled tag
//   read_record(accept_mask) -> bytes   OSError(ENOENT) if absent / wrong type
//   write_record(type, data)
//
// Card contents are attacker-controlled; all validation lives in the component
// (see ports/esp32/nfc/src/nfc_record.h). Payload buffers are wiped before free.

#include <stdlib.h>
#include <string.h>

#include "py/mperrno.h"
#include "py/obj.h"
#include "py/runtime.h"

#include "board_i2c.h"
#include "nfc.h"

static nfc_tag_t s_tag;
static bool s_have_tag = false;

static void wipe(void *buf, size_t len) {
    volatile unsigned char *p = buf;
    while (len--) {
        *p++ = 0;
    }
}

static MP_NORETURN void raise_esp_err(esp_err_t err) {
    int e = MP_EIO;
    if (err == ESP_ERR_NOT_FOUND) {
        e = MP_ENOENT;
    } else if (err == ESP_ERR_INVALID_SIZE || err == ESP_ERR_INVALID_ARG) {
        e = MP_EINVAL;
    } else if (err == ESP_ERR_TIMEOUT) {
        e = MP_ETIMEDOUT;
    } else if (err == ESP_ERR_NO_MEM) {
        e = MP_ENOMEM;
    }
    mp_raise_OSError(e);
}

static void require_ready(void) {
    if (!nfc_is_ready()) {
        mp_raise_OSError(MP_ENODEV);
    }
}

static void require_tag(void) {
    require_ready();
    if (!s_have_tag) {
        mp_raise_ValueError(MP_ERROR_TEXT("no tag polled"));
    }
}

static mp_obj_t mod_nfc_init(void) {
    i2c_master_bus_handle_t bus = board_i2c_get_handle();
    if (bus == NULL) {
        mp_raise_OSError(MP_ENODEV);
    }
    esp_err_t err = nfc_init(bus);
    if (err == ESP_ERR_NOT_FOUND) {
        mp_raise_OSError(MP_ENODEV);
    } else if (err != ESP_OK) {
        raise_esp_err(err);
    }
    s_have_tag = false;
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(mod_nfc_init_obj, mod_nfc_init);

static mp_obj_t mod_nfc_deinit(void) {
    nfc_deinit();
    s_have_tag = false;
    wipe(&s_tag, sizeof(s_tag));
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(mod_nfc_deinit_obj, mod_nfc_deinit);

static mp_obj_t mod_nfc_is_ready(void) {
    return mp_obj_new_bool(nfc_is_ready());
}
static MP_DEFINE_CONST_FUN_OBJ_0(mod_nfc_is_ready_obj, mod_nfc_is_ready);

static mp_obj_t mod_nfc_field(mp_obj_t on_in) {
    require_ready();
    esp_err_t err = nfc_field_set(mp_obj_is_true(on_in));
    if (err != ESP_OK) {
        raise_esp_err(err);
    }
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_nfc_field_obj, mod_nfc_field);

static mp_obj_t mod_nfc_poll(void) {
    require_ready();
    nfc_tag_t tag;
    if (nfc_poll(&tag) != ESP_OK) {
        // Empty field, unsupported tag, or a transient bus/RF error: all read as
        // "no card" so a tap loop simply tries again on its next tick.
        s_have_tag = false;
        return mp_const_none;
    }
    s_tag = tag;
    s_have_tag = true;
    mp_obj_t dict = mp_obj_new_dict(4);
    mp_obj_dict_store(dict, MP_OBJ_NEW_QSTR(MP_QSTR_type), MP_OBJ_NEW_SMALL_INT(tag.type));
    mp_obj_dict_store(dict, MP_OBJ_NEW_QSTR(MP_QSTR_uid), mp_obj_new_bytes(tag.uid, tag.uid_len));
    mp_obj_dict_store(dict, MP_OBJ_NEW_QSTR(MP_QSTR_sak), MP_OBJ_NEW_SMALL_INT(tag.sak));
    mp_obj_dict_store(dict, MP_OBJ_NEW_QSTR(MP_QSTR_capacity), mp_obj_new_int_from_uint(tag.capacity));
    return dict;
}
static MP_DEFINE_CONST_FUN_OBJ_0(mod_nfc_poll_obj, mod_nfc_poll);

static mp_obj_t mod_nfc_has_record(void) {
    require_tag();
    return mp_obj_new_bool(nfc_has_record(&s_tag));
}
static MP_DEFINE_CONST_FUN_OBJ_0(mod_nfc_has_record_obj, mod_nfc_has_record);

static mp_obj_t mod_nfc_read_record(mp_obj_t mask_in) {
    require_tag();
    uint32_t mask = (uint32_t)mp_obj_get_int(mask_in);
    uint8_t *data = NULL;
    size_t len = 0;
    esp_err_t err = nfc_read_record(&s_tag, mask, &data, &len);
    if (err != ESP_OK) {
        raise_esp_err(err);
    }
    mp_obj_t out = mp_obj_new_bytes(data, len);
    wipe(data, len);
    free(data);
    return out;
}
static MP_DEFINE_CONST_FUN_OBJ_1(mod_nfc_read_record_obj, mod_nfc_read_record);

static mp_obj_t mod_nfc_write_record(mp_obj_t type_in, mp_obj_t data_in) {
    require_tag();
    mp_int_t type = mp_obj_get_int(type_in);
    if (type < 0 || type > 255) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid record type"));
    }
    mp_buffer_info_t data;
    mp_get_buffer_raise(data_in, &data, MP_BUFFER_READ);
    esp_err_t err = nfc_write_record(&s_tag, (uint8_t)type, data.buf, data.len);
    if (err != ESP_OK) {
        raise_esp_err(err);
    }
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(mod_nfc_write_record_obj, mod_nfc_write_record);

static const mp_rom_map_elem_t nfc_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_nfc)},
    {MP_ROM_QSTR(MP_QSTR_init), MP_ROM_PTR(&mod_nfc_init_obj)},
    {MP_ROM_QSTR(MP_QSTR_deinit), MP_ROM_PTR(&mod_nfc_deinit_obj)},
    {MP_ROM_QSTR(MP_QSTR_is_ready), MP_ROM_PTR(&mod_nfc_is_ready_obj)},
    {MP_ROM_QSTR(MP_QSTR_field), MP_ROM_PTR(&mod_nfc_field_obj)},
    {MP_ROM_QSTR(MP_QSTR_poll), MP_ROM_PTR(&mod_nfc_poll_obj)},
    {MP_ROM_QSTR(MP_QSTR_has_record), MP_ROM_PTR(&mod_nfc_has_record_obj)},
    {MP_ROM_QSTR(MP_QSTR_read_record), MP_ROM_PTR(&mod_nfc_read_record_obj)},
    {MP_ROM_QSTR(MP_QSTR_write_record), MP_ROM_PTR(&mod_nfc_write_record_obj)},
    {MP_ROM_QSTR(MP_QSTR_RECORD_KEF), MP_ROM_INT(NFC_RECORD_TYPE_KEF)},
    {MP_ROM_QSTR(MP_QSTR_RECORD_DESCRIPTOR), MP_ROM_INT(NFC_RECORD_TYPE_DESCRIPTOR)},
    {MP_ROM_QSTR(MP_QSTR_MAX_PAYLOAD), MP_ROM_INT(NFC_MAX_PAYLOAD)},
    {MP_ROM_QSTR(MP_QSTR_TAG_MIFARE_CLASSIC), MP_ROM_INT(NFC_TAG_MIFARE_CLASSIC)},
    {MP_ROM_QSTR(MP_QSTR_TAG_ULTRALIGHT), MP_ROM_INT(NFC_TAG_ULTRALIGHT)},
};
static MP_DEFINE_CONST_DICT(nfc_globals, nfc_globals_table);

const mp_obj_module_t nfc_user_cmodule = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&nfc_globals,
};

MP_REGISTER_MODULE(MP_QSTR_nfc, nfc_user_cmodule);
