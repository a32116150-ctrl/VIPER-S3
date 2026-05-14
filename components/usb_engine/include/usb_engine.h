#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define USB_HID_KEY_NONE      0x00
#define USB_HID_KEY_A         0x04
#define USB_HID_KEY_B         0x05
#define USB_HID_KEY_C         0x06
#define USB_HID_KEY_D         0x07
#define USB_HID_KEY_E         0x08
#define USB_HID_KEY_F         0x09
#define USB_HID_KEY_G         0x0A
#define USB_HID_KEY_H         0x0B
#define USB_HID_KEY_I         0x0C
#define USB_HID_KEY_J         0x0D
#define USB_HID_KEY_K         0x0E
#define USB_HID_KEY_L         0x0F
#define USB_HID_KEY_M         0x10
#define USB_HID_KEY_N         0x11
#define USB_HID_KEY_O         0x12
#define USB_HID_KEY_P         0x13
#define USB_HID_KEY_Q         0x14
#define USB_HID_KEY_R         0x15
#define USB_HID_KEY_S         0x16
#define USB_HID_KEY_T         0x17
#define USB_HID_KEY_U         0x18
#define USB_HID_KEY_V         0x19
#define USB_HID_KEY_W         0x1A
#define USB_HID_KEY_X         0x1B
#define USB_HID_KEY_Y         0x1C
#define USB_HID_KEY_Z         0x1D
#define USB_HID_KEY_1         0x1E
#define USB_HID_KEY_2         0x1F
#define USB_HID_KEY_3         0x20
#define USB_HID_KEY_4         0x21
#define USB_HID_KEY_5         0x22
#define USB_HID_KEY_6         0x23
#define USB_HID_KEY_7         0x24
#define USB_HID_KEY_8         0x25
#define USB_HID_KEY_9         0x26
#define USB_HID_KEY_0         0x27
#define USB_HID_KEY_ENTER     0x28
#define USB_HID_KEY_ESC       0x29
#define USB_HID_KEY_BACKSPACE 0x2A
#define USB_HID_KEY_TAB       0x2B
#define USB_HID_KEY_SPACE     0x2C
#define USB_HID_KEY_MINUS     0x2D
#define USB_HID_KEY_EQUAL     0x2E
#define USB_HID_KEY_BRACKET_L 0x2F
#define USB_HID_KEY_BRACKET_R 0x30
#define USB_HID_KEY_BACKSLASH 0x31
#define USB_HID_KEY_SEMICOLON 0x33
#define USB_HID_KEY_QUOTE     0x34
#define USB_HID_KEY_GRAVE     0x35
#define USB_HID_KEY_COMMA     0x36
#define USB_HID_KEY_DOT       0x37
#define USB_HID_KEY_SLASH     0x38
#define USB_HID_KEY_CAPS      0x39
#define USB_HID_KEY_F1        0x3A
#define USB_HID_KEY_F2        0x3B
#define USB_HID_KEY_F3        0x3C
#define USB_HID_KEY_F4        0x3D
#define USB_HID_KEY_F5        0x3E
#define USB_HID_KEY_F6        0x3F
#define USB_HID_KEY_F7        0x40
#define USB_HID_KEY_F8        0x41
#define USB_HID_KEY_F9        0x42
#define USB_HID_KEY_F10       0x43
#define USB_HID_KEY_F11       0x44
#define USB_HID_KEY_F12       0x45
#define USB_HID_KEY_DELETE    0x4C
#define USB_HID_KEY_ARROW_R   0x4F
#define USB_HID_KEY_ARROW_L   0x50
#define USB_HID_KEY_ARROW_D   0x51
#define USB_HID_KEY_ARROW_U   0x52
#define USB_HID_KEY_HOME      0x4A
#define USB_HID_KEY_END       0x4D
#define USB_HID_KEY_PAGEUP    0x4B
#define USB_HID_KEY_PAGEDOWN  0x4E

#define USB_HID_MOD_LCTRL   0x01
#define USB_HID_MOD_LSHIFT  0x02
#define USB_HID_MOD_LALT    0x04
#define USB_HID_MOD_LGUI    0x08
#define USB_HID_MOD_RCTRL   0x10
#define USB_HID_MOD_RSHIFT  0x20
#define USB_HID_MOD_RALT    0x40
#define USB_HID_MOD_RGUI    0x80

typedef enum {
    USB_MODE_HID = 0,
    USB_MODE_CDC,
    USB_MODE_RNDIS,
    USB_MODE_MSC,
    USB_MODE_COMBO,
} usb_mode_t;

esp_err_t usb_engine_init(void);
esp_err_t usb_engine_deinit(void);
usb_mode_t usb_engine_get_mode(void);
esp_err_t usb_engine_set_mode(usb_mode_t mode);

bool usb_engine_is_host_connected(void);

esp_err_t usb_hid_send_keys(uint8_t modifier, uint8_t keycode);
esp_err_t usb_hid_send_string(const char *str);
esp_err_t usb_hid_send_key_with_mods(uint8_t keycode, uint8_t modifier);
esp_err_t usb_hid_press_keys(uint8_t modifier, const uint8_t *keys, int count);
esp_err_t usb_hid_release_all(void);

typedef enum {
    OS_UNKNOWN = 0,
    OS_WINDOWS,
    OS_MACOS,
    OS_LINUX,
} os_type_t;

os_type_t usb_os_fingerprint(void);

esp_err_t usb_ducky_execute(const char *script_path);
esp_err_t usb_ducky_execute_string(const char *script);
esp_err_t usb_ducky_set_default_delay(uint32_t ms);

esp_err_t usb_cdc_write(const char *str);
int      usb_cdc_read(char *buf, int max_len);
bool     usb_cdc_is_connected(void);

esp_err_t usb_msc_start(const char *flash_path);
esp_err_t usb_msc_stop(void);

int char_to_key(char c, uint8_t *code, uint8_t *mod);

int  usb_payload_execute_line(const char *line);
esp_err_t usb_payload_execute_script(const char *script_content);
int  usb_payload_list(char names[][64], int max);
esp_err_t usb_payload_save(const char *name, const char *content);
esp_err_t usb_payload_delete(const char *name);
esp_err_t usb_payload_get(const char *name, char *buf, size_t *len);
