#include "usb_engine.h"
#include "esp_log.h"
#include "tusb.h"
#include <string.h>

static const char *TAG = "USBHID";

static uint8_t s_key_modifier = 0;
static uint8_t s_key_codes[6] = {0};
static int s_key_count = 0;

static const struct { char c; uint8_t code; uint8_t shift; } s_keymap[] = {
    {'a', USB_HID_KEY_A, 0}, {'b', USB_HID_KEY_B, 0}, {'c', USB_HID_KEY_C, 0},
    {'d', USB_HID_KEY_D, 0}, {'e', USB_HID_KEY_E, 0}, {'f', USB_HID_KEY_F, 0},
    {'g', USB_HID_KEY_G, 0}, {'h', USB_HID_KEY_H, 0}, {'i', USB_HID_KEY_I, 0},
    {'j', USB_HID_KEY_J, 0}, {'k', USB_HID_KEY_K, 0}, {'l', USB_HID_KEY_L, 0},
    {'m', USB_HID_KEY_M, 0}, {'n', USB_HID_KEY_N, 0}, {'o', USB_HID_KEY_O, 0},
    {'p', USB_HID_KEY_P, 0}, {'q', USB_HID_KEY_Q, 0}, {'r', USB_HID_KEY_R, 0},
    {'s', USB_HID_KEY_S, 0}, {'t', USB_HID_KEY_T, 0}, {'u', USB_HID_KEY_U, 0},
    {'v', USB_HID_KEY_V, 0}, {'w', USB_HID_KEY_W, 0}, {'x', USB_HID_KEY_X, 0},
    {'y', USB_HID_KEY_Y, 0}, {'z', USB_HID_KEY_Z, 0},
    {'A', USB_HID_KEY_A, USB_HID_MOD_LSHIFT},
    {'B', USB_HID_KEY_B, USB_HID_MOD_LSHIFT},
    {'C', USB_HID_KEY_C, USB_HID_MOD_LSHIFT},
    {'D', USB_HID_KEY_D, USB_HID_MOD_LSHIFT},
    {'E', USB_HID_KEY_E, USB_HID_MOD_LSHIFT},
    {'F', USB_HID_KEY_F, USB_HID_MOD_LSHIFT},
    {'G', USB_HID_KEY_G, USB_HID_MOD_LSHIFT},
    {'H', USB_HID_KEY_H, USB_HID_MOD_LSHIFT},
    {'I', USB_HID_KEY_I, USB_HID_MOD_LSHIFT},
    {'J', USB_HID_KEY_J, USB_HID_MOD_LSHIFT},
    {'K', USB_HID_KEY_K, USB_HID_MOD_LSHIFT},
    {'L', USB_HID_KEY_L, USB_HID_MOD_LSHIFT},
    {'M', USB_HID_KEY_M, USB_HID_MOD_LSHIFT},
    {'N', USB_HID_KEY_N, USB_HID_MOD_LSHIFT},
    {'O', USB_HID_KEY_O, USB_HID_MOD_LSHIFT},
    {'P', USB_HID_KEY_P, USB_HID_MOD_LSHIFT},
    {'Q', USB_HID_KEY_Q, USB_HID_MOD_LSHIFT},
    {'R', USB_HID_KEY_R, USB_HID_MOD_LSHIFT},
    {'S', USB_HID_KEY_S, USB_HID_MOD_LSHIFT},
    {'T', USB_HID_KEY_T, USB_HID_MOD_LSHIFT},
    {'U', USB_HID_KEY_U, USB_HID_MOD_LSHIFT},
    {'V', USB_HID_KEY_V, USB_HID_MOD_LSHIFT},
    {'W', USB_HID_KEY_W, USB_HID_MOD_LSHIFT},
    {'X', USB_HID_KEY_X, USB_HID_MOD_LSHIFT},
    {'Y', USB_HID_KEY_Y, USB_HID_MOD_LSHIFT},
    {'Z', USB_HID_KEY_Z, USB_HID_MOD_LSHIFT},
    {'1', USB_HID_KEY_1, 0}, {'!', USB_HID_KEY_1, USB_HID_MOD_LSHIFT},
    {'2', USB_HID_KEY_2, 0}, {'@', USB_HID_KEY_2, USB_HID_MOD_LSHIFT},
    {'3', USB_HID_KEY_3, 0}, {'#', USB_HID_KEY_3, USB_HID_MOD_LSHIFT},
    {'4', USB_HID_KEY_4, 0}, {'$', USB_HID_KEY_4, USB_HID_MOD_LSHIFT},
    {'5', USB_HID_KEY_5, 0}, {'%', USB_HID_KEY_5, USB_HID_MOD_LSHIFT},
    {'6', USB_HID_KEY_6, 0}, {'^', USB_HID_KEY_6, USB_HID_MOD_LSHIFT},
    {'7', USB_HID_KEY_7, 0}, {'&', USB_HID_KEY_7, USB_HID_MOD_LSHIFT},
    {'8', USB_HID_KEY_8, 0}, {'*', USB_HID_KEY_8, USB_HID_MOD_LSHIFT},
    {'9', USB_HID_KEY_9, 0}, {'(', USB_HID_KEY_9, USB_HID_MOD_LSHIFT},
    {'0', USB_HID_KEY_0, 0}, {')', USB_HID_KEY_0, USB_HID_MOD_LSHIFT},
    {' ', USB_HID_KEY_SPACE, 0},
    {'-', USB_HID_KEY_MINUS, 0}, {'_', USB_HID_KEY_MINUS, USB_HID_MOD_LSHIFT},
    {'=', USB_HID_KEY_EQUAL, 0}, {'+', USB_HID_KEY_EQUAL, USB_HID_MOD_LSHIFT},
    {'[', USB_HID_KEY_BRACKET_L, 0}, {'{', USB_HID_KEY_BRACKET_L, USB_HID_MOD_LSHIFT},
    {']', USB_HID_KEY_BRACKET_R, 0}, {'}', USB_HID_KEY_BRACKET_R, USB_HID_MOD_LSHIFT},
    {'\\',USB_HID_KEY_BACKSLASH, 0},{'|', USB_HID_KEY_BACKSLASH, USB_HID_MOD_LSHIFT},
    {';', USB_HID_KEY_SEMICOLON, 0},{':', USB_HID_KEY_SEMICOLON, USB_HID_MOD_LSHIFT},
    {'\'',USB_HID_KEY_QUOTE, 0},     {'"', USB_HID_KEY_QUOTE, USB_HID_MOD_LSHIFT},
    {'`', USB_HID_KEY_GRAVE, 0},     {'~', USB_HID_KEY_GRAVE, USB_HID_MOD_LSHIFT},
    {',', USB_HID_KEY_COMMA, 0},     {'<', USB_HID_KEY_COMMA, USB_HID_MOD_LSHIFT},
    {'.', USB_HID_KEY_DOT, 0},       {'>', USB_HID_KEY_DOT, USB_HID_MOD_LSHIFT},
    {'/', USB_HID_KEY_SLASH, 0},     {'?', USB_HID_KEY_SLASH, USB_HID_MOD_LSHIFT},
    {'\n', USB_HID_KEY_ENTER, 0},    {'\t', USB_HID_KEY_TAB, 0},
};

int char_to_key(char c, uint8_t *code, uint8_t *mod)
{
    for (int i = 0; i < sizeof(s_keymap) / sizeof(s_keymap[0]); i++) {
        if (s_keymap[i].c == c) {
            *code = s_keymap[i].code;
            *mod = s_keymap[i].shift;
            return 1;
        }
    }
    return 0;
}

esp_err_t usb_hid_send_keys(uint8_t modifier, uint8_t keycode)
{
    return usb_hid_press_keys(modifier, &keycode, 1);
}

esp_err_t usb_hid_send_key_with_mods(uint8_t keycode, uint8_t modifier)
{
    s_key_modifier = modifier;
    s_key_codes[0] = keycode;
    s_key_count = 1;
    tud_hid_keyboard_report(0, s_key_modifier, s_key_codes);
    vTaskDelay(pdMS_TO_TICKS(10));
    usb_hid_release_all();
    return ESP_OK;
}

esp_err_t usb_hid_press_keys(uint8_t modifier, const uint8_t *keys, int count)
{
    if (!tud_hid_ready()) return ESP_FAIL;

    uint8_t codes[6] = {0};
    int copy = count < 6 ? count : 6;
    memcpy(codes, keys, copy);
    tud_hid_keyboard_report(0, modifier, codes);
    return ESP_OK;
}

esp_err_t usb_hid_release_all(void)
{
    uint8_t empty[6] = {0};
    tud_hid_keyboard_report(0, 0, empty);
    return ESP_OK;
}

esp_err_t usb_hid_send_string(const char *str)
{
    if (!str) return ESP_ERR_INVALID_ARG;

    for (int i = 0; str[i]; i++) {
        uint8_t code = 0, mod = 0;
        if (char_to_key(str[i], &code, &mod)) {
            s_key_modifier = mod;
            s_key_codes[0] = code;
            tud_hid_keyboard_report(0, s_key_modifier, s_key_codes);
            vTaskDelay(pdMS_TO_TICKS(15));
            usb_hid_release_all();
            vTaskDelay(pdMS_TO_TICKS(10));
        } else {
            ESP_LOGW(TAG, "Unknown char: '%c' (0x%02X)", str[i], str[i]);
        }
    }
    return ESP_OK;
}
