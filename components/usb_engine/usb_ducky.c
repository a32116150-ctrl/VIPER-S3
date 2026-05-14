#include "usb_engine.h"
#include "storage_manager.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "DUCKY";

static uint32_t s_default_delay = 0;

typedef struct {
    const char *name;
    uint8_t keycode;
    uint8_t modifier;
} ducky_keyword_t;

static const ducky_keyword_t s_keywords[] = {
    {"ENTER",      USB_HID_KEY_ENTER,     0},
    {"SPACE",      USB_HID_KEY_SPACE,     0},
    {"TAB",        USB_HID_KEY_TAB,       0},
    {"ESC",        USB_HID_KEY_ESC,       0},
    {"DELETE",     USB_HID_KEY_DELETE,    0},
    {"BACKSPACE",  USB_HID_KEY_BACKSPACE, 0},
    {"HOME",       USB_HID_KEY_HOME,      0},
    {"END",        USB_HID_KEY_END,       0},
    {"PAGEUP",     USB_HID_KEY_PAGEUP,    0},
    {"PAGEDOWN",   USB_HID_KEY_PAGEDOWN,  0},
    {"UPARROW",    USB_HID_KEY_ARROW_U,   0},
    {"DOWNARROW",  USB_HID_KEY_ARROW_D,   0},
    {"LEFTARROW",  USB_HID_KEY_ARROW_L,   0},
    {"RIGHTARROW", USB_HID_KEY_ARROW_R,   0},
    {"F1",         USB_HID_KEY_F1,        0},
    {"F2",         USB_HID_KEY_F2,        0},
    {"F3",         USB_HID_KEY_F3,        0},
    {"F4",         USB_HID_KEY_F4,        0},
    {"F5",         USB_HID_KEY_F5,        0},
    {"F6",         USB_HID_KEY_F6,        0},
    {"F7",         USB_HID_KEY_F7,        0},
    {"F8",         USB_HID_KEY_F8,        0},
    {"F9",         USB_HID_KEY_F9,        0},
    {"F10",        USB_HID_KEY_F10,       0},
    {"F11",        USB_HID_KEY_F11,       0},
    {"F12",        USB_HID_KEY_F12,       0},
    {"CAPSLOCK",   USB_HID_KEY_CAPS,      0},
};

static const struct {
    const char *name;
    uint8_t mod;
} s_mods[] = {
    {"CTRL",  USB_HID_MOD_LCTRL},
    {"GUI",   USB_HID_MOD_LGUI},
    {"ALT",   USB_HID_MOD_LALT},
    {"SHIFT", USB_HID_MOD_LSHIFT},
    {"CONTROL", USB_HID_MOD_LCTRL},
    {"WINDOWS", USB_HID_MOD_LGUI},
    {"COMMAND", USB_HID_MOD_LGUI},
};

static int parse_keyword(const char *word, uint8_t *code, uint8_t *mod)
{
    for (int i = 0; i < sizeof(s_keywords) / sizeof(s_keywords[0]); i++) {
        if (strcasecmp(word, s_keywords[i].name) == 0) {
            *code = s_keywords[i].keycode;
            *mod = s_keywords[i].modifier;
            return 1;
        }
    }
    return 0;
}

static int parse_modifier(const char *word)
{
    for (int i = 0; i < sizeof(s_mods) / sizeof(s_mods[0]); i++) {
        if (strcasecmp(word, s_mods[i].name) == 0) {
            return s_mods[i].mod;
        }
    }
    return 0;
}

static void trim(char *s)
{
    char *start = s;
    while (*start == ' ' || *start == '\t') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == ' ' || *end == '\t' || *end == '\r')) end--;
    *(end + 1) = '\0';
    if (start != s) memmove(s, start, strlen(start) + 1);
}

static int execute_line(const char *line)
{
    char buf[256];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *save = NULL;
    char *cmd = strtok_r(buf, " \t", &save);
    if (!cmd || cmd[0] == '\0' || cmd[0] == '#') return 0;

    uint8_t modifiers = 0;
    char *mods[4];
    int mod_count = 0;
    char *token = cmd;
    bool has_key = false;
    uint8_t final_key = 0;
    uint8_t final_mod = 0;

    char *rest = cmd;
    while (1) {
        char *part = strtok_r(rest, " \t-", &save);
        if (!part) break;
        rest = NULL;

        if (!has_key) {
            uint8_t m = parse_modifier(part);
            if (m) {
                modifiers |= m;
                continue;
            }
        }

        if (parse_keyword(part, &final_key, &final_mod)) {
            has_key = true;
            modifiers |= final_mod;
        }
    }

    if (has_key) {
        usb_hid_send_key_with_mods(final_key, modifiers);
        if (s_default_delay > 0) vTaskDelay(pdMS_TO_TICKS(s_default_delay));
    } else if (modifiers) {
        usb_hid_send_key_with_mods(USB_HID_KEY_NONE, modifiers);
    }

    return 0;
}

esp_err_t usb_ducky_execute(const char *script_path)
{
    FILE *f = fopen(script_path, "r");
    if (!f) {
        ESP_LOGE(TAG, "Script not found: %s", script_path);
        return ESP_ERR_NOT_FOUND;
    }

    ESP_LOGI(TAG, "Executing Ducky Script: %s", script_path);

    char line[256];
    int repeat_count = 0;
    char repeat_line[256] = {0};

    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        int r = execute_line(line);
        if (r > 0 && repeat_line[0]) {
            for (int i = 0; i < r; i++) {
                execute_line(repeat_line);
            }
            repeat_line[0] = '\0';
        } else if (r == 0) {
            strncpy(repeat_line, line, sizeof(repeat_line) - 1);
        }
    }

    fclose(f);
    ESP_LOGI(TAG, "Script complete: %s", script_path);
    return ESP_OK;
}

esp_err_t usb_ducky_execute_string(const char *script)
{
    if (!script) return ESP_ERR_INVALID_ARG;

    ESP_LOGI(TAG, "Executing inline Ducky Script");

    const char *p = script;
    char line[256];
    int li = 0;

    while (*p) {
        if (*p == '\n' || li >= 255) {
            line[li] = '\0';
            trim(line);
            if (line[0] && line[0] != '#') execute_line(line);
            li = 0;
        } else if (*p != '\r') {
            line[li++] = *p;
        }
        p++;
    }
    if (li > 0) {
        line[li] = '\0';
        trim(line);
        if (line[0] && line[0] != '#') execute_line(line);
    }

    return ESP_OK;
}

esp_err_t usb_ducky_set_default_delay(uint32_t ms)
{
    s_default_delay = ms;
    return ESP_OK;
}
