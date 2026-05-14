#include "usb_engine.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>

static const char *TAG = "PAYLOAD";

#define PAYLOAD_DIR DIR_PAYLOADS
#define MAX_PAYLOADS 32

static uint32_t s_default_delay = 0;
static int s_repeat_count = 0;

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
    {"ESCAPE",     USB_HID_KEY_ESC,       0},
    {"DELETE",     USB_HID_KEY_DELETE,    0},
    {"BACKSPACE",  USB_HID_KEY_BACKSPACE, 0},
    {"HOME",       USB_HID_KEY_HOME,      0},
    {"END",        USB_HID_KEY_END,       0},
    {"PAGEUP",     USB_HID_KEY_PAGEUP,    0},
    {"PAGEDOWN",   USB_HID_KEY_PAGEDOWN,  0},
    {"UP",         USB_HID_KEY_ARROW_U,   0},
    {"UPARROW",    USB_HID_KEY_ARROW_U,   0},
    {"DOWN",       USB_HID_KEY_ARROW_D,   0},
    {"DOWNARROW",  USB_HID_KEY_ARROW_D,   0},
    {"LEFT",       USB_HID_KEY_ARROW_L,   0},
    {"LEFTARROW",  USB_HID_KEY_ARROW_L,   0},
    {"RIGHT",      USB_HID_KEY_ARROW_R,   0},
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
    {"PRINTSCREEN",0x46,                  0},
    {"SCROLLLOCK", 0x47,                  0},
    {"PAUSE",      0x48,                  0},
    {"INSERT",     0x49,                  0},
    {"MENU",       0x65,                  0},
};

static const struct {
    const char *name;
    uint8_t mod;
} s_mods[] = {
    {"CTRL",    USB_HID_MOD_LCTRL},
    {"CONTROL", USB_HID_MOD_LCTRL},
    {"GUI",     USB_HID_MOD_LGUI},
    {"WINDOWS", USB_HID_MOD_LGUI},
    {"COMMAND", USB_HID_MOD_LGUI},
    {"ALT",     USB_HID_MOD_LALT},
    {"SHIFT",   USB_HID_MOD_LSHIFT},
    {"RCTRL",   USB_HID_MOD_RCTRL},
    {"RSHIFT",  USB_HID_MOD_RSHIFT},
    {"RALT",    USB_HID_MOD_RALT},
    {"RGUI",    USB_HID_MOD_RGUI},
    {"APPLE",   USB_HID_MOD_LGUI},
};

static int parse_keyword(const char *word, uint8_t *code, uint8_t *mod)
{
    for (int i = 0; i < sizeof(s_keywords) / sizeof(s_keywords[0]); i++) {
        if (strcasecmp(word, s_keywords[i].name) == 0) {
            *code = s_keywords[i].keycode; *mod = s_keywords[i].modifier;
            return 1;
        }
    }
    return 0;
}

static int parse_modifier(const char *word)
{
    for (int i = 0; i < sizeof(s_mods) / sizeof(s_mods[0]); i++) {
        if (strcasecmp(word, s_mods[i].name) == 0) return s_mods[i].mod;
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

static void type_string(const char *str)
{
    usb_hid_send_string(str);
}

static void press_combination(const char *line)
{
    char buf[128];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    uint8_t modifiers = 0;
    uint8_t final_key = 0;
    uint8_t final_mod = 0;
    bool has_key = false;

    char *save;
    char *part = strtok_r(buf, " \t-", &save);
    while (part) {
        uint8_t m = parse_modifier(part);
        if (m && !has_key) {
            modifiers |= m;
        } else if (parse_keyword(part, &final_key, &final_mod)) {
            has_key = true;
            modifiers |= final_mod;
        } else if (strlen(part) == 1) {
            uint8_t code, mod;
            if (char_to_key(part[0], &code, &mod)) {
                final_key = code; modifiers |= mod; has_key = true;
            }
        }
        part = strtok_r(NULL, " \t-", &save);
    }

    if (has_key) {
        usb_hid_send_key_with_mods(final_key, modifiers);
    } else if (modifiers) {
        usb_hid_send_key_with_mods(USB_HID_KEY_NONE, modifiers);
    }
}

int usb_payload_execute_line(const char *line)
{
    char buf[256];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    trim(buf);
    if (buf[0] == '\0' || buf[0] == '#') return 0;

    if (strncasecmp(buf, "STRING ", 7) == 0) {
        type_string(buf + 7);
        return 1;
    }

    if (strncasecmp(buf, "STRINGLN ", 9) == 0) {
        type_string(buf + 9);
        usb_hid_send_key_with_mods(USB_HID_KEY_ENTER, 0);
        return 1;
    }

    if (strncasecmp(buf, "DELAY ", 6) == 0) {
        int ms = atoi(buf + 6);
        if (ms > 0 && ms < 60000) vTaskDelay(pdMS_TO_TICKS(ms));
        return 1;
    }

    if (strncasecmp(buf, "DELAY", 5) == 0 && strlen(buf) == 5) {
        vTaskDelay(pdMS_TO_TICKS(s_default_delay > 0 ? s_default_delay : 100));
        return 1;
    }

    if (strncasecmp(buf, "DEFAULTDELAY ", 13) == 0 ||
        strncasecmp(buf, "DEFAULT_DELAY ", 14) == 0) {
        const char *val = strchr(buf, ' ');
        if (val) {
            s_default_delay = atoi(val + 1);
            ESP_LOGI(TAG, "Default delay set to %lu ms", s_default_delay);
        }
        return 1;
    }

    if (strncasecmp(buf, "REPEAT ", 7) == 0) {
        s_repeat_count = atoi(buf + 7);
        ESP_LOGI(TAG, "REPEAT count: %d", s_repeat_count);
        return s_repeat_count;
    }

    if (strncasecmp(buf, "REPLAY ", 7) == 0) {
        int count = atoi(buf + 7);
        usb_ducky_execute("/viper/payloads/last_captured.txt");
        return 1;
    }

    if (strncasecmp(buf, "WAIT_FOR_WINDOW ", 16) == 0) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        return 1;
    }

    if (strncasecmp(buf, "ALT-END", 7) == 0) {
        usb_hid_send_key_with_mods(USB_HID_KEY_END, USB_HID_MOD_LALT);
        return 1;
    }

    if (strncasecmp(buf, "ALT-F4", 6) == 0) {
        usb_hid_send_key_with_mods(USB_HID_KEY_F4, USB_HID_MOD_LALT);
        return 1;
    }

    if (strncasecmp(buf, "ALT-TAB", 7) == 0) {
        usb_hid_send_key_with_mods(USB_HID_KEY_TAB, USB_HID_MOD_LALT);
        return 1;
    }

    if (strncasecmp(buf, "CTRL-ALT-DEL", 12) == 0) {
        usb_hid_send_key_with_mods(USB_HID_KEY_DELETE, USB_HID_MOD_LCTRL | USB_HID_MOD_LALT);
        return 1;
    }

    if (strncasecmp(buf, "GUI-R", 5) == 0 || strncasecmp(buf, "WINDOWS-R", 9) == 0) {
        usb_hid_send_key_with_mods(USB_HID_KEY_R, USB_HID_MOD_LGUI);
        return 1;
    }

    if (strncasecmp(buf, "GUI-L", 5) == 0) {
        usb_hid_send_key_with_mods(USB_HID_KEY_L, USB_HID_MOD_LGUI);
        return 1;
    }

    press_combination(buf);
    return 1;
}

esp_err_t usb_payload_execute_script(const char *script_content)
{
    if (!script_content) return ESP_ERR_INVALID_ARG;

    const char *p = script_content;
    char line[256];
    int li = 0;
    char repeat_line[256] = {0};

    s_repeat_count = 0;

    while (*p) {
        if (*p == '\n' || li >= 255) {
            line[li] = '\0';
            int r = usb_payload_execute_line(line);

            if (r > 1 && repeat_line[0]) {
                for (int i = 0; i < r - 1; i++) {
                    usb_payload_execute_line(repeat_line);
                }
                repeat_line[0] = '\0';
            } else if (r == 0) {
                strncpy(repeat_line, line, sizeof(repeat_line) - 1);
            }

            li = 0;
        } else if (*p != '\r') {
            line[li++] = *p;
        }
        p++;
    }
    if (li > 0) {
        line[li] = '\0';
        usb_payload_execute_line(line);
    }

    return ESP_OK;
}

int usb_payload_list(char names[][64], int max)
{
    DIR *dir = opendir(PAYLOAD_DIR);
    if (!dir) return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && count < max) {
        if (entry->d_type == DT_REG) {
            strncpy(names[count], entry->d_name, 63);
            names[count][63] = '\0';
            count++;
        }
    }
    closedir(dir);
    return count;
}

esp_err_t usb_payload_save(const char *name, const char *content)
{
    if (!name || !content) return ESP_ERR_INVALID_ARG;

    char path[64];
    snprintf(path, sizeof(path), PAYLOAD_DIR "/%s", name);

    ESP_LOGI(TAG, "Saving payload: %s", path);
    return storage_write_file(path, (uint8_t *)content, strlen(content), false);
}

esp_err_t usb_payload_delete(const char *name)
{
    if (!name) return ESP_ERR_INVALID_ARG;

    char path[64];
    snprintf(path, sizeof(path), PAYLOAD_DIR "/%s", name);

    ESP_LOGI(TAG, "Deleting payload: %s", path);
    return storage_delete_file(path);
}

esp_err_t usb_payload_get(const char *name, char *buf, size_t *len)
{
    if (!name || !buf || !len) return ESP_ERR_INVALID_ARG;

    char path[64];
    snprintf(path, sizeof(path), PAYLOAD_DIR "/%s", name);

    return storage_read_file(path, (uint8_t *)buf, *len, len);
}
