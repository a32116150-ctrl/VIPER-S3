#include "ble_engine.h"
#include "esp_log.h"
#include "string.h"
#include "stdlib.h"

static const char *TAG = "BLEPROP";

#define MAX_PROPRIETARY_DEVICES 32

typedef struct {
    uint8_t  addr[6];
    bool     present;
    char     type[32];
    struct {
        uint32_t seq;
        uint8_t  battery;
        bool     battery_present;
    } tile;
    struct {
        uint8_t  protocol;
        uint32_t tag_id;
        bool     encrypted;
    } samsung;
    struct {
        uint8_t  status;
        uint8_t  battery;
    } find_my;
    struct {
        uint8_t  version;
        char     model[32];
        uint8_t  battery_level;
        bool     battery_present;
    } swift_pair;
    struct {
        uint8_t  battery_left;
        uint8_t  battery_right;
        uint8_t  battery_case;
        bool     is_apple;
    } apple;
} proprietary_entry_t;

static proprietary_entry_t s_entries[MAX_PROPRIETARY_DEVICES];
static int s_entry_count = 0;

static int find_or_add_prop(const uint8_t *addr)
{
    for (int i = 0; i < s_entry_count; i++) {
        if (memcmp(s_entries[i].addr, addr, 6) == 0) return i;
    }
    if (s_entry_count >= MAX_PROPRIETARY_DEVICES) return -1;
    int idx = s_entry_count++;
    memset(&s_entries[idx], 0, sizeof(proprietary_entry_t));
    memcpy(s_entries[idx].addr, addr, 6);
    return idx;
}

static void decode_tile(const uint8_t *data, uint8_t len, proprietary_entry_t *e)
{
    if (len < 6) return;
    uint16_t company = data[0] | (data[1] << 8);

    if ((company == 0x00D7 || company == 0x00D8) && len >= 8) {
        snprintf(e->type, sizeof(e->type), "Tile");
        e->tile.seq = (data[4] << 16) | (data[5] << 8) | data[6];
        e->present = true;
    }

    if (company == 0x004C && len >= 10 && data[4] == 0x10) {
        snprintf(e->type, sizeof(e->type), "Tile (Apple Find My)");
        e->tile.seq = (data[5] << 16) | (data[6] << 8) | data[7];
        e->tile.battery = data[8] & 0x7F;
        e->tile.battery_present = true;
        e->present = true;
    }
}

static void decode_samsung_smarttag(const uint8_t *data, uint8_t len, proprietary_entry_t *e)
{
    if (len < 8) return;
    uint16_t company = data[0] | (data[1] << 8);
    if (company != 0x0075) return;

    uint8_t protocol = data[4];
    switch (protocol) {
        case 0x01: snprintf(e->type, sizeof(e->type), "Samsung SmartTag"); break;
        case 0x02: snprintf(e->type, sizeof(e->type), "Samsung SmartTag+"); break;
        case 0x03: snprintf(e->type, sizeof(e->type), "Samsung FamilyTag"); break;
        case 0x05: snprintf(e->type, sizeof(e->type), "Samsung Galaxy Buds"); break;
        default:   snprintf(e->type, sizeof(e->type), "Samsung(0x%02X)", protocol); break;
    }

    e->samsung.protocol = protocol;
    e->samsung.encrypted = (len > 10);
    if (len >= 12) {
        e->samsung.tag_id = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
    }
    e->present = true;
}

static void decode_apple_findmy(const uint8_t *data, uint8_t len, proprietary_entry_t *e)
{
    if (len < 10) return;
    uint16_t company = data[0] | (data[1] << 8);
    if (company != 0x004C) return;

    uint8_t adv_type = data[4];
    if (adv_type == 0x0F || adv_type == 0x10) {
        e->present = true;
        e->find_my.status = data[5];
        e->find_my.battery = data[6];
        snprintf(e->type, sizeof(e->type), "Apple FindMy (%s)",
                 adv_type == 0x0F ? "nearby" : "offline");
    }
}

static void decode_apple_continuity(const uint8_t *data, uint8_t len, proprietary_entry_t *e)
{
    if (len < 6) return;
    uint16_t company = data[0] | (data[1] << 8);
    if (company != 0x004C) return;

    uint8_t adv_type = data[4];
    switch (adv_type) {
        case 0x05: snprintf(e->type, sizeof(e->type), "Apple AirDrop"); break;
        case 0x07:
            snprintf(e->type, sizeof(e->type), "Apple AirPods");
            if (len >= 10) { e->apple.battery_left = data[7]; e->apple.battery_right = data[8]; e->apple.battery_case = data[9]; }
            break;
        case 0x09:
            snprintf(e->type, sizeof(e->type), "Apple AirPods Pro");
            if (len >= 10) { e->apple.battery_left = data[6]; e->apple.battery_right = data[7]; e->apple.battery_case = data[8]; }
            break;
        case 0x0A: snprintf(e->type, sizeof(e->type), "Apple AirPods Max"); break;
        case 0x0B: snprintf(e->type, sizeof(e->type), "Apple HomePod"); break;
        case 0x0C: snprintf(e->type, sizeof(e->type), "Apple Watch"); break;
        case 0x0E: snprintf(e->type, sizeof(e->type), "Apple TV"); break;
        case 0x12: snprintf(e->type, sizeof(e->type), "Apple Handoff"); break;
        case 0x13: snprintf(e->type, sizeof(e->type), "Apple Tethering"); break;
        case 0x15: snprintf(e->type, sizeof(e->type), "Apple Nearby"); break;
        default:   snprintf(e->type, sizeof(e->type), "Apple(0x%02X)", adv_type); break;
    }
    e->apple.is_apple = true;
    e->present = true;
}

static void decode_swiftpair(const uint8_t *data, uint8_t len, proprietary_entry_t *e)
{
    if (len < 6) return;
    uint16_t company = data[0] | (data[1] << 8);
    if (company != 0x0006 && company != 0x00F2) return;

    uint8_t frame_type = data[4];
    switch (frame_type) {
        case 0x00: snprintf(e->type, sizeof(e->type), "MS SwiftPair"); break;
        case 0x01:
            snprintf(e->type, sizeof(e->type), "MS SwiftPair (setup)");
            if (len >= 14) {
                int ml = (len - 6) < 31 ? (len - 6) : 31;
                memcpy(e->swift_pair.model, data + 6, ml);
                e->swift_pair.model[ml] = '\0';
            }
            break;
        case 0x02:
            snprintf(e->type, sizeof(e->type), "MS SwiftPair (battery)");
            if (len >= 7) { e->swift_pair.battery_level = data[5]; e->swift_pair.battery_present = true; }
            break;
        case 0x03: snprintf(e->type, sizeof(e->type), "MS SwiftPair (device info)"); break;
        default:   snprintf(e->type, sizeof(e->type), "MS SwiftPair(0x%02X)", frame_type); break;
    }
    e->present = true;
}

void ble_scan_proprietary_feed(const uint8_t *addr, uint16_t manufacturer,
                                const uint8_t *manuf_data, uint8_t field_len)
{
    if (!addr || !manuf_data || field_len == 0) return;

    int idx = find_or_add_prop(addr);
    if (idx < 0) return;

    proprietary_entry_t *e = &s_entries[idx];

    decode_tile(manuf_data, field_len, e);
    if (!e->present) decode_samsung_smarttag(manuf_data, field_len, e);
    if (!e->present) decode_apple_findmy(manuf_data, field_len, e);
    if (!e->present) decode_apple_continuity(manuf_data, field_len, e);
    if (!e->present) decode_swiftpair(manuf_data, field_len, e);
}

int ble_scan_proprietary_get_results(proprietary_scan_result_t *results, int max)
{
    if (!results || max <= 0) return 0;

    int count = 0;
    for (int i = 0; i < s_entry_count && count < max; i++) {
        if (!s_entries[i].present) continue;

        proprietary_scan_result_t *r = &results[count];
        strncpy(r->type, s_entries[i].type, sizeof(r->type) - 1);

        r->has_battery = s_entries[i].tile.battery_present ||
                         s_entries[i].swift_pair.battery_present ||
                         s_entries[i].find_my.battery > 0;
        r->battery_level = s_entries[i].tile.battery > 0 ?
                           s_entries[i].tile.battery : s_entries[i].swift_pair.battery_level;
        if (r->battery_level == 0 && s_entries[i].find_my.battery > 0)
            r->battery_level = s_entries[i].find_my.battery;

        r->is_apple = s_entries[i].apple.is_apple;
        r->is_samsung = (s_entries[i].samsung.protocol > 0);
        r->is_tile = (strstr(s_entries[i].type, "Tile") != NULL);
        r->is_findmy = (strstr(s_entries[i].type, "FindMy") != NULL);
        r->is_swiftpair = (strstr(s_entries[i].type, "SwiftPair") != NULL);

        count++;
    }

    return count;
}

void ble_scan_proprietary_clear(void)
{
    s_entry_count = 0;
    memset(s_entries, 0, sizeof(s_entries));
}

int ble_scan_proprietary_get_count(void)
{
    int c = 0;
    for (int i = 0; i < s_entry_count; i++) {
        if (s_entries[i].present) c++;
    }
    return c;
}
