#include "ble_engine.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "BLESCAN";

static ble_device_t s_devices[BLE_MAX_DEVICES];
static int s_device_count = 0;
static bool s_scanning = false;
static uint64_t s_scan_start = 0;

static const struct {
    uint16_t company;
    const char *name;
} s_company_ids[] = {
    {0x004C, "Apple"},
    {0x00E0, "Google"},
    {0x0006, "Microsoft"},
    {0x0075, "Samsung"},
    {0x000A, "BlueRadios"},
    {0x001D, "Nordic"},
    {0x0002, "Intel"},
    {0x0060, "Huawei"},
    {0x00F0, "Xiaomi"},
    {0x0059, "Bose"},
    {0x006B, "Sony"},
};

static const char *lookup_company(uint16_t company_id)
{
    for (int i = 0; i < sizeof(s_company_ids) / sizeof(s_company_ids[0]); i++) {
        if (s_company_ids[i].company == company_id)
            return s_company_ids[i].name;
    }
    return "Unknown";
}

static void decode_apple_adv(const uint8_t *data, uint8_t len, ble_device_t *dev)
{
    if (len < 3) return;
    uint8_t msg_type = data[2];

    switch (msg_type) {
        case 0x05: snprintf(dev->device_type, sizeof(dev->device_type), "Apple AirDrop"); break;
        case 0x07: snprintf(dev->device_type, sizeof(dev->device_type), "Apple AirPods"); break;
        case 0x09: snprintf(dev->device_type, sizeof(dev->device_type), "Apple AirPods Pro"); break;
        case 0x0A: snprintf(dev->device_type, sizeof(dev->device_type), "Apple AirPods Max"); break;
        case 0x0B: snprintf(dev->device_type, sizeof(dev->device_type), "Apple HomePod"); break;
        case 0x0C: snprintf(dev->device_type, sizeof(dev->device_type), "Apple Watch"); break;
        case 0x0E: snprintf(dev->device_type, sizeof(dev->device_type), "Apple TV"); break;
        case 0x12: snprintf(dev->device_type, sizeof(dev->device_type), "Apple Handoff"); break;
        case 0x13: snprintf(dev->device_type, sizeof(dev->device_type), "Apple Tethering"); break;
        case 0x15: snprintf(dev->device_type, sizeof(dev->device_type), "Apple Nearby"); break;
        default:   snprintf(dev->device_type, sizeof(dev->device_type), "Apple(0x%02X)", msg_type); break;
    }
}

static void decode_beacon(const uint8_t *data, uint8_t len, ble_device_t *dev)
{
    if (len >= 23 && data[2] == 0x02 && data[3] == 0x15) {
        snprintf(dev->device_type, sizeof(dev->device_type), "iBeacon");
        dev->is_ibeacon = true;
        return;
    }

    if (len >= 12 && data[2] == 0x00 && data[3] == 0x00) {
        snprintf(dev->device_type, sizeof(dev->device_type), "Eddystone");
        uint8_t frame_type = data[4];
        if (frame_type == 0x00) strcat(dev->device_type, " UID");
        else if (frame_type == 0x10) strcat(dev->device_type, " URL");
        else if (frame_type == 0x20) strcat(dev->device_type, " TLM");
    }
}

static void decode_google_fastpair(const uint8_t *data, uint8_t len, ble_device_t *dev)
{
    (void)data;
    (void)len;
    snprintf(dev->device_type, sizeof(dev->device_type), "Google FastPair");
}

static int find_or_add_device(const uint8_t *addr)
{
    for (int i = 0; i < s_device_count; i++) {
        if (memcmp(s_devices[i].addr, addr, 6) == 0) return i;
    }
    if (s_device_count >= BLE_MAX_DEVICES) return -1;
    memset(&s_devices[s_device_count], 0, sizeof(ble_device_t));
    memcpy(s_devices[s_device_count].addr, addr, 6);
    return s_device_count++;
}

static uint8_t *find_adv_field(uint8_t type, const uint8_t *data, uint8_t len, uint8_t *field_len)
{
    int off = 0;
    while (off < len) {
        uint8_t flen = data[off];
        if (flen == 0) break;
        if (off + flen >= len) break;
        if (data[off + 1] == type) {
            *field_len = flen - 1;
            return (uint8_t *)&data[off + 2];
        }
        off += flen + 1;
    }
    *field_len = 0;
    return NULL;
}

static int ble_gap_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
        case BLE_GAP_EVENT_DISC: {
            struct ble_gap_disc_desc *d = &event->disc;
            int idx = find_or_add_device(d->addr.val);
            if (idx < 0) return 0;

            ble_device_t *dev = &s_devices[idx];
            dev->rssi = d->rssi;

            uint8_t field_len = 0;
            uint8_t *name = find_adv_field(BLE_HS_ADV_TYPE_FULL_NAME,
                                            d->data, d->length_data, &field_len);
            if (!name)
                name = find_adv_field(BLE_HS_ADV_TYPE_SHORT_NAME,
                                      d->data, d->length_data, &field_len);
            if (name && field_len > 0) {
                int copy = field_len < BLE_DEVICE_NAME_MAX - 1 ? field_len : BLE_DEVICE_NAME_MAX - 1;
                memcpy(dev->name, name, copy);
                dev->name[copy] = '\0';
            }

            uint8_t *manuf_data = find_adv_field(BLE_HS_ADV_TYPE_MFG_DATA,
                                                  d->data, d->length_data, &field_len);
            if (manuf_data && field_len >= 2) {
                dev->manufacturer = manuf_data[0] | (manuf_data[1] << 8);

                ble_scan_proprietary_feed(d->addr.val, dev->manufacturer, manuf_data, field_len);
                snprintf(dev->device_type, sizeof(dev->device_type), "%s",
                         lookup_company(dev->manufacturer));

                memcpy(dev->adv_data, manuf_data, field_len < 64 ? field_len : 64);
                dev->adv_data_len = field_len < 64 ? field_len : 64;

                if (dev->manufacturer == 0x004C) {
                    dev->is_apple = true;
                    if (field_len >= 3) decode_apple_adv(manuf_data, field_len, dev);
                    if (field_len >= 23) decode_beacon(manuf_data, field_len, dev);
                }
                if (dev->manufacturer == 0x00E0) {
                    dev->is_google = true;
                    decode_google_fastpair(manuf_data, field_len, dev);
                }
            }

            uint16_t *uuids = d->uuids16;
            int uuid_count = d->uuids16_length / 2;
            for (int i = 0; i < uuid_count && dev->service_count < 4; i++) {
                dev->service_uuids[dev->service_count++] = uuids[i];
            }

            break;
        }
        case BLE_GAP_EVENT_DISC_COMPLETE: {
            ESP_LOGI(TAG, "Scan complete: %d devices found", s_device_count);
            s_scanning = false;
            break;
        }
        default:
            break;
    }
    return 0;
}

esp_err_t ble_scanner_start(uint32_t duration_ms)
{
    if (s_scanning) return ESP_OK;

    uint8_t own_addr_type;
    ble_hs_id_infer_auto(0, &own_addr_type);

    struct ble_gap_disc_params params = {
        .itvl = 200,
        .window = 60,
        .filter_policy = 0,
        .limited = 0,
        .passive = 1,
    };

    int rc = ble_gap_disc(own_addr_type, duration_ms, ble_gap_event_cb, &params);
    if (rc != 0) {
        ESP_LOGE(TAG, "Scan start failed: %d", rc);
        return ESP_FAIL;
    }

    s_scanning = true;
    s_scan_start = esp_timer_get_time();
    ESP_LOGI(TAG, "BLE scanner started (%lu ms)", (unsigned long)duration_ms);
    return ESP_OK;
}

esp_err_t ble_scanner_stop(void)
{
    if (!s_scanning) return ESP_OK;
    ble_gap_disc_cancel();
    s_scanning = false;
    ESP_LOGI(TAG, "BLE scanner stopped: %d devices", s_device_count);
    return ESP_OK;
}

int ble_scanner_get_count(void) { return s_device_count; }

int ble_scanner_get_results(ble_device_t *devices, int max)
{
    int copy = max < s_device_count ? max : s_device_count;
    memcpy(devices, s_devices, copy * sizeof(ble_device_t));
    return copy;
}

esp_err_t ble_scanner_clear(void)
{
    s_device_count = 0;
    return ESP_OK;
}
