#include "wifi_engine.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_rom_sys.h"
#include "storage_manager.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "SCANNER";

static viper_ap_t s_scan_results[WIFI_MAX_SCAN_RESULTS];
static uint16_t s_scan_count = 0;

static viper_client_t s_client_list[WIFI_MAX_CLIENTS];
static uint16_t s_client_count = 0;

static bool s_scanning = false;

static const char *oui_lookup(const uint8_t *mac)
{
    static char vendor[32] = {0};
    uint32_t oui = ((uint32_t)mac[0] << 16) | ((uint32_t)mac[1] << 8) | mac[2];
    switch (oui) {
        case 0x00037F: snprintf(vendor, sizeof(vendor), "Cisco"); break;
        case 0x0050F2: snprintf(vendor, sizeof(vendor), "Microsoft"); break;
        case 0x00904C: snprintf(vendor, sizeof(vendor), "Atheros"); break;
        case 0x002128: snprintf(vendor, sizeof(vendor), "Broadcom"); break;
        case 0x3C5A37: snprintf(vendor, sizeof(vendor), "Intel"); break;
        case 0x005A04: snprintf(vendor, sizeof(vendor), "Apple"); break;
        case 0x001122: snprintf(vendor, sizeof(vendor), "Espressif"); break;
        case 0xAC9E17: snprintf(vendor, sizeof(vendor), "Samsung"); break;
        case 0xF4F5D8: snprintf(vendor, sizeof(vendor), "Xiaomi"); break;
        case 0xA42B8C: snprintf(vendor, sizeof(vendor), "TP-Link"); break;
        default: snprintf(vendor, sizeof(vendor), "Unknown"); break;
    }
    return vendor;
}

static void update_client_list(void)
{
    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) {
        s_client_count = sta_list.num;
        for (int i = 0; i < sta_list.num && i < WIFI_MAX_CLIENTS; i++) {
            memcpy(s_client_list[i].mac, sta_list.sta[i].mac, 6);
            s_client_list[i].rssi = sta_list.sta[i].rssi;
            strncpy((char *)s_client_list[i].oui_vendor, oui_lookup(sta_list.sta[i].mac), sizeof(s_client_list[i].oui_vendor) - 1);
        }
    }
}

static void hidden_ssid_probe(const uint8_t *bssid, uint8_t channel)
{
    const char *common_ssids[] = {
        "Campus", "eduroam", "guest", "WiFi", "Starbucks", "xfinitywifi",
        "ATT", "Home", "Office", "Lab", "IoT", "Camera", NULL
    };

    uint8_t probe_req[32] = {
        0x40, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00,
        0x00, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
    };

    memcpy(&probe_req[10], bssid, 6);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    for (int i = 0; common_ssids[i]; i++) {
        uint8_t frame[256];
        memcpy(frame, probe_req, sizeof(probe_req));
        size_t len = sizeof(probe_req);
        uint8_t ssid_ie[] = {0x00, (uint8_t)strlen(common_ssids[i])};
        memcpy(frame + len, ssid_ie, 2);
        len += 2;
        memcpy(frame + len, common_ssids[i], strlen(common_ssids[i]));
        len += strlen(common_ssids[i]);
        esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
        esp_rom_delay_us(1000);
    }
}

esp_err_t wifi_scan_start(void)
{
    if (s_scanning) return ESP_OK;
    s_scanning = true;
    s_scan_count = 0;

    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 120,
        .scan_time.active.max = 300,
    };

    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_cfg, true));

    uint16_t ap_count = WIFI_MAX_SCAN_RESULTS;
    wifi_ap_record_t *records = malloc(WIFI_MAX_SCAN_RESULTS * sizeof(wifi_ap_record_t));
    if (!records) {
        s_scanning = false;
        return ESP_ERR_NO_MEM;
    }

    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_count, records));
    if (ap_count > WIFI_MAX_SCAN_RESULTS) ap_count = WIFI_MAX_SCAN_RESULTS;

    for (int i = 0; i < ap_count; i++) {
        memcpy(s_scan_results[i].bssid, records[i].bssid, 6);
        strncpy(s_scan_results[i].ssid, (char *)records[i].ssid, sizeof(s_scan_results[i].ssid) - 1);
        s_scan_results[i].channel = records[i].primary;
        s_scan_results[i].rssi = records[i].rssi;
        s_scan_results[i].authmode = records[i].authmode;
        s_scan_results[i].hidden = (records[i].ssid[0] == 0);

        strncpy((char *)s_scan_results[i].oui_vendor, oui_lookup(records[i].bssid), sizeof(s_scan_results[i].oui_vendor) - 1);

        char bssid_str[18];
        wifi_mac_to_str(records[i].bssid, bssid_str);
        ESP_LOGI(TAG, "[%02d] %-32s ch=%-2d rssi=%-4d %s %s",
                 i, s_scan_results[i].ssid, s_scan_results[i].channel,
                 s_scan_results[i].rssi, bssid_str, s_scan_results[i].oui_vendor);

        if (s_scan_results[i].hidden) {
            hidden_ssid_probe(records[i].bssid, records[i].primary);
        }
    }

    s_scan_count = ap_count;
    free(records);
    update_client_list();
    s_scanning = false;

    ESP_LOGI(TAG, "Scan complete: %d APs found, %d clients connected", s_scan_count, s_client_count);
    return ESP_OK;
}

esp_err_t wifi_scan_get_results(viper_ap_t *results, uint16_t *count)
{
    if (!results || !count) return ESP_ERR_INVALID_ARG;
    uint16_t copy_count = (*count < s_scan_count) ? *count : s_scan_count;
    memcpy(results, s_scan_results, copy_count * sizeof(viper_ap_t));
    *count = copy_count;
    return ESP_OK;
}

esp_err_t wifi_scan_get_clients(viper_client_t *clients, uint16_t *count)
{
    if (!clients || !count) return ESP_ERR_INVALID_ARG;
    update_client_list();
    uint16_t copy_count = (*count < s_client_count) ? *count : s_client_count;
    memcpy(clients, s_client_list, copy_count * sizeof(viper_client_t));
    *count = copy_count;
    return ESP_OK;
}
