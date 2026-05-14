#include "wifi_engine.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "esp_random.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "WIFI";
static wifi_attack_mode_t s_current_mode = WIFI_MODE_IDLE;
static esp_netif_t *s_ap_netif  = NULL;
static esp_netif_t *s_sta_netif = NULL;

/* ── Core Init ─────────────────────────────────── */

esp_err_t wifi_engine_init(void)
{
    s_ap_netif  = esp_netif_create_default_wifi_ap();
    s_sta_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    /* Enable 802.11 long range if needed, max TX power */
    esp_wifi_set_ps(WIFI_PS_NONE);

    /* Start in AP mode (control AP for web dashboard) */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    wifi_config_t ap_cfg = {
        .ap = {
            .ssid            = "AndroidAP_3F7A",  /* Benign-looking SSID */
            .ssid_len        = 0,
            .password        = "00000000",
            .max_connection  = 8,
            .authmode        = WIFI_AUTH_WPA2_PSK,
            .channel         = 6,
        }
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Max TX power */
    esp_wifi_set_max_tx_power(84); /* 21 dBm */

    ESP_LOGI(TAG, "WiFi engine online. Control AP: 'AndroidAP_3F7A' @ 192.168.4.1");
    return ESP_OK;
}

esp_err_t wifi_engine_set_mode(wifi_attack_mode_t mode)
{
    s_current_mode = mode;
    return ESP_OK;
}

wifi_attack_mode_t wifi_engine_get_mode(void) { return s_current_mode; }

/* ── Utility ───────────────────────────────────── */

void wifi_mac_to_str(const uint8_t *mac, char *out)
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool wifi_mac_is_broadcast(const uint8_t *mac)
{
    return (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
            mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF);
}

esp_err_t wifi_set_channel(uint8_t ch)
{
    return esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

esp_err_t wifi_randomize_mac(void)
{
    uint8_t mac[6];
    esp_fill_random(mac, 6);
    mac[0] &= 0xFE; /* Unicast */
    mac[0] |= 0x02; /* Locally administered */
    return esp_wifi_set_mac(WIFI_IF_STA, mac);
}

esp_err_t wifi_engine_stop_current(void)
{
    switch (s_current_mode) {
        case WIFI_MODE_DEAUTH:        wifi_deauth_stop();        break;
        case WIFI_MODE_EVIL_TWIN:     wifi_eviltwin_stop();      break;
        case WIFI_MODE_BEACON_FLOOD:  wifi_beacon_flood_stop();  break;
        case WIFI_MODE_PMKID_HARVEST: wifi_pmkid_harvest_stop(); break;
        case WIFI_MODE_KARMA:         wifi_karma_stop();         break;
        case WIFI_MODE_HTTP_SNIFF:    http_sniffer_stop();       break;
        default: break;
    }
    s_current_mode = WIFI_MODE_IDLE;
    return ESP_OK;
}
