/**
 * VIPER-S3 — Visual Intelligence Pentesting & Exploitation Router
 * Main entry point
 *
 * Hardware: ESP32-S3 WROOM N16R8 + OV3660 Camera
 * Author:   VIPER-S3 Project
 * License:  For authorized security research only
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"

/* VIPER-S3 modules */
#include "storage_manager.h"
#include "wifi_engine.h"
#include "ble_engine.h"
#include "usb_engine.h"
#include "camera_engine.h"
#include "web_dashboard.h"
#include "attack_orchestrator.h"
#include "responder.h"
#include "crack_engine.h"
#include "protocol_attacks.h"
#include "ir_engine.h"
#include "nfc_engine.h"
#include "ai_engine.h"

static const char *TAG = "VIPER-S3";

/* ────────────────────────────────────────────────
   System init sequence
   ──────────────────────────────────────────────── */
static void system_init(void)
{
    /* NVS — required for WiFi */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* TCP/IP stack */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_LOGI(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    ESP_LOGI(TAG, "  VIPER-S3 FIRMWARE — BOOTING");
    ESP_LOGI(TAG, "  ESP32-S3 N16R8 + OV3660");
    ESP_LOGI(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

/* ────────────────────────────────────────────────
   App main
   ──────────────────────────────────────────────── */
void app_main(void)
{
    system_init();

    /* 1. Mount LittleFS — all modules depend on storage */
    ESP_LOGI(TAG, "[1/11] Mounting storage...");
    storage_init();

    /* 2. Start camera engine early — needs fresh internal DRAM pool for DMA descriptors.
       Must allocate before dashboard+WiFi fragment the 32KB reserved pool. */
    ESP_LOGI(TAG, "[2/11] Starting camera engine...");
    {
        esp_err_t r = camera_engine_init(&CAMERA_CONFIG_DEFAULT);
        if (r != ESP_OK) ESP_LOGW(TAG, "[2/11] Camera engine skipped: %s", esp_err_to_name(r));
    }

    /* 3. Start web dashboard (CRITICAL — must succeed). Done BEFORE WiFi so DRAM is maximally available. */
    ESP_LOGI(TAG, "[3/11] Starting web dashboard...");
    {
        esp_err_t r = web_dashboard_init();
        if (r != ESP_OK) {
            ESP_LOGE(TAG, "[3/11] Dashboard init failed: %s — will retry later",
                     esp_err_to_name(r));
        }
    }

    /* 4. Start WiFi engine (optional — graceful failure) */
    ESP_LOGI(TAG, "[4/11] Starting WiFi engine...");
    {
        esp_err_t r = wifi_engine_init();
        if (r != ESP_OK) ESP_LOGW(TAG, "[4/11] WiFi engine skipped: %s", esp_err_to_name(r));
    }

    /* 5. Start IR engine (optional — graceful failure) */
    ESP_LOGI(TAG, "[5/11] Initializing IR engine...");
    {
        esp_err_t r = ir_engine_init(2, 4);
        if (r != ESP_OK) ESP_LOGW(TAG, "[5/11] IR engine skipped: %s", esp_err_to_name(r));
    }

    /* 6. Start NFC engine (optional — graceful failure) */
    ESP_LOGI(TAG, "[6/11] Initializing NFC engine...");
    {
        esp_err_t r = nfc_engine_init(NFC_PN532_MODE_UART, 18, 5, -1, -1);
        if (r != ESP_OK) ESP_LOGW(TAG, "[6/11] NFC engine skipped: %s", esp_err_to_name(r));
    }

    /* 7. Start crack engine & protocol attacks (optional) */
    ESP_LOGI(TAG, "[7/11] Initializing attack engines...");
    {
        esp_err_t r = crack_engine_init();
        if (r != ESP_OK) ESP_LOGW(TAG, "[7/11] Crack engine skipped: %s", esp_err_to_name(r));
    }
    {
        esp_err_t r = downgrade_engine_init(DOWNGRADE_SSL);
        if (r != ESP_OK) ESP_LOGW(TAG, "[7/11] Downgrade engine skipped: %s", esp_err_to_name(r));
    }
    {
        esp_err_t r = behavioral_init();
        if (r != ESP_OK) ESP_LOGW(TAG, "[7/11] Behavioral engine skipped: %s", esp_err_to_name(r));
    }

    /* 8. Start BLE engine (optional — graceful failure) */
    ESP_LOGI(TAG, "[8/11] Starting BLE engine...");
    {
        esp_err_t r = ble_engine_init();
        if (r != ESP_OK) ESP_LOGW(TAG, "[8/11] BLE engine skipped: %s", esp_err_to_name(r));
    }

    /* 9. Start USB engine (optional — graceful failure) */
    ESP_LOGI(TAG, "[9/11] Starting USB engine...");
    {
        esp_err_t r = usb_engine_init();
        if (r != ESP_OK) ESP_LOGW(TAG, "[9/11] USB engine skipped: %s", esp_err_to_name(r));
    }

    /* 10. AI engine (optional — graceful failure) */
    ESP_LOGI(TAG, "[10/11] Initializing AI engine...");
    {
        esp_err_t r = ai_engine_init();
        if (r != ESP_OK) ESP_LOGW(TAG, "[10/11] AI engine skipped: %s", esp_err_to_name(r));
    }


    {
        esp_err_t r = attack_orchestrator_start();
        if (r != ESP_OK) ESP_LOGW(TAG, "[11/11] Attack orchestrator skipped: %s", esp_err_to_name(r));
    }

    /* Retry dashboard init if it failed earlier (now WiFi is up, DRAM may have shifted) */
    if (web_dashboard_init() == ESP_OK) {
        ESP_LOGI(TAG, "Dashboard started on retry — ready at http://192.168.4.1");
    }

    /* Main task becomes the health monitor */
    while (1) {
        uint32_t free = esp_get_free_heap_size();
        uint32_t min_free = esp_get_minimum_free_heap_size();
        uint32_t block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        ESP_LOGI(TAG, "[HEALTH] Free: %lu KB | Min: %lu KB | Int block: %lu B",
                 free / 1024, min_free / 1024, block);
        vTaskDelay(pdMS_TO_TICKS(30000));
    }
}
