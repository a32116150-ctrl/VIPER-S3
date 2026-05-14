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
    ESP_LOGI(TAG, "[1/6] Mounting storage...");
    storage_init();

    /* 2. Start WiFi engine (AP + STA + monitor mode capable) */
    ESP_LOGI(TAG, "[2/6] Starting WiFi engine...");
    wifi_engine_init();

    /* 3. Start BLE engine (NimBLE — scanner, spam, UART C2) */
    ESP_LOGI(TAG, "[3/6] Starting BLE engine...");
    ble_engine_init();

    /* 4. Start USB engine (TinyUSB — HID/RNDIS/CDC) */
    ESP_LOGI(TAG, "[4/6] Starting USB engine...");
    usb_engine_init();

    /* 5. Start camera engine (OV3660 — stream, QR, motion) */
    ESP_LOGI(TAG, "[5/6] Starting camera engine...");
    camera_engine_init();

    /* 6. Start web dashboard (HTTP + WebSocket on port 80) */
    ESP_LOGI(TAG, "[6/6] Starting web dashboard...");
    web_dashboard_init();

    /* 7. Start responder + crack engine (Phase 7 features) */
    ESP_LOGI(TAG, "[7/7] Initializing crack engine...");
    crack_engine_init();

    /* 8. Protocol attacks (downgrade, canary, behavioral) */
    ESP_LOGI(TAG, "[8/8] Initializing protocol attacks...");
    downgrade_engine_init(DOWNGRADE_SSL);
    behavioral_init();

    /* Boot complete — hand off to attack orchestrator */
    ESP_LOGI(TAG, "✓ All modules online. Dashboard: http://192.168.4.1");
    ESP_LOGI(TAG, "✓ BLE UART C2 active. Connect via BLE GATT.");
    ESP_LOGI(TAG, "✓ Responder & crack engine ready. Start via dashboard.");
    ESP_LOGI(TAG, "✓ Protocol attacks: SSL strip, canary, behavioral ready.");
    ESP_LOGI(TAG, "✓ BLE Advanced: ext advertising, proprietary scans, MITM proxy.");
    ESP_LOGI(TAG, "✓ Phase 10: BadUSB payloads, IR engine, NFC ready.");
    ESP_LOGI(TAG, "✓ Phase 11: ML classification + digital twin engine ready.");

    /* 9. IR engine (RMT — GPIO2=TX, GPIO4=RX) */
    ESP_LOGI(TAG, "[9/9] Initializing IR engine...");
    ir_engine_init(2, 4);

    /* 10. NFC engine (PN532 — UART1: GPIO18=TX, GPIO5=RX) */
    ESP_LOGI(TAG, "[10/10] Initializing NFC engine...");
    esp_err_t nfc_ret = nfc_engine_init(NFC_PN532_MODE_UART, 18, 5, -1, -1);
    if (nfc_ret != ESP_OK) {
        ESP_LOGW(TAG, "NFC module not detected — skipping");
    }

    /* 11. AI engine (ML classification + digital twin) */
    ESP_LOGI(TAG, "[11/11] Initializing AI engine...");
    ai_engine_init();

    attack_orchestrator_start();

    /* Main task becomes the health monitor */
    while (1) {
        ESP_LOGI(TAG, "[HEAP] Free: %lu KB | Min ever: %lu KB",
                 esp_get_free_heap_size() / 1024,
                 esp_get_minimum_free_heap_size() / 1024);
        vTaskDelay(pdMS_TO_TICKS(30000));
    }
}
