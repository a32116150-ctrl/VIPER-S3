#include "web_dashboard.h"
#include "wifi_engine.h"
#include "storage_manager.h"
#include "camera_engine.h"
#include "responder.h"
#include "crack_engine.h"
#include "protocol_attacks.h"
#include "ble_engine.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "DASHBOARD";

#define MAX_WS_CLIENTS 8

static httpd_handle_t s_server = NULL;
static int s_ws_fds[MAX_WS_CLIENTS];
static int s_ws_count = 0;

static char s_log_buf[16384];
static size_t s_log_len = 0;

/* ── WebSocket helpers ──────────────────────────── */

static void ws_add_client(int fd)
{
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (s_ws_fds[i] == 0) { s_ws_fds[i] = fd; s_ws_count++; return; }
    }
}

static void ws_remove_client(int fd)
{
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (s_ws_fds[i] == fd) { s_ws_fds[i] = 0; s_ws_count--; return; }
    }
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

    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (s_ws_fds[i] != 0) {
            httpd_ws_send_frame_async(s_server, s_ws_fds[i], &ws_msg);
        }
    }
    return ESP_OK;
}

static void dashboard_log(const char *fmt, ...)
{
    char line[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    size_t llen = strlen(line);
    if (s_log_len + llen + 1 > sizeof(s_log_buf)) {
        size_t remove = s_log_len / 4;
        memmove(s_log_buf, s_log_buf + remove, s_log_len - remove);
        s_log_len -= remove;
    }
    s_log_len += snprintf(s_log_buf + s_log_len, sizeof(s_log_buf) - s_log_len, "%s\n", line);

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
    viper_ap_t results[WIFI_MAX_SCAN_RESULTS];
    uint16_t count = WIFI_MAX_SCAN_RESULTS;

    wifi_scan_get_results(results, &count);

    char *buf = malloc(count * 256 + 128);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_OK;
    }

    int off = snprintf(buf, 4096, "{\"count\":%d,\"aps\":[", count);
    for (int i = 0; i < count; i++) {
        char bssid[18];
        wifi_mac_to_str(results[i].bssid, bssid);
        off += snprintf(buf + off, 4096 - off,
            "%c{\"ssid\":\"%s\",\"bssid\":\"%s\",\"ch\":%d,\"rssi\":%d,\"auth\":%d,\"hidden\":%d,\"vendor\":\"%s\"}",
            i > 0 ? ',' : ' ',
            results[i].ssid, bssid,
            results[i].channel, results[i].rssi,
            results[i].authmode, results[i].hidden,
            results[i].oui_vendor);
    }
    off += snprintf(buf + off, 4096 - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

/* ── API: Clients ───────────────────────────────── */

static esp_err_t api_clients_get(httpd_req_t *req)
{
    viper_client_t clients[WIFI_MAX_CLIENTS];
    uint16_t count = WIFI_MAX_CLIENTS;

    wifi_scan_get_clients(clients, &count);

    char buf[4096];
    int off = snprintf(buf, sizeof(buf), "{\"count\":%d,\"clients\":[", count);
    for (int i = 0; i < count; i++) {
        char mac[18];
        wifi_mac_to_str(clients[i].mac, mac);
        off += snprintf(buf + off, sizeof(buf) - off,
            "%c{\"mac\":\"%s\",\"rssi\":%d,\"vendor\":\"%s\"}",
            i > 0 ? ',' : ' ', mac, clients[i].rssi, clients[i].oui_vendor);
    }
    off += snprintf(buf + off, sizeof(buf) - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    return ESP_OK;
}

/* ── API: Attack Control ────────────────────────── */

static esp_err_t api_attack_start(httpd_req_t *req)
{
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

    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_attack_stop(httpd_req_t *req)
{
    wifi_engine_stop_current();
    dashboard_log("Attack stopped");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

/* ── API: Captures ──────────────────────────────── */

static esp_err_t api_captures_creds(httpd_req_t *req)
{
    uint8_t buf[8192];
    size_t len = 0;
    esp_err_t ret = storage_read_file(FILE_CREDS, buf, sizeof(buf) - 1, &len);
    if (ret != ESP_OK) {
        httpd_resp_sendstr(req, "{\"count\":0,\"entries\":[]}");
        return ESP_OK;
    }
    buf[len] = '\0';

    char resp[8256];
    int rlen = snprintf(resp, sizeof(resp), "{\"count\":%zu,\"entries\":[%s]}", len > 0 ? 1 : 0, buf);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, rlen);
    return ESP_OK;
}

static esp_err_t api_captures_hashes(httpd_req_t *req)
{
    uint8_t buf[8192];
    size_t len = 0;
    esp_err_t ret = storage_read_file(FILE_HASHES, buf, sizeof(buf) - 1, &len);
    if (ret != ESP_OK) {
        httpd_resp_sendstr(req, "{\"count\":0,\"entries\":[]}");
        return ESP_OK;
    }
    buf[len] = '\0';

    char resp[8256];
    int rlen = snprintf(resp, sizeof(resp), "{\"count\":%zu,\"entries\":[%s]}", len > 0 ? 1 : 0, buf);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, rlen);
    return ESP_OK;
}

static esp_err_t api_captures_wipe(httpd_req_t *req)
{
    storage_wipe_captures();
    dashboard_log("Captures wiped");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

/* ── API: Logs ──────────────────────────────────── */

static esp_err_t api_logs_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, s_log_buf, s_log_len);
    return ESP_OK;
}

/* ── API: Config ────────────────────────────────── */

static esp_err_t api_config_get(httpd_req_t *req)
{
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
    char buf[2048];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) { httpd_resp_send_500(req); return ESP_OK; }
    buf[len] = '\0';

    storage_write_file(FILE_CONFIG, (uint8_t *)buf, len, false);
    dashboard_log("Config updated");
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
    const char *type = httpd_req_get_url_query_str(req) ?: "";
    if (strstr(type, "creds")) return serve_file(req, FILE_CREDS, "application/json");
    if (strstr(type, "hashes")) return serve_file(req, FILE_HASHES, "application/json");
    if (strstr(type, "all")) {
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
    "</style></head><body>"
    "<div class='header'>"
    "<h1>VIPER<span>-S3</span></h1>"
    "<div class='status'><span class='dot'></span><span id='statusText'>Online</span> &middot; <span id='heapText'>0</span> KB free</div>"
    "</div>"
    "<div class='nav' id='nav'>"
    "<a href='#' class='active' data-panel='overview'>Overview</a>"
    "<a href='#' data-panel='wifi'>WiFi</a>"
    "<a href='#' data-panel='attacks'>Attacks</a>"
    "<a href='#' data-panel='captures'>Captures</a>"
    "<a href='#' data-panel='camera'>Camera</a>"
    "<a href='#' data-panel='logs'>Logs</a>"
    "<a href='#' data-panel='ble'>BLE</a>"
    "<a href='#' data-panel='config'>Config</a>"
    "</div>"
    "<div class='main' id='main'>"
    "<div class='panel active' id='panel-overview'>"
    "<div class='cards' id='statusCards'>"
    "<div class='card'><h3>Heap Free</h3><div class='value green' id='heapVal'>0 KB</div></div>"
    "<div class='card'><h3>WiFi Mode</h3><div class='value blue' id='wifiModeVal'>Idle</div></div>"
    "<div class='card'><h3>WS Clients</h3><div class='value yellow' id='wsClientsVal'>0</div></div>"
    "<div class='card'><h3>Uptime</h3><div class='value' id='uptimeVal'>0s</div></div>"
    "</div>"
    "<div class='card'><h3>Recent Activity</h3><div class='log-viewer' id='activityLog'><div class='info'>Waiting for events...</div></div></div>"
    "</div>"
    "<div class='panel' id='panel-wifi'><div class='card'><h3>Access Points</h3><div style='margin:8px 0'><button class='btn btn-primary btn-sm' onclick='scanWifi()'>Scan Now</button></div><div id='scanResults' style='overflow-x:auto'><div class='empty'>Click "Scan Now" to start</div></div></div></div>"
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
    "<div class='card'><h3>Device Configuration</h3><div id='configForm'><div class='empty'>Loading...</div></div></div>"
    "</div>"
    "</div>"
    "<script>"
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
    "document.querySelectorAll('.nav a').forEach(function(a){"
    "a.addEventListener('click',function(e){"
    "e.preventDefault();"
    "document.querySelectorAll('.nav a').forEach(function(x){x.classList.remove('active')});"
    "this.classList.add('active');"
    "document.querySelectorAll('.panel').forEach(function(p){p.classList.remove('active')});"
    "document.getElementById('panel-'+this.dataset.panel).classList.add('active');"
    "if(this.dataset.panel=='overview')refreshOverview();"
    "if(this.dataset.panel=='ble'){refreshProprietary();refreshMitmStatus()}"
    "});"
    "});"
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
    "},2000);"
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
    "fetch('/api/captures/creds').then(function(r){return r.json()}).then(function(d){"
    "if(!d.entries||d.entries.length===0){document.getElementById('credsList').innerHTML='<div class=\\'empty\\'>No credentials captured yet</div>';return}"
    "var h='<table><tr><th>Source</th><th>Username</th><th>Password</th><th>MAC/IP</th></tr>';"
    "(Array.isArray(d.entries)?d.entries:[d.entries]).forEach(function(e){"
    "if(e&&e.user)h+='<tr><td>'+e.src+'</td><td class=\\'user\\'>'+e.user+'</td><td class=\\'pass\\'>'+e.pass+'</td><td>'+e.mac+'</td></tr>'"
    "});"
    "h+='</table>';document.getElementById('credsList').innerHTML=h;"
    "});"
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
    "setInterval(refreshOverview,5000);"
    "connectWS();"
    "</script></body></html>";

/* ── Root handler ───────────────────────────────── */

static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, DASHBOARD_HTML, sizeof(DASHBOARD_HTML) - 1);
    return ESP_OK;
}

/* ── URI Registration ───────────────────────────── */

static const httpd_uri_t s_uris[] = {
    { .uri = "/",         .method = HTTP_GET,    .handler = root_get_handler },
    { .uri = "/ws",       .method = HTTP_GET,    .handler = ws_handler },
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
};

/* ── API: Responder ─────────────────────────────── */

static esp_err_t api_responder_start(httpd_req_t *req)
{
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
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_responder_stop(httpd_req_t *req)
{
    uint32_t count = responder_get_poisoned_count();
    responder_stop();
    dashboard_log("Responder stopped (%lu poisoned)", count);
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_responder_status(httpd_req_t *req)
{
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
    smb_honeypot_start(445);
    dashboard_log("SMB honeypot started");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_smb_stop(httpd_req_t *req)
{
    smb_honeypot_stop();
    dashboard_log("SMB honeypot stopped");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

/* ── API: Crack Engine ──────────────────────────── */

static esp_err_t api_crack_start(httpd_req_t *req)
{
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

    if (!hash[0]) { httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"no hash\"}"); return ESP_OK; }

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
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_canary_create(httpd_req_t *req)
{
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
    canary_token_t tokens[32];
    int count = canary_injector_get_tokens(tokens, 32);

    char *buf = malloc(count * 256 + 64);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }
    int off = snprintf(buf, 4096, "{\"count\":%d,\"tokens\":[", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(buf + off, 4096 - off,
            "%c{\"token\":\"%s\",\"hits\":%lu,\"last_seen\":%llu}",
            i > 0 ? ',' : ' ', tokens[i].token, tokens[i].hit_count, tokens[i].last_seen_at);
    }
    off += snprintf(buf + off, 4096 - off, "]}");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

static esp_err_t api_behavioral_results(httpd_req_t *req)
{
    fingerprint_result_t results[16];
    int count = behavioral_get_results(results, 16);

    char *buf = malloc(count * 256 + 64);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }

    behavioral_classify();

    int off = snprintf(buf, 4096, "{\"count\":%d,\"results\":[", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(buf + off, 4096 - off,
            "%c{\"app\":\"%s\",\"confidence\":%.1f,\"pkts\":%lu,\"avg_size\":%lu,\"duration\":%lu}",
            i > 0 ? ',' : ' ', app_type_to_string(results[i].app),
            results[i].confidence, results[i].packet_count,
            results[i].avg_packet_size, results[i].duration_sec);
    }
    off += snprintf(buf + off, 4096 - off, "]}");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

/* ── API: BLE Proprietary Scan ──────────────────── */

static esp_err_t api_ble_proprietary(httpd_req_t *req)
{
    proprietary_scan_result_t results[32];
    int count = ble_scan_proprietary_get_results(results, 32);

    char *buf = malloc(count * 256 + 64);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }

    int off = snprintf(buf, 4096, "{\"count\":%d,\"results\":[", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(buf + off, 4096 - off,
            "%c{\"type\":\"%s\",\"battery\":%d,\"apple\":%d,\"samsung\":%d,\"tile\":%d,\"findmy\":%d,\"swiftpair\":%d}",
            i > 0 ? ',' : ' ',
            results[i].type, results[i].battery_level,
            results[i].is_apple, results[i].is_samsung,
            results[i].is_tile, results[i].is_findmy, results[i].is_swiftpair);
    }
    off += snprintf(buf + off, 4096 - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

/* ── API: BLE MITM ──────────────────────────────── */

static esp_err_t api_ble_mitm_start(httpd_req_t *req)
{
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
        httpd_resp_sendstr(req, "{\"ok\":true}");
    } else {
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"failed to start\"}");
    }
    return ESP_OK;
}

static esp_err_t api_ble_mitm_stop(httpd_req_t *req)
{
    ble_mitm_stop();
    dashboard_log("BLE MITM stopped");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_ble_mitm_status(httpd_req_t *req)
{
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
    mitm_service_t svcs[8];
    int count = ble_mitm_get_discovered_services(svcs, 8);

    char *buf = malloc(count * 1024 + 64);
    if (!buf) { httpd_resp_send_500(req); return ESP_OK; }

    int off = snprintf(buf, 8192, "{\"count\":%d,\"services\":[", count);
    for (int i = 0; i < count; i++) {
        off += snprintf(buf + off, 8192 - off,
            "%c{\"start\":%d,\"end\":%d,\"chars\":[",
            i > 0 ? ',' : ' ', svcs[i].start_handle, svcs[i].end_handle);
        for (int c = 0; c < svcs[i].char_count; c++) {
            off += snprintf(buf + off, 8192 - off,
                "%c{\"handle\":%d,\"uuid\":\"0x%04x\",\"props\":%d}",
                c > 0 ? ',' : ' ', svcs[i].chars[c].handle,
                svcs[i].chars[c].uuid, svcs[i].chars[c].properties);
        }
        off += snprintf(buf + off, 8192 - off, "]}");
    }
    off += snprintf(buf + off, 8192 - off, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, off);
    free(buf);
    return ESP_OK;
}

/* ── Init / Deinit ──────────────────────────────── */

esp_err_t web_dashboard_init(void)
{
    if (s_server) return ESP_OK;

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = 80;
    cfg.max_open_sockets = 12;
    cfg.lru_purge_enable = true;

    if (httpd_start(&s_server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return ESP_FAIL;
    }

    for (int i = 0; i < sizeof(s_uris) / sizeof(s_uris[0]); i++) {
        httpd_register_uri_handler(s_server, &s_uris[i]);
    }

    if (camera_engine_is_initialized()) {
        camera_engine_start_stream();
        dashboard_log("Camera stream active on /stream");
    }
    dashboard_log("Web dashboard online — http://192.168.4.1");
    ESP_LOGI(TAG, "Dashboard online — http://192.168.4.1");
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
