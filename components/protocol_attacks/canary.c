#include "protocol_attacks.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "lwip/sockets.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "CANARY";

#define MAX_CANARIES 32
#define CANARY_FILE  "/viper/config/canaries.jsonl"

static canary_token_t s_canaries[MAX_CANARIES];
static int s_canary_count = 0;
static bool s_active = false;

static TaskHandle_t s_canary_task = NULL;
static volatile bool s_running = false;
static int s_canary_fd = -1;

static void generate_token(char *out, int len)
{
    const char *chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < len - 1; i++) {
        out[i] = chars[esp_random() % strlen(chars)];
    }
    out[len - 1] = '\0';
}

static void save_canaries(void)
{
    FILE *f = fopen(CANARY_FILE, "w");
    if (!f) return;
    for (int i = 0; i < s_canary_count; i++) {
        fprintf(f, "{\"token\":\"%s\",\"target\":\"%s\",\"created\":%llu,\"hits\":%lu}\n",
                s_canaries[i].token, s_canaries[i].target_url,
                (unsigned long long)s_canaries[i].created_at,
                (unsigned long)s_canaries[i].hit_count);
    }
    fclose(f);
}

static void load_canaries(void)
{
    FILE *f = fopen(CANARY_FILE, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f) && s_canary_count < MAX_CANARIES) {
        canary_token_t *c = &s_canaries[s_canary_count];
        const char *t = strstr(line, "\"token\":\"");
        if (t) { t += 9; int i = 0; while (*t && *t != '"' && i < 63) c->token[i++] = *t++; }
        const char *u = strstr(line, "\"target\":\"");
        if (u) { u += 10; int i = 0; while (*u && *u != '"' && i < 255) c->target_url[i++] = *u++; }
        s_canary_count++;
    }
    fclose(f);
}

static void handle_canary_hit(const char *token, const char *client_ip)
{
    for (int i = 0; i < s_canary_count; i++) {
        if (strcmp(s_canaries[i].token, token) == 0) {
            s_canaries[i].hit_count++;
            s_canaries[i].last_seen_at = esp_timer_get_time() / 1000000;
            strncpy(s_canaries[i].client_ip, client_ip, sizeof(s_canaries[i].client_ip) - 1);
            save_canaries();
            ESP_LOGI(TAG, "Canary HIT: token=%s from %s (hits=%lu)", token, client_ip, s_canaries[i].hit_count);
            return;
        }
    }
    ESP_LOGW(TAG, "Unknown canary token: %s", token);
}

static void canary_task(void *arg)
{
    s_canary_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_canary_fd < 0) { s_running = false; vTaskDelete(NULL); return; }

    int opt = 1;
    setsockopt(s_canary_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8888),
        .sin_addr = { .s_addr = INADDR_ANY },
    };

    if (bind(s_canary_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s_canary_fd);
        s_canary_fd = -1;
        s_running = false;
        vTaskDelete(NULL);
        return;
    }

    listen(s_canary_fd, 5);
    ESP_LOGI(TAG, "Canary tracker on port 8888");

    while (s_running) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s_canary_fd, &readfds);

        if (select(s_canary_fd + 1, &readfds, NULL, NULL, &tv) <= 0) continue;

        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int client_fd = accept(s_canary_fd, (struct sockaddr *)&client, &clen);
        if (client_fd < 0) continue;

        char buf[1024];
        int len = recv(client_fd, buf, sizeof(buf) - 1, 0);
        if (len > 0) {
            buf[len] = '\0';
            char token[64] = {0};
            const char *t = strstr(buf, "/track?token=");
            if (t) {
                t += 13;
                int i = 0;
                while (*t && *t != ' ' && *t != '&' && *t != '\r' && *t != '\n' && i < 63)
                    token[i++] = *t++;
                char ip[16];
                inet_ntoa_r(client.sin_addr, ip, sizeof(ip));
                handle_canary_hit(token, ip);
            }
        }

        const char *resp = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Type: image/gif\r\n\r\n ";
        send(client_fd, resp, strlen(resp), 0);
        close(client_fd);
    }

    close(s_canary_fd);
    s_canary_fd = -1;
    s_canary_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t canary_injector_start(void)
{
    if (s_running) return ESP_OK;
    load_canaries();
    s_running = true;
    s_active = true;
    xTaskCreatePinnedToCore(canary_task, "canary", 4096, NULL, 5, &s_canary_task, 0);
    return ESP_OK;
}

esp_err_t canary_injector_stop(void)
{
    s_running = false;
    s_active = false;
    if (s_canary_fd >= 0) { close(s_canary_fd); s_canary_fd = -1; }
    if (s_canary_task) { vTaskDelay(pdMS_TO_TICKS(200)); s_canary_task = NULL; }
    return ESP_OK;
}

bool canary_injector_is_active(void) { return s_active; }

esp_err_t canary_injector_create_token(const char *target_url, canary_token_t *out)
{
    if (s_canary_count >= MAX_CANARIES) return ESP_ERR_NO_MEM;

    canary_token_t *c = &s_canaries[s_canary_count++];
    generate_token(c->token, sizeof(c->token));
    if (target_url) strncpy(c->target_url, target_url, sizeof(c->target_url) - 1);
    c->created_at = esp_timer_get_time() / 1000000;
    c->hit_count = 0;

    save_canaries();
    ESP_LOGI(TAG, "Canary token created: %s → %s", c->token, c->target_url);

    if (out) memcpy(out, c, sizeof(canary_token_t));
    return ESP_OK;
}

int canary_injector_get_tokens(canary_token_t *tokens, int max)
{
    int copy = max < s_canary_count ? max : s_canary_count;
    memcpy(tokens, s_canaries, copy * sizeof(canary_token_t));
    return copy;
}

esp_err_t canary_injector_clear_tokens(void)
{
    s_canary_count = 0;
    remove(CANARY_FILE);
    return ESP_OK;
}
