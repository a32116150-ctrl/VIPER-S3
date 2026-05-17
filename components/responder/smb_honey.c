#include "responder.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "SMBHONEY";

static TaskHandle_t s_smb_task = NULL;
static volatile bool s_running = false;
static int s_listen_fd = -1;
static volatile uint32_t s_captures = 0;

#define SMB_NEGOTIATE_REQ_LEN 64

static const uint8_t SMBv2_NEGOTIATE_RESP[] = {
    0x00, 0x00, 0x00, 0x89, 0xFE, 0x53, 0x4D, 0x42,
    0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x41, 0x00, 0x01, 0x00, 0x02, 0x02, 0x10, 0x02,
    0x00, 0x03, 0x02, 0x03, 0x11, 0x03, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x53, 0x4D, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

static void extract_ntlmv2(const uint8_t *buf, int len, const char *src_ip)
{
    for (int i = 0; i < len - 8; i++) {
        if (buf[i] == 'N' && buf[i+1] == 'T' && buf[i+2] == 'L' && buf[i+3] == 'M' &&
            buf[i+4] == 'S' && buf[i+5] == 'S' && buf[i+6] == 'P') {
            int remain = len - i;
            char hex[512] = {0};
            int hi = 0;
            int dump = remain < 256 ? remain : 256;
            for (int j = 0; j < dump && hi < 500; j++) {
                sprintf(hex + hi, "%02X", buf[i + j]);
                hi += 2;
            }
            ESP_LOGI(TAG, "NTLMv2 captured from %s (%d bytes)", src_ip, dump);
            storage_log_credential("smb_honeypot", "NTLMv2", hex, src_ip);
            s_captures++;
            return;
        }
    }
}

static void handle_client(int fd, struct sockaddr_in *client)
{
    char src_ip[16];
    inet_ntoa_r(client->sin_addr, src_ip, sizeof(src_ip));

    uint8_t *buf = malloc(2048);
    if (!buf) { close(fd); return; }
    int len = recv(fd, buf, 2048, 0);
    if (len <= 0) { free(buf); close(fd); return; }

    if (len >= 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00) {
        send(fd, SMBv2_NEGOTIATE_RESP, sizeof(SMBv2_NEGOTIATE_RESP), 0);

        vTaskDelay(pdMS_TO_TICKS(100));

        len = recv(fd, buf, 2048, 0);
        if (len > 0) {
            extract_ntlmv2(buf, len, src_ip);
        }
    }

    free(buf);
    close(fd);
}

static void smb_task(void *arg)
{
    s_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s_listen_fd < 0) { s_running = false; vTaskDelete(NULL); return; }

    int opt = 1;
    setsockopt(s_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(445),
        .sin_addr = { .s_addr = INADDR_ANY },
    };

    if (bind(s_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Bind port 445 failed");
        close(s_listen_fd);
        s_listen_fd = -1;
        s_running = false;
        vTaskDelete(NULL);
        return;
    }

    listen(s_listen_fd, 5);
    ESP_LOGI(TAG, "SMB honeypot on port 445");

    while (s_running) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s_listen_fd, &readfds);

        if (select(s_listen_fd + 1, &readfds, NULL, NULL, &tv) <= 0) continue;

        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int client_fd = accept(s_listen_fd, (struct sockaddr *)&client, &clen);
        if (client_fd >= 0) {
            handle_client(client_fd, &client);
        }
    }

    close(s_listen_fd);
    s_listen_fd = -1;
    s_smb_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t smb_honeypot_start(uint16_t port)
{
    if (s_running) return ESP_OK;
    (void)port;
    s_running = true;
    xTaskCreatePinnedToCore(smb_task, "smb_honey", 6144, NULL, 5, &s_smb_task, 0);
    return ESP_OK;
}

esp_err_t smb_honeypot_stop(void)
{
    s_running = false;
    if (s_listen_fd >= 0) { close(s_listen_fd); s_listen_fd = -1; }
    if (s_smb_task) { vTaskDelay(pdMS_TO_TICKS(200)); s_smb_task = NULL; }
    ESP_LOGI(TAG, "SMB honeypot stopped (%lu captures)", (unsigned long)s_captures);
    return ESP_OK;
}

uint32_t smb_honeypot_get_capture_count(void) { return s_captures; }
