#include "wifi_engine.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "DNSSPOOF";

static TaskHandle_t s_dns_task = NULL;
static volatile bool s_running = false;
static int s_dns_fd = -1;
static char s_redirect_ip[16] = "192.168.4.1";

typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

typedef struct __attribute__((packed)) {
    uint16_t type;
    uint16_t dns_class;
} dns_question_t;

typedef struct __attribute__((packed)) {
    uint16_t name_ptr;
    uint16_t type;
    uint16_t dns_class;
    uint32_t ttl;
    uint16_t rdlength;
    uint32_t rdata;
} dns_answer_t;

static void build_dns_response(const uint8_t *query, uint16_t query_len,
                                uint8_t *resp, uint16_t *resp_len)
{
    dns_header_t *req_hdr = (dns_header_t *)query;

    dns_header_t *res_hdr = (dns_header_t *)resp;
    res_hdr->id = req_hdr->id;
    res_hdr->flags = htons(0x8180);
    res_hdr->qdcount = req_hdr->qdcount;
    res_hdr->ancount = htons(1);
    res_hdr->nscount = 0;
    res_hdr->arcount = 0;

    size_t off = sizeof(dns_header_t);
    memcpy(resp + off, query + off, query_len - off);

    while (off < query_len) {
        uint8_t label_len = query[off];
        if (label_len == 0) {
            off++;
            break;
        }
        if ((label_len & 0xC0) == 0xC0) {
            off += 2;
            break;
        }
        off += 1 + label_len;
    }

    off += sizeof(dns_question_t);

    dns_answer_t *ans = (dns_answer_t *)(resp + off);
    ans->name_ptr = htons(0xC00C);
    ans->type = htons(1);
    ans->dns_class = htons(1);
    ans->ttl = htonl(60);
    ans->rdlength = htons(4);

    uint32_t ip = inet_addr(s_redirect_ip);
    ans->rdata = ip;

    *resp_len = off + sizeof(dns_answer_t);
}

static void dns_task(void *arg)
{
    s_dns_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_dns_fd < 0) {
        ESP_LOGE(TAG, "Failed to create DNS socket");
        s_running = false;
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr = { .s_addr = INADDR_ANY },
    };

    if (bind(s_dns_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind DNS port 53");
        close(s_dns_fd);
        s_dns_fd = -1;
        s_running = false;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS spoofer listening on port 53 → %s", s_redirect_ip);

    uint8_t buf[512];
    uint8_t resp[512];

    while (s_running) {
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s_dns_fd, &readfds);

        int ret = select(s_dns_fd + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        int len = recvfrom(s_dns_fd, buf, sizeof(buf), 0,
                          (struct sockaddr *)&client, &client_len);
        if (len < 12) continue;

        dns_header_t *hdr = (dns_header_t *)buf;
        uint16_t flags = ntohs(hdr->flags);
        uint8_t qr = (flags >> 15) & 1;
        uint8_t opcode = (flags >> 11) & 0x0F;

        if (qr != 0 || opcode != 0) continue;

        uint16_t resp_len = 0;
        build_dns_response(buf, len, resp, &resp_len);

        sendto(s_dns_fd, resp, resp_len, 0,
               (struct sockaddr *)&client, client_len);
    }

    close(s_dns_fd);
    s_dns_fd = -1;
    s_dns_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t dns_spoof_start(const char *redirect_ip)
{
    if (s_running) return ESP_OK;

    if (redirect_ip) {
        strncpy(s_redirect_ip, redirect_ip, sizeof(s_redirect_ip) - 1);
    }

    s_running = true;
    xTaskCreatePinnedToCore(dns_task, "dns_spoof", 4096, NULL, 5,
                            &s_dns_task, 0);
    return ESP_OK;
}

esp_err_t dns_spoof_stop(void)
{
    s_running = false;
    if (s_dns_fd >= 0) {
        close(s_dns_fd);
        s_dns_fd = -1;
    }
    if (s_dns_task) {
        vTaskDelay(pdMS_TO_TICKS(200));
        s_dns_task = NULL;
    }
    ESP_LOGI(TAG, "DNS spoofer stopped");
    return ESP_OK;
}
