#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/* ── Downgrade Engine ───────────────────────────── */

typedef enum {
    DOWNGRADE_WPA3  = 1,
    DOWNGRADE_SSL   = 2,
    DOWNGRADE_TLS   = 4,
    DOWNGRADE_ALL   = 7,
} downgrade_type_t;

esp_err_t downgrade_engine_init(downgrade_type_t types);
esp_err_t downgrade_engine_deinit(void);
bool     downgrade_is_active(downgrade_type_t type);

esp_err_t downgrade_set_evil_twin_wpa2(const char *ssid, uint8_t channel);

/* ── Canary Injector ────────────────────────────── */

typedef struct {
    char token[64];
    char target_url[256];
    uint64_t created_at;
    uint64_t last_seen_at;
    uint32_t hit_count;
    char client_ip[16];
} canary_token_t;

esp_err_t canary_injector_start(void);
esp_err_t canary_injector_stop(void);
bool     canary_injector_is_active(void);

esp_err_t canary_injector_create_token(const char *target_url, canary_token_t *out);
int      canary_injector_get_tokens(canary_token_t *tokens, int max);
esp_err_t canary_injector_clear_tokens(void);

/* ── Behavioral Fingerprinting ──────────────────── */

typedef enum {
    APP_UNKNOWN = 0,
    APP_ZOOM,
    APP_SSH,
    APP_NETFLIX,
    APP_HTTP_BROWSE,
    APP_STREAMING,
    APP_VOIP,
    APP_FILE_TRANSFER,
    APP_GAMING,
} app_type_t;

typedef struct {
    char     client_ip[16];
    app_type_t app;
    float    confidence;
    uint32_t packet_count;
    uint32_t avg_packet_size;
    uint32_t duration_sec;
    uint64_t last_seen;
} fingerprint_result_t;

esp_err_t behavioral_init(void);
esp_err_t behavioral_deinit(void);

void     behavioral_feed_packet(uint32_t size, uint32_t timestamp_us);
app_type_t behavioral_classify(void);
int      behavioral_get_results(fingerprint_result_t *results, int max);
void     behavioral_clear(void);

const char *app_type_to_string(app_type_t app);
