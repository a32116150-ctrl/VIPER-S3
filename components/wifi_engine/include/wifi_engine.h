#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "esp_wifi_types.h"

/* ── AP Record ─────────────────────────────────── */
#define WIFI_MAX_SCAN_RESULTS   64
#define WIFI_MAX_CLIENTS        32

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    wifi_auth_mode_t authmode;
    bool     hidden;
    uint8_t  oui_vendor[32]; /* Manufacturer from OUI lookup */
} viper_ap_t;

typedef struct {
    uint8_t  mac[6];
    uint8_t  ap_bssid[6];
    int8_t   rssi;
    char     oui_vendor[32];
} viper_client_t;

/* ── WiFi Modes ────────────────────────────────── */
typedef enum {
    WIFI_MODE_IDLE = 0,
    WIFI_MODE_SCANNER,       /* Passive scan all channels */
    WIFI_MODE_MONITOR,       /* Promiscuous / raw RX */
    WIFI_MODE_EVIL_TWIN,     /* Rogue AP */
    WIFI_MODE_DEAUTH,        /* Deauth attack */
    WIFI_MODE_BEACON_FLOOD,  /* Beacon spam */
    WIFI_MODE_KARMA,         /* Respond to all probes */
    WIFI_MODE_PMKID_HARVEST, /* Passive PMKID + handshake */
    WIFI_MODE_HTTP_SNIFF,    /* HTTP credential sniff on rogue AP */
} wifi_attack_mode_t;

/* ── Public API ────────────────────────────────── */

/* Core init / mode control */
esp_err_t wifi_engine_init(void);
esp_err_t wifi_engine_set_mode(wifi_attack_mode_t mode);
wifi_attack_mode_t wifi_engine_get_mode(void);
esp_err_t wifi_engine_stop_current(void);

/* Scanner */
esp_err_t wifi_scan_start(void);
esp_err_t wifi_scan_get_results(viper_ap_t *results, uint16_t *count);
esp_err_t wifi_scan_get_clients(viper_client_t *clients, uint16_t *count);

/* Deauth */
esp_err_t wifi_deauth_start(const uint8_t *bssid, const uint8_t *client_mac,
                             uint8_t channel, uint32_t pps, uint32_t duration_ms);
esp_err_t wifi_deauth_all(uint32_t pps, uint32_t duration_ms);
esp_err_t wifi_deauth_stop(void);

/* Evil Twin */
typedef struct {
    char     ssid[33];
    uint8_t  channel;
    wifi_auth_mode_t authmode;
    char     password[64];     /* Empty = open (recommended for evil twin) */
    bool     deauth_legit;     /* Auto-deauth legitimate AP */
    uint8_t  legit_bssid[6];  /* Legitimate AP to deauth */
} evil_twin_cfg_t;

esp_err_t wifi_eviltwin_start(const evil_twin_cfg_t *cfg);
esp_err_t wifi_eviltwin_stop(void);
uint8_t   wifi_eviltwin_get_client_count(void);

/* Beacon Flood */
esp_err_t wifi_beacon_flood_start(const char **ssid_list, uint16_t count,
                                   uint8_t channel, uint32_t pps);
esp_err_t wifi_beacon_flood_stop(void);

/* PMKID / Handshake Harvest */
esp_err_t wifi_pmkid_harvest_start(const uint8_t *target_bssid); /* NULL = all */
esp_err_t wifi_pmkid_harvest_stop(void);
uint32_t  wifi_pmkid_get_capture_count(void);

/* Karma Attack */
esp_err_t wifi_karma_start(void);
esp_err_t wifi_karma_stop(void);

/* HTTP Sniffer (runs on rogue AP) */
esp_err_t http_sniffer_start(void);
esp_err_t http_sniffer_stop(void);

/* Captive Portal */
esp_err_t captive_portal_start(const char *template_name);
esp_err_t captive_portal_stop(void);
esp_err_t captive_portal_inject_js(const char *js_snippet);

/* DNS Spoofer */
esp_err_t dns_spoof_start(const char *redirect_ip);
esp_err_t dns_spoof_stop(void);

/* Utility */
void      wifi_mac_to_str(const uint8_t *mac, char *out); /* "AA:BB:CC:DD:EE:FF" */
bool      wifi_mac_is_broadcast(const uint8_t *mac);
esp_err_t wifi_set_channel(uint8_t channel);

esp_err_t wifi_randomize_mac(void);
