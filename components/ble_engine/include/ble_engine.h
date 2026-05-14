#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define BLE_MAX_DEVICES 64
#define BLE_DEVICE_NAME_MAX 64

typedef struct {
    uint8_t  addr[6];
    char     name[BLE_DEVICE_NAME_MAX];
    int8_t   rssi;
    uint16_t manufacturer;
    uint8_t  adv_data[64];
    uint16_t adv_data_len;
    uint16_t service_uuids[4];
    int      service_count;
    bool     is_apple;
    bool     is_google;
    bool     is_ibeacon;
    char     device_type[32];
} ble_device_t;

typedef enum {
    BLE_SPAM_NONE = 0,
    BLE_SPAM_AIRDROP,
    BLE_SPAM_AIRPODS,
    BLE_SPAM_APPLE_WATCH,
    BLE_SPAM_APPLE_TV,
    BLE_SPAM_ANDROID_FASTPAIR,
    BLE_SPAM_WINDOWS_SWIFTPAIR,
    BLE_SPAM_SAMSUNG,
    BLE_SPAM_ALL,
} ble_spam_type_t;

/* ── BLE Engine Core ──────────────────────────── */

esp_err_t ble_engine_init(void);
esp_err_t ble_engine_deinit(void);
bool     ble_engine_is_synced(void);

/* ── BLE Scanner ──────────────────────────────── */

esp_err_t ble_scanner_start(uint32_t duration_ms);
esp_err_t ble_scanner_stop(void);
int      ble_scanner_get_count(void);
int      ble_scanner_get_results(ble_device_t *devices, int max);
esp_err_t ble_scanner_clear(void);

/* ── BLE Spam ─────────────────────────────────── */

esp_err_t ble_spam_start(ble_spam_type_t type, uint32_t rate_ms);
esp_err_t ble_spam_stop(void);
bool     ble_spam_is_active(void);

/* ── BLE UART ─────────────────────────────────── */

esp_err_t ble_uart_init(void);
esp_err_t ble_uart_send(const uint8_t *data, size_t len);
int      ble_uart_receive(uint8_t *buf, size_t max_len);
bool     ble_uart_is_connected(void);
typedef void (*ble_uart_rx_cb_t)(const uint8_t *data, size_t len, void *ctx);
esp_err_t ble_uart_register_rx_cb(ble_uart_rx_cb_t cb, void *ctx);

/* ── Phase 9: BLE Extended Advertising ────────── */

typedef uint8_t ble_adv_ext_set_handle_t;

esp_err_t ble_adv_ext_create_set(uint8_t phy, const char *tag, ble_adv_ext_set_handle_t *handle);
esp_err_t ble_adv_ext_set_data(ble_adv_ext_set_handle_t handle, const uint8_t *data, uint16_t len);
esp_err_t ble_adv_ext_set_params(ble_adv_ext_set_handle_t handle, uint32_t interval_min_ms, uint32_t interval_max_ms);
esp_err_t ble_adv_ext_start(ble_adv_ext_set_handle_t handle, uint32_t duration_ms);
esp_err_t ble_adv_ext_stop(ble_adv_ext_set_handle_t handle);
esp_err_t ble_adv_ext_destroy_set(ble_adv_ext_set_handle_t handle);

esp_err_t ble_adv_ext_set_periodic_data(ble_adv_ext_set_handle_t handle, const uint8_t *data, uint16_t len);

esp_err_t ble_adv_ext_long_range_beacon(const char *name, uint32_t interval_ms);
esp_err_t ble_adv_ext_2m_scan_rsp(const uint8_t *data, uint16_t len);
void     ble_adv_ext_cleanup_all(void);

/* ── Phase 9: Proprietary Scan Formats ────────── */

typedef struct {
    char     type[32];
    bool     has_battery;
    uint8_t  battery_level;
    bool     is_apple;
    bool     is_samsung;
    bool     is_tile;
    bool     is_findmy;
    bool     is_swiftpair;
    uint16_t manufacturer;
} proprietary_scan_result_t;

void ble_scan_proprietary_feed(const uint8_t *addr, uint16_t manufacturer,
                                const uint8_t *manuf_data, uint8_t field_len);
int  ble_scan_proprietary_get_results(proprietary_scan_result_t *results, int max);
void ble_scan_proprietary_clear(void);
int  ble_scan_proprietary_get_count(void);

/* ── Phase 9: BLE MITM Proxy ──────────────────── */

typedef bool (*mitm_intercept_cb_t)(uint16_t attr_handle, uint8_t *data,
                                     uint16_t *len, void *ctx);

typedef struct {
    uint16_t handle;
    uint16_t uuid;
    uint8_t  properties;
    uint8_t  value[128];
    uint16_t value_len;
} mitm_char_t;

typedef struct {
    uint16_t    start_handle;
    uint16_t    end_handle;
    int         char_count;
    mitm_char_t chars[16];
} mitm_service_t;

typedef struct {
    bool     active;
    bool     central_connected;
    bool     peripheral_connected;
    int      services_discovered;
    char     state_str[16];
    uint8_t  target_addr[6];
    char     target_name[64];
} ble_mitm_status_t;

esp_err_t ble_mitm_start(const uint8_t *target_addr, const char *target_name, uint32_t scan_timeout_ms);
esp_err_t ble_mitm_stop(void);
bool     ble_mitm_is_active(void);
ble_mitm_status_t ble_mitm_get_status(void);
esp_err_t ble_mitm_register_intercept_cb(mitm_intercept_cb_t cb, void *ctx);
int      ble_mitm_get_discovered_services(mitm_service_t *services, int max);
