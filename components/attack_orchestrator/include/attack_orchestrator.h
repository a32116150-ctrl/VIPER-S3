#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

typedef enum {
    CHAIN_NONE = 0,
    CHAIN_WIFI_RECON_EVIL_TWIN,
    CHAIN_PLUG_AND_PWN,
    CHAIN_CONFERENCE_RECON,
    CHAIN_BLE_MITM,
    CHAIN_CUSTOM,
} attack_chain_t;

typedef enum {
    TRIGGER_NONE = 0,
    TRIGGER_MOTION,
    TRIGGER_NEW_CLIENT,
    TRIGGER_HANDSHAKE_CAPTURED,
    TRIGGER_BLE_DEVICE_SEEN,
    TRIGGER_SCHEDULED,
} trigger_type_t;

typedef struct {
    trigger_type_t type;
    union {
        struct { int motion_threshold; } motion;
        struct { } new_client;
        struct { } handshake;
        struct { uint8_t target_addr[6]; } ble_device;
        struct { uint32_t interval_ms; bool repeat; } scheduled;
    };
    void (*action)(void *arg);
    void *arg;
    bool enabled;
} trigger_cfg_t;

esp_err_t attack_orchestrator_start(void);
esp_err_t attack_orchestrator_stop(void);

esp_err_t attack_orchestrator_run_chain(attack_chain_t chain);
esp_err_t attack_orchestrator_stop_chain(void);
attack_chain_t attack_orchestrator_get_active_chain(void);
bool   attack_orchestrator_is_busy(void);

esp_err_t attack_orchestrator_register_trigger(const trigger_cfg_t *cfg);
esp_err_t attack_orchestrator_unregister_trigger(trigger_type_t type);
void     attack_orchestrator_check_triggers(void);

esp_err_t attack_orchestrator_schedule(uint32_t interval_ms, attack_chain_t chain);
esp_err_t attack_orchestrator_unschedule(void);

typedef struct {
    uint32_t uptime_ms;
    uint32_t heap_free;
    uint32_t heap_min;
    uint32_t wifi_mode;
    bool     ble_active;
    bool     camera_active;
    bool     usb_active;
    uint32_t credentials_captured;
    uint32_t hashes_captured;
    uint32_t chains_executed;
} system_health_t;

void attack_orchestrator_get_health(system_health_t *health);
