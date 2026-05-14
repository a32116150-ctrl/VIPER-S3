#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

typedef enum {
    RESPONDER_LLMNR = 1,
    RESPONDER_NBTNS = 2,
    RESPONDER_MDNS  = 4,
    RESPONDER_ALL   = 7,
} responder_proto_t;

esp_err_t responder_start(responder_proto_t protocols);
esp_err_t responder_stop(void);
bool     responder_is_running(void);
uint32_t responder_get_poisoned_count(void);

esp_err_t smb_honeypot_start(uint16_t port);
esp_err_t smb_honeypot_stop(void);
uint32_t smb_honeypot_get_capture_count(void);
