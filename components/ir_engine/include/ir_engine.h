#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define IR_SIGNAL_MAX_LEN 1024
#define IR_BRAND_NAME_MAX 32
#define IR_DEVICE_NAME_MAX 32

typedef enum {
    IR_PROTOCOL_NEC,
    IR_PROTOCOL_SONY,
    IR_PROTOCOL_RC5,
    IR_PROTOCOL_RC6,
    IR_PROTOCOL_SAMSUNG,
    IR_PROTOCOL_RAW,
    IR_PROTOCOL_UNKNOWN,
} ir_protocol_t;

typedef struct {
    ir_protocol_t protocol;
    uint16_t address;
    uint16_t command;
    uint32_t raw_len;
    uint32_t raw_data[IR_SIGNAL_MAX_LEN];
} ir_signal_t;

typedef struct {
    uint32_t pulses[IR_SIGNAL_MAX_LEN];
    uint32_t pulse_count;
    ir_protocol_t protocol;
    uint16_t address;
    uint16_t command;
    uint32_t freq_khz;
} ir_capture_t;

typedef struct {
    char brand[IR_BRAND_NAME_MAX];
    char device[IR_DEVICE_NAME_MAX];
    uint16_t address;
    uint16_t command;
    ir_protocol_t protocol;
} ir_code_t;

esp_err_t ir_engine_init(int tx_gpio, int rx_gpio);
esp_err_t ir_engine_deinit(void);

esp_err_t ir_send_raw(const uint32_t *pulses, uint32_t count, uint32_t freq_khz);
esp_err_t ir_send_nec(uint16_t address, uint16_t command);
esp_err_t ir_send_nec_repeat(uint16_t address, uint16_t command, int times, uint32_t interval_ms);
esp_err_t ir_send_sony(uint16_t command, uint8_t address, int bits);
esp_err_t ir_send_samsung(uint16_t address, uint16_t command);
esp_err_t ir_send_signal(const ir_signal_t *signal);

esp_err_t ir_capture_start(uint32_t timeout_ms);
esp_err_t ir_capture_stop(void);
bool     ir_capture_is_ready(void);
esp_err_t ir_capture_get(ir_capture_t *capture);

int  ir_codes_lookup(const char *brand, const char *device, ir_code_t *codes, int max);
int  ir_codes_list_brands(char brands[][IR_BRAND_NAME_MAX], int max);
int  ir_codes_list_devices(const char *brand, char devices[][IR_DEVICE_NAME_MAX], int max);

esp_err_t ir_learn(const char *name, uint32_t timeout_ms);
int  ir_learned_list(char names[][64], int max);
esp_err_t ir_learned_send(const char *name);

int ir_decode_nec(const uint32_t *pulses, uint32_t count, uint16_t *addr, uint16_t *cmd);
int ir_encode_nec(uint16_t addr, uint16_t cmd, uint32_t *pulses, uint32_t *count);
