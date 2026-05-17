#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define NFC_UID_MAX_LEN 7
#define NFC_TAG_TYPE_MAX 32
#define NFC_NDEF_MAX_LEN 512
#define NFC_SECTOR_COUNT 64
#define NFC_BLOCKS_PER_SECTOR 4

typedef enum {
    NFC_TAG_MIFARE_CLASSIC_1K,
    NFC_TAG_MIFARE_CLASSIC_4K,
    NFC_TAG_MIFARE_ULTRALIGHT,
    NFC_TAG_MIFARE_DESFIRE,
    NFC_TAG_TYPE_UNKNOWN,
} nfc_tag_type_t;

typedef struct {
    bool     present;
    nfc_tag_type_t type;
    uint8_t  uid[NFC_UID_MAX_LEN];
    uint8_t  uid_len;
    char     tag_type[NFC_TAG_TYPE_MAX];
    uint16_t sector_count;
} nfc_tag_info_t;

typedef struct {
    uint8_t  data[16];
    bool     has_data;
} nfc_sector_t;

typedef struct {
    bool     valid;
    char     uri[256];
    char     text[512];
    uint8_t  raw[NFC_NDEF_MAX_LEN];
    uint16_t raw_len;
} nfc_ndef_t;

typedef enum {
    NFC_PN532_MODE_UART,
    NFC_PN532_MODE_I2C,
} nfc_pn532_mode_t;

esp_err_t nfc_engine_init(nfc_pn532_mode_t mode, int uart_tx, int uart_rx, int i2c_sda, int i2c_scl);
esp_err_t nfc_engine_deinit(void);

esp_err_t nfc_detect_tag(nfc_tag_info_t *info);
esp_err_t nfc_read_sector(uint8_t sector, uint8_t key[6], nfc_sector_t *data, int num_blocks);
esp_err_t nfc_write_sector(uint8_t sector, uint8_t key[6], const nfc_sector_t *data);
esp_err_t nfc_read_ndef(nfc_ndef_t *ndef);
esp_err_t nfc_write_ndef(const nfc_ndef_t *ndef);

esp_err_t nfc_emulate_start(const uint8_t *uid, uint8_t uid_len,
                             const nfc_sector_t *sectors, int count);
esp_err_t nfc_emulate_stop(void);
bool     nfc_emulate_is_active(void);

int  nfc_dump_tag(uint8_t key[6], nfc_sector_t *sectors, int max);
esp_err_t nfc_clone_tag(uint8_t key[6]);

const char *nfc_tag_type_str(nfc_tag_type_t type);
