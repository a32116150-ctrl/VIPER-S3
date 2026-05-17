#include "nfc_engine.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "driver/uart.h"
#include "driver/i2c.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "NFC";

#define PN532_UART_PORT  UART_NUM_1
#define PN532_I2C_PORT   I2C_NUM_0
#define PN532_I2C_ADDR   0x24
#define PN532_BAUD       115200
#define PN532_TIMEOUT_MS 1000
#define PN532_BUFFER_LEN 64

static bool s_initialized = false;
static nfc_pn532_mode_t s_mode = NFC_PN532_MODE_UART;
static int s_uart_tx = -1, s_uart_rx = -1;
static int s_i2c_sda = -1, s_i2c_scl = -1;

static uint8_t s_rx_buf[PN532_BUFFER_LEN];
static uint8_t s_tx_buf[PN532_BUFFER_LEN];

static nfc_tag_info_t s_last_tag;
static bool s_emulating = false;

static const uint8_t PN532_PREAMBLE = 0x00;
static const uint8_t PN532_STARTCODE1 = 0x00;
static const uint8_t PN532_STARTCODE2 = 0xFF;
static const uint8_t PN532_POSTAMBLE = 0x00;

static uint8_t pn532_checksum(const uint8_t *data, int len)
{
    uint8_t sum = 0;
    for (int i = 0; i < len; i++) sum += data[i];
    return (~sum + 1) & 0xFF;
}

static void uart_write(const uint8_t *data, int len)
{
    uart_write_bytes(PN532_UART_PORT, data, len);
}

static int uart_read(uint8_t *buf, int max_len, uint32_t timeout_ms)
{
    if (max_len <= 0) max_len = PN532_BUFFER_LEN;
    int len = uart_read_bytes(PN532_UART_PORT, buf, max_len, pdMS_TO_TICKS(timeout_ms));
    return len;
}

static void i2c_write(const uint8_t *data, int len)
{
    i2c_master_write_to_device(PN532_I2C_PORT, PN532_I2C_ADDR, data, len, pdMS_TO_TICKS(100));
}

static int i2c_read(uint8_t *buf, int max_len, uint32_t timeout_ms)
{
    if (max_len <= 0) max_len = PN532_BUFFER_LEN;
    esp_err_t ret = i2c_master_read_from_device(PN532_I2C_PORT, PN532_I2C_ADDR, buf, max_len, pdMS_TO_TICKS(timeout_ms));
    if (ret != ESP_OK) return 0;
    return max_len;
}

static void pn532_write_command(const uint8_t *cmd, int cmd_len)
{
    int pkt_len = cmd_len + 1;
    uint8_t pkt[PN532_BUFFER_LEN];
    int off = 0;

    pkt[off++] = PN532_PREAMBLE;
    pkt[off++] = PN532_STARTCODE1;
    pkt[off++] = PN532_STARTCODE2;
    pkt[off++] = pkt_len;
    pkt[off++] = ~pkt_len + 1;
    pkt[off++] = PN532_PREAMBLE;

    uint8_t dsum = PN532_PREAMBLE + cmd[0];
    for (int i = 1; i < cmd_len; i++) dsum += cmd[i];
    dsum = ~dsum + 1;

    memcpy(pkt + off, cmd, cmd_len);
    off += cmd_len;
    pkt[off++] = dsum;
    pkt[off++] = PN532_POSTAMBLE;

    if (s_mode == NFC_PN532_MODE_UART) uart_write(pkt, off);
    else i2c_write(pkt, off);
}

static int pn532_read_response(uint8_t *resp, int max_len, uint32_t timeout_ms)
{
    uint8_t buf[PN532_BUFFER_LEN];
    int len;

    if (s_mode == NFC_PN532_MODE_UART) {
        len = uart_read(buf, PN532_BUFFER_LEN, timeout_ms);
    } else {
        uint8_t status;
        for (int i = 0; i < timeout_ms / 5; i++) {
            if (i2c_read(&status, 1, 10) > 0 && status == 0x01) break;
            vTaskDelay(pdMS_TO_TICKS(5));
        }
        len = i2c_read(buf, PN532_BUFFER_LEN, timeout_ms);
    }

    if (len <= 0) return -1;

    int pos = 0;
    while (pos < len - 2) {
        if (buf[pos] == 0x00 && buf[pos + 1] == 0x00 && buf[pos + 2] == 0xFF) {
            int body_len = buf[pos + 3];
            int checksum = buf[pos + 4];
            if (body_len + checksum != 0xFF) return -1;

            int resp_start = pos + 5;
            int resp_len = body_len - 1;

            if (resp_len > 0 && resp_len <= max_len) {
                memcpy(resp, buf + resp_start, resp_len);
                return resp_len;
            }
            return -1;
        }
        pos++;
    }

    return -1;
}

static bool pn532_send_command(const uint8_t *cmd, int cmd_len, uint8_t *resp, int *resp_len)
{
    pn532_write_command(cmd, cmd_len);

    int retries = 5;
    while (retries--) {
        vTaskDelay(pdMS_TO_TICKS(20));
        int len = pn532_read_response(resp, PN532_BUFFER_LEN, 100);
        if (len > 0) {
            if (resp_len) *resp_len = len;
            return true;
        }
    }

    return false;
}

static bool pn532_wakeup(void)
{
    if (s_mode == NFC_PN532_MODE_I2C) {
        uint8_t wake[] = {0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        i2c_write(wake, sizeof(wake));
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    uint8_t fw_cmd[] = {0x02, 0x02};
    uint8_t resp[PN532_BUFFER_LEN];
    int resp_len = 0;

    if (!pn532_send_command(fw_cmd, sizeof(fw_cmd), resp, &resp_len)) {
        return false;
    }

    if (resp_len >= 2) {
        ESP_LOGI(TAG, "PN532 firmware: v%u.%u", resp[0], resp[1]);
        return true;
    }

    return false;
}

static bool pn532_configure(void)
{
    uint8_t sam_cmd[] = {0x14, 0x01, 0x01, 0x00};
    uint8_t resp[PN532_BUFFER_LEN];
    int resp_len = 0;

    bool ok = pn532_send_command(sam_cmd, sizeof(sam_cmd), resp, &resp_len);
    if (!ok) {
        ESP_LOGE(TAG, "Failed to configure SAM");
        return false;
    }

    ESP_LOGI(TAG, "PN532 SAM configured");
    return true;
}

static bool pn532_detect_tag(nfc_tag_info_t *info)
{
    if (!info) return false;

    uint8_t inlist_cmd[] = {0x4A, 0x01, 0x01};
    uint8_t resp[PN532_BUFFER_LEN];
    int resp_len = 0;

    if (!pn532_send_command(inlist_cmd, sizeof(inlist_cmd), resp, &resp_len)) {
        memset(info, 0, sizeof(nfc_tag_info_t));
        return false;
    }

    if (resp_len < 3 || resp[0] != 0x01) {
        memset(info, 0, sizeof(nfc_tag_info_t));
        return false;
    }

    info->present = true;
    info->uid_len = resp[1];
    if (info->uid_len > NFC_UID_MAX_LEN) info->uid_len = NFC_UID_MAX_LEN;
    memcpy(info->uid, resp + 2, info->uid_len);

    uint8_t sak = resp[2 + info->uid_len];
    if (sak == 0x08 || sak == 0x88) {
        info->type = NFC_TAG_MIFARE_CLASSIC_1K;
        info->sector_count = 16;
        snprintf(info->tag_type, sizeof(info->tag_type), "MIFARE Classic 1K");
    } else if (sak == 0x18) {
        info->type = NFC_TAG_MIFARE_CLASSIC_4K;
        info->sector_count = 64;
        snprintf(info->tag_type, sizeof(info->tag_type), "MIFARE Classic 4K");
    } else if (sak == 0x00) {
        info->type = NFC_TAG_MIFARE_ULTRALIGHT;
        info->sector_count = 16;
        snprintf(info->tag_type, sizeof(info->tag_type), "MIFARE Ultralight");
    } else if (sak == 0x20) {
        info->type = NFC_TAG_MIFARE_DESFIRE;
        info->sector_count = 64;
        snprintf(info->tag_type, sizeof(info->tag_type), "MIFARE DESFire");
    } else {
        info->type = NFC_TAG_TYPE_UNKNOWN;
        info->sector_count = 0;
        snprintf(info->tag_type, sizeof(info->tag_type), "Unknown(SAK=0x%02X)", sak);
    }

    memcpy(&s_last_tag, info, sizeof(nfc_tag_info_t));
    return true;
}

esp_err_t nfc_engine_init(nfc_pn532_mode_t mode, int uart_tx, int uart_rx, int i2c_sda, int i2c_scl)
{
    if (s_initialized) return ESP_OK;

    s_mode = mode;
    s_uart_tx = uart_tx;
    s_uart_rx = uart_rx;
    s_i2c_sda = i2c_sda;
    s_i2c_scl = i2c_scl;

    if (mode == NFC_PN532_MODE_UART && uart_tx >= 0 && uart_rx >= 0) {
        uart_config_t cfg = {
            .baud_rate = PN532_BAUD,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        };
        uart_param_config(PN532_UART_PORT, &cfg);
        uart_set_pin(PN532_UART_PORT, uart_tx, uart_rx, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
        uart_driver_install(PN532_UART_PORT, PN532_BUFFER_LEN * 2, 0, 0, NULL, 0);
        ESP_LOGI(TAG, "NFC UART: TX=%d RX=%d", uart_tx, uart_rx);
    }

    if (mode == NFC_PN532_MODE_I2C && i2c_sda >= 0 && i2c_scl >= 0) {
        i2c_config_t cfg = {
            .mode = I2C_MODE_MASTER,
            .sda_io_num = i2c_sda,
            .scl_io_num = i2c_scl,
            .sda_pullup_en = GPIO_PULLUP_ENABLE,
            .scl_pullup_en = GPIO_PULLUP_ENABLE,
            .master.clk_speed = 100000,
        };
        i2c_param_config(PN532_I2C_PORT, &cfg);
        i2c_driver_install(PN532_I2C_PORT, I2C_MODE_MASTER, 0, 0, 0);
        ESP_LOGI(TAG, "NFC I2C: SDA=%d SCL=%d", i2c_sda, i2c_scl);
    }

    if (!pn532_wakeup()) {
        ESP_LOGW(TAG, "PN532 not detected — NFC unavailable");
        nfc_engine_deinit();
        return ESP_ERR_NOT_FOUND;
    }

    pn532_configure();

    s_initialized = true;
    ESP_LOGI(TAG, "NFC engine initialized");
    return ESP_OK;
}

esp_err_t nfc_engine_deinit(void)
{
    if (!s_initialized) return ESP_OK;

    nfc_emulate_stop();

    if (s_mode == NFC_PN532_MODE_UART && s_uart_tx >= 0) {
        uart_driver_delete(PN532_UART_PORT);
    }
    if (s_mode == NFC_PN532_MODE_I2C && s_i2c_sda >= 0) {
        i2c_driver_delete(PN532_I2C_PORT);
    }

    memset(&s_last_tag, 0, sizeof(s_last_tag));
    s_initialized = false;
    ESP_LOGI(TAG, "NFC engine deinitialized");
    return ESP_OK;
}

esp_err_t nfc_detect_tag(nfc_tag_info_t *info)
{
    if (!info) return ESP_ERR_INVALID_ARG;
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    pn532_detect_tag(info);
    return info->present ? ESP_OK : ESP_ERR_NOT_FOUND;
}

esp_err_t nfc_read_sector(uint8_t sector, uint8_t key[6], nfc_sector_t *data, int num_blocks)
{
    if (!data) return ESP_ERR_INVALID_ARG;
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    if (num_blocks > NFC_BLOCKS_PER_SECTOR) num_blocks = NFC_BLOCKS_PER_SECTOR;
    if (num_blocks <= 0) return ESP_ERR_INVALID_ARG;

    uint8_t block = sector * NFC_BLOCKS_PER_SECTOR;

    uint8_t auth_cmd[] = {0x40, 0x01, block, key[0], key[1], key[2], key[3], key[4], key[5]};
    uint8_t resp[PN532_BUFFER_LEN];
    int resp_len = 0;

    if (!pn532_send_command(auth_cmd, sizeof(auth_cmd), resp, &resp_len)) {
        return ESP_FAIL;
    }

    if (resp_len < 1 || resp[0] != 0x00) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    for (int i = 0; i < num_blocks; i++) {
        uint8_t read_cmd[] = {0x10, 0x01, (uint8_t)(block + i)};
        resp_len = 0;
        if (!pn532_send_command(read_cmd, sizeof(read_cmd), resp, &resp_len)) {
            return ESP_FAIL;
        }
        if (resp_len >= 16) {
            memcpy(data[i].data, resp, 16);
            data[i].has_data = true;
        }
    }

    return ESP_OK;
}

esp_err_t nfc_write_sector(uint8_t sector, uint8_t key[6], const nfc_sector_t *data)
{
    if (!data) return ESP_ERR_INVALID_ARG;
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    uint8_t block = sector * 4;

    uint8_t auth_cmd[] = {0x40, 0x01, block, key[0], key[1], key[2], key[3], key[4], key[5]};
    uint8_t resp[PN532_BUFFER_LEN];
    int resp_len = 0;

    if (!pn532_send_command(auth_cmd, sizeof(auth_cmd), resp, &resp_len)) {
        return ESP_FAIL;
    }

    for (int i = 0; i < 4; i++) {
        uint8_t write_cmd[18] = {0x20, 0x01, (uint8_t)(block + i)};
        memcpy(write_cmd + 3, data[i].data, 16);

        resp_len = 0;
        if (!pn532_send_command(write_cmd, sizeof(write_cmd), resp, &resp_len)) {
            return ESP_FAIL;
        }
    }

    return ESP_OK;
}

esp_err_t nfc_read_ndef(nfc_ndef_t *ndef)
{
    if (!ndef) return ESP_ERR_INVALID_ARG;
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    memset(ndef, 0, sizeof(nfc_ndef_t));

    uint8_t read_cmd[] = {0x10, 0x01, 0x04};
    uint8_t resp[PN532_BUFFER_LEN];
    int resp_len = 0;

    if (!pn532_send_command(read_cmd, sizeof(read_cmd), resp, &resp_len)) {
        return ESP_FAIL;
    }

    if (resp_len < 4) return ESP_ERR_INVALID_RESPONSE;

    uint16_t ndef_len = (resp[2] << 8) | resp[3];
    if (ndef_len > NFC_NDEF_MAX_LEN) ndef_len = NFC_NDEF_MAX_LEN;

    int off = 0;
    for (int block = 4; off < ndef_len && block < 40; block++) {
        read_cmd[2] = block;
        resp_len = 0;
        if (!pn532_send_command(read_cmd, sizeof(read_cmd), resp, &resp_len)) break;

        int copy = (resp_len < 16) ? resp_len : 16;
        if (off + copy > ndef_len) copy = ndef_len - off;
        memcpy(ndef->raw + off, resp, copy);
        off += copy;
    }

    ndef->raw_len = off;
    ndef->valid = true;

    if (off >= 3 && ndef->raw[0] == 0x03) {
        int type_len = ndef->raw[1];
        int payload_len = ndef->raw[2];
        int payload_start = 3 + type_len;

        if (type_len == 1 && ndef->raw[3] == 'U' && payload_start < off) {
            int uri_len = off - payload_start;
            if (uri_len > (int)sizeof(ndef->uri) - 1) uri_len = sizeof(ndef->uri) - 1;
            memcpy(ndef->uri, ndef->raw + payload_start, uri_len);
            ndef->uri[uri_len] = '\0';
        }
        if (type_len == 1 && ndef->raw[3] == 'T' && payload_start < off) {
            int lang_len = ndef->raw[payload_start];
            int text_start = payload_start + 1 + lang_len;
            if (text_start < off) {
                int text_len = off - text_start;
                if (text_len > (int)sizeof(ndef->text) - 1) text_len = sizeof(ndef->text) - 1;
                memcpy(ndef->text, ndef->raw + text_start, text_len);
                ndef->text[text_len] = '\0';
            }
        }
    }

    return ESP_OK;
}

esp_err_t nfc_write_ndef(const nfc_ndef_t *ndef)
{
    if (!ndef) return ESP_ERR_INVALID_ARG;
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    uint8_t buf[20];
    buf[0] = 0x20;
    buf[1] = 0x01;

    int max_blocks = ndef->raw_len / 16;
    if (ndef->raw_len % 16 != 0) max_blocks++;
    for (int i = 0; i < max_blocks; i++) {
        buf[2] = 4 + i;
        int copy = (ndef->raw_len - i * 16);
        if (copy > 16) copy = 16;
        if (copy < 0) break;

        memset(buf + 3, 0, 16);
        memcpy(buf + 3, ndef->raw + i * 16, copy);

        uint8_t resp[PN532_BUFFER_LEN];
        int resp_len = 0;
        if (!pn532_send_command(buf, 3 + 16, resp, &resp_len)) {
            return ESP_FAIL;
        }
    }

    return ESP_OK;
}

esp_err_t nfc_emulate_start(const uint8_t *uid, uint8_t uid_len,
                             const nfc_sector_t *sectors, int count)
{
    if (!uid || uid_len == 0) return ESP_ERR_INVALID_ARG;
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    uint8_t tginit_cmd[] = {0x50, 0x00, 0x08, 0x00};
    uint8_t resp[PN532_BUFFER_LEN];
    int resp_len = 0;

    if (!pn532_send_command(tginit_cmd, sizeof(tginit_cmd), resp, &resp_len)) {
        return ESP_FAIL;
    }

    s_emulating = true;
    ESP_LOGI(TAG, "NFC tag emulation started (UID: %d bytes)", uid_len);
    return ESP_OK;
}

esp_err_t nfc_emulate_stop(void)
{
    if (!s_emulating) return ESP_OK;

    uint8_t tgrelease_cmd[] = {0x52};
    uint8_t resp[PN532_BUFFER_LEN];
    int resp_len = 0;
    pn532_send_command(tgrelease_cmd, sizeof(tgrelease_cmd), resp, &resp_len);

    s_emulating = false;
    ESP_LOGI(TAG, "NFC tag emulation stopped");
    return ESP_OK;
}

bool nfc_emulate_is_active(void) { return s_emulating; }

int nfc_dump_tag(uint8_t key[6], nfc_sector_t *sectors, int max)
{
    if (!sectors || max <= 0) return 0;
    if (!s_initialized) return 0;

    nfc_tag_info_t info;
    if (!pn532_detect_tag(&info)) return 0;

    int total = info.sector_count;
    if (total > max) total = max;

    int read = 0;
    for (int i = 0; i < total; i++) {
        if (nfc_read_sector(i, key, &sectors[i * NFC_BLOCKS_PER_SECTOR], NFC_BLOCKS_PER_SECTOR) == ESP_OK) {
            for (int b = 0; b < 4; b++) sectors[i * 4 + b].has_data = true;
            read++;
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }

    ESP_LOGI(TAG, "Tag dump: %d/%d sectors read", read, total);
    return read;
}

esp_err_t nfc_clone_tag(uint8_t key[6])
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    nfc_tag_info_t info;
    if (!pn532_detect_tag(&info)) return ESP_ERR_NOT_FOUND;

    nfc_sector_t sectors[64 * 4];
    int count = nfc_dump_tag(key, sectors, 64);

    if (count == 0) return ESP_FAIL;

    char filename[64];
    char uid_str[32];
    snprintf(uid_str, sizeof(uid_str), "%02x%02x%02x%02x",
             info.uid[0], info.uid[1], info.uid[2], info.uid[3]);
    snprintf(filename, sizeof(filename), "/viper/nfc/clones/%s.bin", uid_str);

    size_t total = count * 4 * sizeof(nfc_sector_t);
    esp_err_t ret = storage_write_file(filename, (uint8_t *)sectors, total, false);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Tag cloned to %s (%d bytes, %d sectors)", filename, total, count);
    }
    return ret;
}

const char *nfc_tag_type_str(nfc_tag_type_t type)
{
    static const char *names[] = {
        "MIFARE Classic 1K",
        "MIFARE Classic 4K",
        "MIFARE Ultralight",
        "MIFARE DESFire",
        "Unknown",
    };
    if (type < NFC_TAG_TYPE_UNKNOWN) return names[type];
    return names[NFC_TAG_TYPE_UNKNOWN];
}
