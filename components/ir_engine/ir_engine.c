#include "ir_engine.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "driver/rmt_tx.h"
#include "driver/rmt_rx.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>

static const char *TAG = "IR";

#define IR_RX_BUF_SIZE 1024
#define IR_LEARNED_DIR "/viper/ir"

static bool s_initialized = false;
static int s_tx_gpio = -1;
static int s_rx_gpio = -1;

static rmt_channel_handle_t s_tx_channel = NULL;
static rmt_channel_handle_t s_rx_channel = NULL;
static rmt_encoder_handle_t s_copy_encoder = NULL;

static rmt_symbol_word_t s_rx_buf[IR_RX_BUF_SIZE];

static ir_capture_t s_last_capture;
static volatile bool s_capturing = false;
static volatile bool s_capture_ready = false;
static SemaphoreHandle_t s_ir_mutex = NULL;

static const uint32_t NEC_CARRIER_HZ = 38000;

static rmt_receive_config_t s_rx_cfg = {
    .signal_range_min_ns = 500,
    .signal_range_max_ns = 1000000,
};

static bool rx_done_cb(rmt_channel_handle_t channel, const rmt_rx_done_event_data_t *edata, void *user_data)
{
    if (s_capturing && edata && edata->received_symbols && edata->num_symbols > 0) {
        int j = 0;
        for (int i = 0; i < edata->num_symbols && j < IR_SIGNAL_MAX_LEN; i++) {
            s_last_capture.pulses[j++] = edata->received_symbols[i].duration0;
            if (j < IR_SIGNAL_MAX_LEN) {
                s_last_capture.pulses[j++] = edata->received_symbols[i].duration1;
            }
        }
        s_last_capture.pulse_count = j;
        s_capture_ready = true;
        s_capturing = false;
    }
    return true;
}

static void build_nec_pulses(uint16_t addr, uint16_t cmd, uint32_t *pulses, uint32_t *count)
{
    uint32_t bits = 0;
    bits = ((uint32_t)addr & 0xFF) | (((uint32_t)~addr & 0xFF) << 8) |
           (((uint32_t)cmd & 0xFF) << 16) | (((uint32_t)~cmd & 0xFF) << 24);

    uint32_t idx = 0;
    pulses[idx++] = 9000;
    pulses[idx++] = 4500;

    for (int i = 0; i < 32; i++) {
        if (bits & 1) {
            pulses[idx++] = 560;
            pulses[idx++] = 1690;
        } else {
            pulses[idx++] = 560;
            pulses[idx++] = 560;
        }
        bits >>= 1;
    }

    pulses[idx++] = 560;

    *count = idx;
}

static int decode_nec_raw(const uint32_t *pulses, uint32_t count, uint16_t *addr, uint16_t *cmd)
{
    if (count < 68) return -1;

    if (pulses[0] < 8000 || pulses[0] > 10000) return -1;
    if (pulses[1] < 4000 || pulses[1] > 5000) return -1;

    uint32_t bits = 0;
    int bit_idx = 0;

    for (int i = 2; i < count - 1 && bit_idx < 32; i += 2) {
        if (pulses[i] > 300 && pulses[i] < 800) {
            if (pulses[i + 1] > 300 && pulses[i + 1] < 800) {
            } else if (pulses[i + 1] > 1400 && pulses[i + 1] < 2000) {
                bits |= (1 << bit_idx);
            } else {
                return -1;
            }
            bit_idx++;
        }
    }

    if (bit_idx < 32) return -1;

    uint8_t raddr = bits & 0xFF;
    uint8_t raddr_inv = (bits >> 8) & 0xFF;
    uint8_t rcmd = (bits >> 16) & 0xFF;
    uint8_t rcmd_inv = (bits >> 24) & 0xFF;

    if (raddr != (uint8_t)~raddr_inv || rcmd != (uint8_t)~rcmd_inv) return -1;

    *addr = raddr;
    *cmd = rcmd;
    return 0;
}

esp_err_t ir_engine_init(int tx_gpio, int rx_gpio)
{
    if (s_initialized) return ESP_OK;

    if (!s_ir_mutex) {
        s_ir_mutex = xSemaphoreCreateMutex();
    }

    s_tx_gpio = tx_gpio;
    s_rx_gpio = rx_gpio;

    rmt_tx_channel_config_t tx_cfg = {
        .gpio_num = tx_gpio >= 0 ? tx_gpio : GPIO_NUM_NC,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 1000000,
        .mem_block_symbols = 128,
    };

    if (tx_gpio >= 0) {
        if (rmt_new_tx_channel(&tx_cfg, &s_tx_channel) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create RMT TX channel");
        } else {
            rmt_copy_encoder_config_t enc_cfg = {};
            if (rmt_new_copy_encoder(&enc_cfg, &s_copy_encoder) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to create RMT copy encoder");
            } else if (rmt_enable(s_tx_channel) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to enable RMT TX");
            } else {
                ESP_LOGI(TAG, "IR TX ready on GPIO%d", tx_gpio);
            }
        }
    }

    if (rx_gpio >= 0) {
        rmt_rx_channel_config_t rx_cfg = {
            .gpio_num = rx_gpio,
            .clk_src = RMT_CLK_SRC_DEFAULT,
            .resolution_hz = 1000000,
            .mem_block_symbols = 512,
        };

        if (rmt_new_rx_channel(&rx_cfg, &s_rx_channel) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create RMT RX channel");
        } else {
            rmt_rx_event_callbacks_t cbs = { .on_recv_done = rx_done_cb };
            rmt_rx_register_event_callbacks(s_rx_channel, &cbs, NULL);
            if (rmt_enable(s_rx_channel) != ESP_OK) {
                ESP_LOGE(TAG, "Failed to enable RMT RX");
            } else {
                ESP_LOGI(TAG, "IR RX ready on GPIO%d", rx_gpio);
            }
        }
    }

    s_initialized = true;
    ESP_LOGI(TAG, "IR engine initialized (TX:GPIO%d, RX:GPIO%d)", tx_gpio, rx_gpio);
    return ESP_OK;
}

esp_err_t ir_engine_deinit(void)
{
    if (!s_initialized) return ESP_OK;

    ir_capture_stop();

    if (s_tx_channel) {
        rmt_disable(s_tx_channel);
        rmt_del_channel(s_tx_channel);
        s_tx_channel = NULL;
    }
    if (s_rx_channel) {
        rmt_disable(s_rx_channel);
        rmt_del_channel(s_rx_channel);
        s_rx_channel = NULL;
    }
    if (s_copy_encoder) {
        rmt_del_encoder(s_copy_encoder);
        s_copy_encoder = NULL;
    }

    s_initialized = false;
    ESP_LOGI(TAG, "IR engine deinitialized");
    return ESP_OK;
}

esp_err_t ir_send_raw(const uint32_t *pulses, uint32_t count, uint32_t freq_khz)
{
    if (!s_tx_channel || !pulses || count == 0) return ESP_ERR_INVALID_STATE;

    rmt_symbol_word_t *items = malloc(count * sizeof(rmt_symbol_word_t));
    if (!items) return ESP_ERR_NO_MEM;

    for (uint32_t i = 0; i < count; i += 2) {
        items[i / 2].level0 = 1;
        items[i / 2].duration0 = pulses[i];
        items[i / 2].level1 = 0;
        items[i / 2].duration1 = (i + 1 < count) ? pulses[i + 1] : 0;
    }

    uint32_t symbol_count = (count + 1) / 2;

    rmt_transmit_config_t tx_cfg = {
        .loop_count = 0,
        .flags = { .eot_level = 0 },
    };

    esp_err_t ret = rmt_transmit(s_tx_channel, s_copy_encoder, items, symbol_count * sizeof(rmt_symbol_word_t), &tx_cfg);
    free(items);

    if (ret == ESP_OK) {
        rmt_tx_wait_all_done(s_tx_channel, 1000);
    }

    return ret;
}

esp_err_t ir_send_nec(uint16_t address, uint16_t command)
{
    uint32_t pulses[IR_SIGNAL_MAX_LEN];
    uint32_t count = 0;
    build_nec_pulses(address, command, pulses, &count);
    return ir_send_raw(pulses, count, NEC_CARRIER_HZ);
}

esp_err_t ir_send_nec_repeat(uint16_t address, uint16_t command, int times, uint32_t interval_ms)
{
    for (int i = 0; i < times; i++) {
        esp_err_t ret = ir_send_nec(address, command);
        if (ret != ESP_OK) return ret;
        if (i < times - 1) vTaskDelay(pdMS_TO_TICKS(interval_ms));
    }
    return ESP_OK;
}

esp_err_t ir_send_samsung(uint16_t address, uint16_t command)
{
    uint32_t pulses[IR_SIGNAL_MAX_LEN];
    uint32_t count = 0;

    pulses[count++] = 4500;
    pulses[count++] = 4500;

    uint32_t data = ((uint32_t)command << 8) | (address & 0xFF);
    for (int i = 0; i < 16; i++) {
        if (data & 0x8000) {
            pulses[count++] = 560;
            pulses[count++] = 1690;
        } else {
            pulses[count++] = 560;
            pulses[count++] = 560;
        }
        data <<= 1;
    }

    pulses[count++] = 560;

    return ir_send_raw(pulses, count, NEC_CARRIER_HZ);
}

esp_err_t ir_send_sony(uint16_t command, uint8_t address, int bits)
{
    uint32_t pulses[IR_SIGNAL_MAX_LEN];
    uint32_t count = 0;

    uint32_t data = ((uint32_t)address << 7) | command;
    int total_bits = 7 + bits;

    pulses[count++] = 2400;
    pulses[count++] = 600;

    for (int i = 0; i < total_bits; i++) {
        if (data & 1) {
            pulses[count++] = 1200;
        } else {
            pulses[count++] = 600;
        }
        pulses[count++] = 600;
        data >>= 1;
    }

    return ir_send_raw(pulses, count, 40000);
}

esp_err_t ir_send_signal(const ir_signal_t *signal)
{
    if (!signal) return ESP_ERR_INVALID_ARG;

    switch (signal->protocol) {
        case IR_PROTOCOL_NEC:
            return ir_send_nec(signal->address, signal->command);
        case IR_PROTOCOL_SAMSUNG:
            return ir_send_samsung(signal->address, signal->command);
        case IR_PROTOCOL_RAW:
            return ir_send_raw(signal->raw_data, signal->raw_len, 38000);
        default:
            return ir_send_raw(signal->raw_data, signal->raw_len, 38000);
    }
}

esp_err_t ir_capture_start(uint32_t timeout_ms)
{
    if (!s_rx_channel) return ESP_ERR_INVALID_STATE;

    if (s_ir_mutex) xSemaphoreTake(s_ir_mutex, portMAX_DELAY);
    if (s_capturing) { if (s_ir_mutex) xSemaphoreGive(s_ir_mutex); return ESP_OK; }

    s_capturing = true;
    s_capture_ready = false;
    memset(&s_last_capture, 0, sizeof(s_last_capture));

    esp_err_t ret = rmt_receive(s_rx_channel, s_rx_buf, sizeof(s_rx_buf), &s_rx_cfg);

    if (timeout_ms > 0) {
        if (s_ir_mutex) xSemaphoreGive(s_ir_mutex);
        vTaskDelay(pdMS_TO_TICKS(timeout_ms));
        if (s_ir_mutex) xSemaphoreTake(s_ir_mutex, portMAX_DELAY);
        if (s_capturing) {
            rmt_disable(s_rx_channel);
            s_capturing = false;
            rmt_enable(s_rx_channel);
        }
    }

    if (s_ir_mutex) xSemaphoreGive(s_ir_mutex);
    return ret;
}

esp_err_t ir_capture_stop(void)
{
    if (s_ir_mutex) xSemaphoreTake(s_ir_mutex, portMAX_DELAY);
    s_capturing = false;
    if (s_rx_channel) rmt_disable(s_rx_channel);
    if (s_ir_mutex) xSemaphoreGive(s_ir_mutex);
    return ESP_OK;
}

bool ir_capture_is_ready(void)
{
    return s_capture_ready;
}

esp_err_t ir_capture_get(ir_capture_t *capture)
{
    if (!capture) return ESP_ERR_INVALID_ARG;
    if (!s_capture_ready) return ESP_ERR_INVALID_STATE;

    memcpy(capture, &s_last_capture, sizeof(ir_capture_t));
    capture->freq_khz = NEC_CARRIER_HZ;

    if (decode_nec_raw(capture->pulses, capture->pulse_count, &capture->address, &capture->command) == 0) {
        capture->protocol = IR_PROTOCOL_NEC;
    } else {
        capture->protocol = IR_PROTOCOL_UNKNOWN;
    }

    s_capture_ready = false;
    return ESP_OK;
}

esp_err_t ir_learn(const char *name, uint32_t timeout_ms)
{
    if (!name) return ESP_ERR_INVALID_ARG;

    ESP_LOGI(TAG, "Learning IR signal: %s (timeout: %lu ms)", name, timeout_ms);
    ir_capture_start(timeout_ms);

    int wait = 0;
    while (!s_capture_ready && wait < timeout_ms) {
        vTaskDelay(pdMS_TO_TICKS(10));
        wait += 10;
    }

    if (!s_capture_ready) {
        ESP_LOGW(TAG, "IR learn timeout: %s", name);
        return ESP_ERR_TIMEOUT;
    }

    ir_capture_t cap;
    ir_capture_get(&cap);

    char path[64];
    snprintf(path, sizeof(path), IR_LEARNED_DIR "/%s", name);

    char buf[4096];
    int off = snprintf(buf, sizeof(buf),
        "protocol=%d\naddr=%u\ncmd=%u\nfreq=%lu\ncount=%lu\npulses=",
        cap.protocol, cap.address, cap.command, cap.freq_khz, cap.pulse_count);
    for (uint32_t i = 0; i < cap.pulse_count && off < (int)sizeof(buf) - 12; i++) {
        off += snprintf(buf + off, sizeof(buf) - off, "%lu,", cap.pulses[i]);
    }
    buf[off] = '\0';

    esp_err_t ret = storage_write_file(path, (uint8_t *)buf, strlen(buf), false);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "IR signal learned: %s (%lu pulses)", name, cap.pulse_count);
    }
    return ret;
}

int ir_learned_list(char names[][64], int max)
{
    DIR *dir = opendir(IR_LEARNED_DIR);
    if (!dir) return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && count < max) {
        if (entry->d_type == DT_REG) {
            strncpy(names[count], entry->d_name, 63);
            names[count][63] = '\0';
            count++;
        }
    }
    closedir(dir);
    return count;
}

esp_err_t ir_learned_send(const char *name)
{
    if (!name) return ESP_ERR_INVALID_ARG;

    char path[64];
    snprintf(path, sizeof(path), IR_LEARNED_DIR "/%s", name);

    char buf[4096];
    size_t len = sizeof(buf);
    esp_err_t ret = storage_read_file(path, (uint8_t *)buf, len, &len);
    if (ret != ESP_OK) return ret;
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;
    buf[len] = '\0';

    uint32_t pulses[IR_SIGNAL_MAX_LEN];
    uint32_t count = 0;

    char *p = strstr(buf, "pulses=");
    if (!p) return ESP_ERR_INVALID_ARG;
    p += 7;

    char *token = strtok(p, ",");
    while (token && count < IR_SIGNAL_MAX_LEN) {
        pulses[count++] = atoi(token);
        token = strtok(NULL, ",");
    }

    if (count == 0) return ESP_ERR_INVALID_ARG;
    return ir_send_raw(pulses, count, NEC_CARRIER_HZ);
}

int ir_decode_nec(const uint32_t *pulses, uint32_t count, uint16_t *addr, uint16_t *cmd)
{
    return decode_nec_raw(pulses, count, addr, cmd);
}

int ir_encode_nec(uint16_t addr, uint16_t cmd, uint32_t *pulses, uint32_t *count)
{
    if (!pulses || !count) return -1;
    build_nec_pulses(addr, cmd, pulses, count);
    return 0;
}

int ir_codes_lookup(const char *brand, const char *device, ir_code_t *codes, int max)
{
    (void)brand; (void)device; (void)codes; (void)max;
    return 0;
}

int ir_codes_list_brands(char brands[][IR_BRAND_NAME_MAX], int max)
{
    (void)brands; (void)max;
    return 0;
}

int ir_codes_list_devices(const char *brand, char devices[][IR_DEVICE_NAME_MAX], int max)
{
    (void)brand; (void)devices; (void)max;
    return 0;
}
