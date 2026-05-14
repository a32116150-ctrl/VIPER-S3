#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "esp_camera.h"

#define CAM_MAX_RESULT_TEXT 256

extern const camera_config_t CAMERA_CONFIG_DEFAULT;

esp_err_t camera_engine_init(const camera_config_t *cfg);
esp_err_t camera_engine_deinit(void);

bool    camera_engine_is_initialized(void);

esp_err_t camera_engine_capture(uint8_t **out_buf, size_t *out_len, int *out_width, int *out_height);

esp_err_t camera_engine_save_jpeg(const char *path);

esp_err_t camera_engine_start_stream(void);
esp_err_t camera_engine_stop_stream(void);
bool     camera_engine_stream_is_active(void);

esp_err_t camera_engine_set_resolution(framesize_t res);
esp_err_t camera_engine_set_pixel_format(pixformat_t fmt);

bool     camera_engine_motion_detected(void);
esp_err_t camera_engine_set_motion_threshold(int threshold);
int      camera_engine_get_motion_value(void);

esp_err_t camera_engine_decode_qr(const uint8_t *image, int width, int height,
                                   char *result, size_t max_len);

typedef void (*camera_stream_cb_t)(const uint8_t *jpeg, size_t len, void *ctx);
esp_err_t camera_engine_register_stream_cb(camera_stream_cb_t cb, void *ctx);

esp_err_t camera_engine_take_burst(const char *dir, int count);
