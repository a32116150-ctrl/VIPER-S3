#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define CAM_MAX_RESULT_TEXT 256

typedef enum {
    CAM_RES_QVGA   = 0, /* 320x240 */
    CAM_RES_VGA    = 1, /* 640x480 */
    CAM_RES_SVGA   = 2, /* 800x600 */
    CAM_RES_HD     = 3, /* 1280x720 */
    CAM_RES_FHD    = 4, /* 1920x1080 */
    CAM_RES_3MP    = 5, /* 2048x1536 */
} cam_resolution_t;

typedef enum {
    CAM_PIXEL_JPEG   = 0,
    CAM_PIXEL_GRAY   = 1,
    CAM_PIXEL_RGB565 = 2,
    CAM_PIXEL_YUV422 = 3,
} cam_pixel_format_t;

typedef struct {
    int pin_pwdn;
    int pin_reset;
    int pin_xclk;
    int pin_siod;
    int pin_sioc;
    int pin_d7;
    int pin_d6;
    int pin_d5;
    int pin_d4;
    int pin_d3;
    int pin_d2;
    int pin_d1;
    int pin_d0;
    int pin_vsync;
    int pin_href;
    int pin_pclk;
    int xclk_freq_hz;
    cam_resolution_t resolution;
    cam_pixel_format_t pixel_format;
} camera_config_t;

extern const camera_config_t CAMERA_CONFIG_DEFAULT;

esp_err_t camera_engine_init(const camera_config_t *cfg);
esp_err_t camera_engine_deinit(void);

bool    camera_engine_is_initialized(void);

esp_err_t camera_engine_capture(uint8_t **out_buf, size_t *out_len, int *out_width, int *out_height);

esp_err_t camera_engine_save_jpeg(const char *path);

esp_err_t camera_engine_start_stream(void);
esp_err_t camera_engine_stop_stream(void);
bool     camera_engine_stream_is_active(void);

esp_err_t camera_engine_set_resolution(cam_resolution_t res);
esp_err_t camera_engine_set_pixel_format(cam_pixel_format_t fmt);

bool     camera_engine_motion_detected(void);
esp_err_t camera_engine_set_motion_threshold(int threshold);
int      camera_engine_get_motion_value(void);

esp_err_t camera_engine_decode_qr(const uint8_t *image, int width, int height,
                                   char *result, size_t max_len);

typedef void (*camera_stream_cb_t)(const uint8_t *jpeg, size_t len, void *ctx);
esp_err_t camera_engine_register_stream_cb(camera_stream_cb_t cb, void *ctx);

esp_err_t camera_engine_take_burst(const char *dir, int count);
