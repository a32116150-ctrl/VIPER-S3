#include "camera_engine.h"
#include "quirc.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_camera.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "CAMERA";

/* Default pin mapping for ESP32-S3 + OV3660 */
const camera_config_t CAMERA_CONFIG_DEFAULT = {
    .pin_pwdn       = -1,
    .pin_reset      = -1,
    .pin_xclk       = 15,
    .pin_siod       = 4,
    .pin_sioc       = 5,
    .pin_d7         = 16,
    .pin_d6         = 17,
    .pin_d5         = 18,
    .pin_d4         = 19,
    .pin_d3         = 20,
    .pin_d2         = 21,
    .pin_d1         = 38,
    .pin_d0         = 39,
    .pin_vsync      = 6,
    .pin_href       = 42,
    .pin_pclk       = 3,
    .xclk_freq_hz   = 20000000,
    .resolution     = CAM_RES_VGA,
    .pixel_format   = CAM_PIXEL_JPEG,
};

static bool s_initialized = false;
static bool s_streaming = false;
static TaskHandle_t s_stream_task = NULL;
static TaskHandle_t s_motion_task = NULL;

static int s_motion_threshold = 40;
static int s_motion_value = 0;
static volatile bool s_motion_flag = false;

static SemaphoreHandle_t s_frame_lock = NULL;
static uint8_t *s_latest_jpeg = NULL;
static size_t s_latest_jpeg_len = 0;
static int s_latest_w = 0;
static int s_latest_h = 0;

static camera_stream_cb_t s_stream_cb = NULL;
static void *s_stream_ctx = NULL;

static uint8_t *s_prev_gray = NULL;
static int s_prev_w = 0;
static int s_prev_h = 0;

/* ── Frame capture (via esp_camera) ─────────────── */

static esp_err_t capture_frame(uint8_t **buf, size_t *len, int *w, int *h,
                                cam_pixel_format_t fmt)
{
    (void)fmt;

    camera_fb_t *fb = esp_camera_fb_get();
    if (!fb) {
        ESP_LOGE(TAG, "Failed to get frame");
        return ESP_FAIL;
    }

    *buf = fb->buf;
    *len = fb->len;
    *w = fb->width;
    *h = fb->height;

    esp_camera_fb_return(fb);
    return ESP_OK;
}

/* ── Init / Deinit ──────────────────────────────── */

static esp_err_t init_camera_hw(const camera_config_t *cfg)
{
    camera_config_t c = {
        .pin_pwdn     = cfg->pin_pwdn,
        .pin_reset    = cfg->pin_reset,
        .pin_xclk     = cfg->pin_xclk,
        .pin_sscb_sda = cfg->pin_siod,
        .pin_sscb_scl = cfg->pin_sioc,
        .pin_d7       = cfg->pin_d7,
        .pin_d6       = cfg->pin_d6,
        .pin_d5       = cfg->pin_d5,
        .pin_d4       = cfg->pin_d4,
        .pin_d3       = cfg->pin_d3,
        .pin_d2       = cfg->pin_d2,
        .pin_d1       = cfg->pin_d1,
        .pin_d0       = cfg->pin_d0,
        .pin_vsync    = cfg->pin_vsync,
        .pin_href     = cfg->pin_href,
        .pin_pclk     = cfg->pin_pclk,
        .xclk_freq_hz = cfg->xclk_freq_hz,
        .ledc_timer   = LEDC_TIMER_0,
        .ledc_channel = LEDC_CHANNEL_0,
        .pixel_format = (cfg->pixel_format == CAM_PIXEL_JPEG) ?
                         PIXFORMAT_JPEG : PIXFORMAT_GRAYSCALE,
        .frame_size   = (framesize_t)(cfg->resolution),
        .jpeg_quality = 12,
        .fb_count     = 2,
        .grab_mode    = CAMERA_GRAB_WHEN_EMPTY,
    };

    esp_err_t ret = esp_camera_init(&c);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Camera init failed: %s", esp_err_to_name(ret));
        return ret;
    }

    sensor_t *s = esp_camera_sensor_get();
    if (s) {
        s->set_vflip(s, 1);
        s->set_hmirror(s, 1);
        s->set_brightness(s, 0);
        s->set_contrast(s, 0);
        s->set_saturation(s, 0);
        ESP_LOGI(TAG, "Sensor: %s", s->id.name);
    }

    return ESP_OK;
}

esp_err_t camera_engine_init(const camera_config_t *cfg)
{
    if (s_initialized) return ESP_OK;

    if (!cfg) cfg = &CAMERA_CONFIG_DEFAULT;

    s_frame_lock = xSemaphoreCreateMutex();
    if (!s_frame_lock) return ESP_ERR_NO_MEM;

    esp_err_t ret = init_camera_hw(cfg);
    if (ret != ESP_OK) {
        vSemaphoreDelete(s_frame_lock);
        s_frame_lock = NULL;
        return ret;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "Camera engine initialized");
    return ESP_OK;
}

esp_err_t camera_engine_deinit(void)
{
    if (!s_initialized) return ESP_OK;
    camera_engine_stop_stream();
    if (s_motion_task) {
        vTaskDelete(s_motion_task);
        s_motion_task = NULL;
    }
    esp_camera_deinit();
    if (s_frame_lock) {
        vSemaphoreDelete(s_frame_lock);
        s_frame_lock = NULL;
    }
    free(s_prev_gray);
    s_prev_gray = NULL;
    s_initialized = false;
    ESP_LOGI(TAG, "Camera engine deinitialized");
    return ESP_OK;
}

bool camera_engine_is_initialized(void) { return s_initialized; }

/* ── Capture ────────────────────────────────────── */

esp_err_t camera_engine_capture(uint8_t **out_buf, size_t *out_len,
                                 int *out_width, int *out_height)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    camera_fb_t *fb = esp_camera_fb_get();
    if (!fb) return ESP_FAIL;

    *out_buf = malloc(fb->len);
    if (!*out_buf) {
        esp_camera_fb_return(fb);
        return ESP_ERR_NO_MEM;
    }
    memcpy(*out_buf, fb->buf, fb->len);
    *out_len = fb->len;
    *out_width = fb->width;
    *out_height = fb->height;

    if (xSemaphoreTake(s_frame_lock, pdMS_TO_TICKS(100))) {
        free(s_latest_jpeg);
        s_latest_jpeg = malloc(fb->len);
        if (s_latest_jpeg) {
            memcpy(s_latest_jpeg, fb->buf, fb->len);
            s_latest_jpeg_len = fb->len;
            s_latest_w = fb->width;
            s_latest_h = fb->height;
        }
        xSemaphoreGive(s_frame_lock);
    }

    esp_camera_fb_return(fb);
    return ESP_OK;
}

/* ── Save JPEG ──────────────────────────────────── */

esp_err_t camera_engine_save_jpeg(const char *path)
{
    uint8_t *buf;
    size_t len;
    int w, h;

    ESP_RETURN_ON_ERROR(camera_engine_capture(&buf, &len, &w, &h), TAG, "capture");

    esp_err_t ret = storage_write_file(path, buf, len, false);
    free(buf);

    if (ret == ESP_OK) {
        char ts[64];
        snprintf(ts, sizeof(ts), "img_%lld.jpg", (long long)(esp_timer_get_time() / 1000000));
        ESP_LOGI(TAG, "Saved: %s (%zu bytes)", path, len);
    }
    return ret;
}

/* ── MJPEG Stream ───────────────────────────────── */

static void stream_task(void *arg)
{
    ESP_LOGI(TAG, "Stream started");
    while (s_streaming) {
        camera_fb_t *fb = esp_camera_fb_get();
        if (!fb) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        if (xSemaphoreTake(s_frame_lock, pdMS_TO_TICKS(100))) {
            free(s_latest_jpeg);
            s_latest_jpeg = malloc(fb->len);
            if (s_latest_jpeg) {
                memcpy(s_latest_jpeg, fb->buf, fb->len);
                s_latest_jpeg_len = fb->len;
                s_latest_w = fb->width;
                s_latest_h = fb->height;
            }
            xSemaphoreGive(s_frame_lock);
        }

        if (s_stream_cb) {
            s_stream_cb(fb->buf, fb->len, s_stream_ctx);
        }

        esp_camera_fb_return(fb);
        vTaskDelay(pdMS_TO_TICKS(30));
    }
    s_stream_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t camera_engine_start_stream(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    if (s_streaming) return ESP_OK;
    s_streaming = true;
    xTaskCreatePinnedToCore(stream_task, "cam_stream", 8192, NULL, 5,
                            &s_stream_task, 1);
    return ESP_OK;
}

esp_err_t camera_engine_stop_stream(void)
{
    s_streaming = false;
    if (s_stream_task) {
        vTaskDelay(pdMS_TO_TICKS(100));
        s_stream_task = NULL;
    }
    return ESP_OK;
}

bool camera_engine_stream_is_active(void) { return s_streaming; }

esp_err_t camera_engine_register_stream_cb(camera_stream_cb_t cb, void *ctx)
{
    s_stream_cb = cb;
    s_stream_ctx = ctx;
    return ESP_OK;
}

/* ── Resolution/Format ──────────────────────────── */

esp_err_t camera_engine_set_resolution(cam_resolution_t res)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    sensor_t *s = esp_camera_sensor_get();
    if (!s) return ESP_FAIL;
    return s->set_framesize(s, (framesize_t)res);
}

esp_err_t camera_engine_set_pixel_format(cam_pixel_format_t fmt)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    sensor_t *s = esp_camera_sensor_get();
    if (!s) return ESP_FAIL;
    pixformat_t pf = (fmt == CAM_PIXEL_JPEG) ? PIXFORMAT_JPEG : PIXFORMAT_GRAYSCALE;
    return s->set_pixformat(s, pf);
}

/* ── Motion Detection ───────────────────────────── */

static void motion_task(void *arg)
{
    int fw = 160, fh = 120;

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(200));

        sensor_t *s = esp_camera_sensor_get();
        if (!s) continue;

        framesize_t orig_fs = s->status.framesize;
        pixformat_t orig_pf = s->status.pixformat;

        s->set_framesize(s, FRAMESIZE_QQVGA);
        s->set_pixformat(s, PIXFORMAT_GRAYSCALE);
        vTaskDelay(pdMS_TO_TICKS(50));

        camera_fb_t *fb = esp_camera_fb_get();

        s->set_framesize(s, orig_fs);
        s->set_pixformat(s, orig_pf);

        if (!fb) continue;

        if (!s_prev_gray || s_prev_w != fb->width || s_prev_h != fb->height) {
            free(s_prev_gray);
            s_prev_w = fb->width;
            s_prev_h = fb->height;
            s_prev_gray = malloc(s_prev_w * s_prev_h);
            if (s_prev_gray) memcpy(s_prev_gray, fb->buf, s_prev_w * s_prev_h);
            esp_camera_fb_return(fb);
            continue;
        }

        int diff = 0;
        int pixels = fb->width * fb->height;
        int step = pixels > 6400 ? 4 : 2;

        for (int i = 0; i < pixels; i += step) {
            int d = abs((int)fb->buf[i] - (int)s_prev_gray[i]);
            if (d > 10) diff += d;
        }

        diff = diff * step * 100 / pixels;
        s_motion_value = diff;
        s_motion_flag = (diff > s_motion_threshold);

        memcpy(s_prev_gray, fb->buf, pixels);
        esp_camera_fb_return(fb);

        if (s_motion_flag) {
            ESP_LOGD(TAG, "Motion: %d (threshold: %d)", diff, s_motion_threshold);
        }
    }
}

bool camera_engine_motion_detected(void)
{
    bool f = s_motion_flag;
    s_motion_flag = false;
    return f;
}

esp_err_t camera_engine_set_motion_threshold(int threshold)
{
    s_motion_threshold = threshold;
    return ESP_OK;
}

int camera_engine_get_motion_value(void) { return s_motion_value; }

/* ── QR Decode ──────────────────────────────────── */

esp_err_t camera_engine_decode_qr(const uint8_t *image, int width, int height,
                                   char *result, size_t max_len)
{
    if (!image || !result || max_len < 1) return ESP_ERR_INVALID_ARG;

    struct quirc *qr = quirc_new();
    if (!qr) return ESP_ERR_NO_MEM;

    int rw, rh;
    uint8_t *buf = quirc_begin(qr, &rw, &rh);
    if (rw != width || rh != height) {
        quirc_resize(qr, width, height);
        buf = quirc_begin(qr, &rw, &rh);
        if (!buf) { quirc_destroy(qr); return ESP_ERR_NO_MEM; }
    }

    if (width == rw && height == rh) {
        memcpy(buf, image, width * height);
    } else {
        for (int y = 0; y < rh && y < height; y++) {
            memcpy(buf + y * rw, image + y * width, (rw < width ? rw : width));
        }
    }

    quirc_end(qr);

    int count = quirc_count(qr);
    if (count == 0) {
        quirc_destroy(qr);
        return ESP_ERR_NOT_FOUND;
    }

    quirc_data_t data;
    if (quirc_decode_data(qr, 0, &data) != 0) {
        quirc_destroy(qr);
        return ESP_FAIL;
    }

    size_t copy_len = data.payload_len < max_len - 1 ? data.payload_len : max_len - 1;
    memcpy(result, data.payload, copy_len);
    result[copy_len] = '\0';

    quirc_destroy(qr);
    ESP_LOGI(TAG, "QR decoded: %s", result);
    return ESP_OK;
}

/* ── Burst Capture ──────────────────────────────── */

esp_err_t camera_engine_take_burst(const char *dir, int count)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    for (int i = 0; i < count; i++) {
        uint8_t *buf;
        size_t len;
        int w, h;

        ESP_RETURN_ON_ERROR(camera_engine_capture(&buf, &len, &w, &h), TAG, "burst");

        char path[128];
        snprintf(path, sizeof(path), "%s/burst_%03d.jpg", dir, i);
        storage_write_file(path, buf, len, false);
        free(buf);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGI(TAG, "Burst complete: %d frames to %s", count, dir);
    return ESP_OK;
}
