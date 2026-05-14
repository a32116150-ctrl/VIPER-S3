#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define AI_FEATURES_MAX   32
#define AI_CLASSES_MAX    16
#define AI_TWIN_PROFILES_MAX 16
#define AI_FINGERPRINT_LEN 64

/* ── Decision Tree Inference ──────────────────── */

typedef struct {
    int feature_idx;
    float threshold;
    int left_child;
    int right_child;
    int class_id;
    bool is_leaf;
} ai_tree_node_t;

typedef struct {
    int num_nodes;
    int num_features;
    int num_classes;
    const ai_tree_node_t *nodes;
    const char * const *class_names;
} ai_decision_tree_t;

int ai_tree_classify(const ai_decision_tree_t *tree, const float *features);
const char *ai_tree_classify_name(const ai_decision_tree_t *tree, const float *features);

/* ── K-Nearest Neighbors ──────────────────────── */

typedef struct {
    float features[AI_FEATURES_MAX];
    int class_id;
} ai_knn_sample_t;

typedef struct {
    int num_samples;
    int num_features;
    int num_classes;
    int k;
    const ai_knn_sample_t *samples;
    const char * const *class_names;
} ai_knn_model_t;

int ai_knn_classify(const ai_knn_model_t *model, const float *features);
const char *ai_knn_classify_name(const ai_knn_model_t *model, const float *features);

/* ── Feature Extraction ────────────────────────── */

typedef struct {
    float rssi_mean;
    float rssi_std;
    float rssi_min;
    float rssi_max;
    float packet_rate;
    float avg_packet_size;
    float burst_ratio;
    float duration_sec;
    float interval_mean;
    float interval_std;
    uint32_t num_service_uuids;
    uint32_t num_manufacturer_ids;
} ai_wifi_features_t;

typedef struct {
    float rssi;
    float adv_interval;
    uint32_t num_service_uuids;
    uint32_t manufacturer_id;
    float name_length;
    bool has_apple_data;
    bool has_google_data;
    bool has_samsung_data;
    uint32_t adv_data_entropy;
} ai_ble_features_t;

int ai_extract_wifi_features(const void *raw_data, float *features, int max);
int ai_extract_ble_features(const void *raw_data, float *features, int max);
int ai_extract_packet_features(const uint16_t *sizes, const uint32_t *timestamps,
                                int count, float *features, int max);

/* ── Digital Twin Generation ──────────────────── */

typedef enum {
    TWIN_TYPE_BLE_DEVICE,
    TWIN_TYPE_WIFI_AP,
    TWIN_TYPE_USB_DEVICE,
    TWIN_TYPE_BEACON,
} ai_twin_type_t;

typedef struct {
    char name[64];
    ai_twin_type_t type;
    union {
        struct {
            uint16_t manufacturer_id;
            char device_type[32];
            bool is_apple;
            bool is_google;
            bool is_samsung;
            uint8_t adv_data[64];
            uint16_t adv_len;
            uint32_t adv_interval_ms;
        } ble;
        struct {
            char ssid[33];
            uint8_t bssid[6];
            int channel;
            uint8_t authmode;
            char oui_vendor[32];
            uint32_t beacon_interval_ms;
        } wifi;
        struct {
            uint16_t vid;
            uint16_t pid;
            char manufacturer[64];
            char product[64];
        } usb;
    };
    uint32_t usage_count;
    uint32_t last_used;
} ai_twin_profile_t;

typedef struct {
    int count;
    ai_twin_profile_t profiles[AI_TWIN_PROFILES_MAX];
} ai_twin_library_t;

esp_err_t ai_engine_init(void);
esp_err_t ai_engine_deinit(void);

esp_err_t ai_twin_create_from_ble(const uint8_t *addr, const char *name,
                                   uint16_t manufacturer, const uint8_t *adv, uint16_t adv_len);
esp_err_t ai_twin_create_from_wifi(const char *ssid, const uint8_t *bssid,
                                    int channel, uint8_t authmode, const char *vendor);
esp_err_t ai_twin_create_from_usb(uint16_t vid, uint16_t pid,
                                   const char *manufacturer, const char *product);

int  ai_twin_list(ai_twin_profile_t *profiles, int max);
esp_err_t ai_twin_delete(int index);
esp_err_t ai_twin_spawn_ble(int index, uint32_t duration_ms);
esp_err_t ai_twin_spawn_wifi(int index, uint32_t duration_ms);
esp_err_t ai_twin_spawn_all(uint32_t duration_ms);

esp_err_t ai_twin_save_library(void);
esp_err_t ai_twin_load_library(void);

/* ── Pre-trained Models ────────────────────────── */

const ai_decision_tree_t *ai_get_app_classifier(void);
const ai_knn_model_t *ai_get_ble_device_classifier(void);

/* ── Fingerprinting ───────────────────────────── */

esp_err_t ai_fingerprint_ble_device(const uint8_t *adv_data, uint16_t adv_len,
                                     char *fingerprint, size_t max_len);
esp_err_t ai_fingerprint_wifi_device(const char *ssid, const uint8_t *bssid,
                                      char *fingerprint, size_t max_len);
bool ai_fingerprint_compare(const char *fp1, const char *fp2, float *similarity);
