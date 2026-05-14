#include "ai_engine.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ble_engine.h"
#include "wifi_engine.h"

static const char *TAG = "AI";

#define TWIN_LIBRARY_PATH "/viper/config/twin_library.bin"

static ai_twin_library_t s_twin_lib;
static bool s_initialized = false;

/* ── Decision Tree Inference ──────────────────── */

int ai_tree_classify(const ai_decision_tree_t *tree, const float *features)
{
    if (!tree || !features) return -1;

    int node_idx = 0;
    while (node_idx >= 0 && node_idx < tree->num_nodes) {
        const ai_tree_node_t *node = &tree->nodes[node_idx];
        if (node->is_leaf) return node->class_id;
        if (features[node->feature_idx] <= node->threshold) {
            node_idx = node->left_child;
        } else {
            node_idx = node->right_child;
        }
    }
    return -1;
}

const char *ai_tree_classify_name(const ai_decision_tree_t *tree, const float *features)
{
    int cls = ai_tree_classify(tree, features);
    if (cls >= 0 && cls < tree->num_classes && tree->class_names) {
        return tree->class_names[cls];
    }
    return "unknown";
}

/* ── K-Nearest Neighbors ──────────────────────── */

static float euclidean_dist(const float *a, const float *b, int n)
{
    float sum = 0;
    for (int i = 0; i < n; i++) {
        float d = a[i] - b[i];
        sum += d * d;
    }
    return sqrtf(sum);
}

static int compare_dist(const void *a, const void *b)
{
    float da = *(const float *)a;
    float db = *(const float *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

int ai_knn_classify(const ai_knn_model_t *model, const float *features)
{
    if (!model || !features) return -1;

    float dists[AI_CLASSES_MAX * 4];
    int n = model->num_samples;
    if (n > AI_CLASSES_MAX * 4) n = AI_CLASSES_MAX * 4;

    float sorted_dists[AI_CLASSES_MAX * 4];
    int sorted_classes[AI_CLASSES_MAX * 4];

    for (int i = 0; i < n; i++) {
        sorted_dists[i] = euclidean_dist(features, model->samples[i].features, model->num_features);
        sorted_classes[i] = model->samples[i].class_id;
    }

    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (sorted_dists[j] > sorted_dists[j + 1]) {
                float td = sorted_dists[j];
                sorted_dists[j] = sorted_dists[j + 1];
                sorted_dists[j + 1] = td;
                int tc = sorted_classes[j];
                sorted_classes[j] = sorted_classes[j + 1];
                sorted_classes[j + 1] = tc;
            }
        }
    }

    int k = model->k < n ? model->k : n;
    int votes[AI_CLASSES_MAX] = {0};
    for (int i = 0; i < k; i++) {
        if (sorted_classes[i] >= 0 && sorted_classes[i] < model->num_classes) {
            votes[sorted_classes[i]]++;
        }
    }

    int best_class = 0;
    int best_votes = 0;
    for (int i = 0; i < model->num_classes; i++) {
        if (votes[i] > best_votes) {
            best_votes = votes[i];
            best_class = i;
        }
    }

    return best_class;
}

const char *ai_knn_classify_name(const ai_knn_model_t *model, const float *features)
{
    int cls = ai_knn_classify(model, features);
    if (cls >= 0 && cls < model->num_classes && model->class_names) {
        return model->class_names[cls];
    }
    return "unknown";
}

/* ── Feature Extraction ────────────────────────── */

int ai_extract_wifi_features(const void *raw_data, float *features, int max)
{
    if (!raw_data || !features || max < 8) return 0;
    (void)raw_data;
    features[0] = 0.0f;
    features[1] = 0.0f;
    features[2] = 0.0f;
    features[3] = 0.0f;
    features[4] = 0.0f;
    features[5] = 0.0f;
    features[6] = 0.0f;
    features[7] = 0.0f;
    return 8;
}

int ai_extract_ble_features(const void *raw_data, float *features, int max)
{
    if (!raw_data || !features || max < 9) return 0;
    (void)raw_data;
    features[0] = 0.0f;
    features[1] = 0.0f;
    features[2] = 0.0f;
    features[3] = 0.0f;
    features[4] = 0.0f;
    features[5] = 0.0f;
    features[6] = 0.0f;
    features[7] = 0.0f;
    features[8] = 0.0f;
    return 9;
}

int ai_extract_packet_features(const uint16_t *sizes, const uint32_t *timestamps,
                                int count, float *features, int max)
{
    if (!sizes || !timestamps || count < 2 || !features || max < 10) return 0;

    float sum_size = 0, sum_interval = 0;
    float min_size = sizes[0], max_size = sizes[0];
    float min_interval = 999999, max_interval = 0;
    int bursts = 0;

    for (int i = 0; i < count; i++) {
        sum_size += sizes[i];
        if (sizes[i] < min_size) min_size = sizes[i];
        if (sizes[i] > max_size) max_size = sizes[i];
    }

    for (int i = 1; i < count; i++) {
        float iv = (float)(timestamps[i] - timestamps[i - 1]) / 1000.0f;
        sum_interval += iv;
        if (iv < min_interval) min_interval = iv;
        if (iv > max_interval) max_interval = iv;
        if (iv < 10) bursts++;
    }

    float mean_size = sum_size / count;
    float mean_interval = sum_interval / (count - 1);

    float var_size = 0, var_interval = 0;
    for (int i = 0; i < count; i++) var_size += (sizes[i] - mean_size) * (sizes[i] - mean_size);
    for (int i = 1; i < count; i++) var_interval += ((timestamps[i] - timestamps[i - 1]) / 1000.0f - mean_interval) * ((timestamps[i] - timestamps[i - 1]) / 1000.0f - mean_interval);

    features[0] = mean_size;
    features[1] = sqrtf(var_size / count);
    features[2] = min_size;
    features[3] = max_size;
    features[4] = mean_interval;
    features[5] = sqrtf(var_interval / (count - 1));
    features[6] = min_interval;
    features[7] = max_interval;
    features[8] = (float)bursts / (count - 1);
    features[9] = (float)count;

    return 10;
}

/* ── App Type Decision Tree ────────────────────── */

static const ai_tree_node_t s_app_tree_nodes[] = {
    { .feature_idx = 0, .threshold = 500.0f, .left_child = 1, .right_child = 6, .is_leaf = false, .class_id = 0 },
    { .feature_idx = 1, .threshold = 200.0f, .left_child = 2, .right_child = 3, .is_leaf = false, .class_id = 0 },
    { .is_leaf = true, .class_id = 7 },
    { .feature_idx = 8, .threshold = 0.3f, .left_child = 4, .right_child = 5, .is_leaf = false, .class_id = 0 },
    { .is_leaf = true, .class_id = 0 },
    { .is_leaf = true, .class_id = 4 },
    { .feature_idx = 4, .threshold = 100.0f, .left_child = 7, .right_child = 10, .is_leaf = false, .class_id = 0 },
    { .feature_idx = 8, .threshold = 0.1f, .left_child = 8, .right_child = 9, .is_leaf = false, .class_id = 0 },
    { .is_leaf = true, .class_id = 2 },
    { .is_leaf = true, .class_id = 6 },
    { .feature_idx = 0, .threshold = 1000.0f, .left_child = 11, .right_child = 13, .is_leaf = false, .class_id = 0 },
    { .feature_idx = 8, .threshold = 0.5f, .left_child = 14, .right_child = 12, .is_leaf = false, .class_id = 0 },
    { .is_leaf = true, .class_id = 1 },
    { .feature_idx = 4, .threshold = 500.0f, .left_child = 14, .right_child = 15, .is_leaf = false, .class_id = 0 },
    { .is_leaf = true, .class_id = 3 },
    { .is_leaf = true, .class_id = 5 },
};

static const char *s_app_class_names[] = {
    "Zoom", "SSH", "Netflix", "HTTP", "Streaming", "VoIP", "FileTransfer", "Gaming",
};

static const ai_decision_tree_t s_app_classifier = {
    .num_nodes = 16,
    .num_features = 10,
    .num_classes = 8,
    .nodes = s_app_tree_nodes,
    .class_names = s_app_class_names,
};

const ai_decision_tree_t *ai_get_app_classifier(void)
{
    return &s_app_classifier;
}

/* ── BLE Device KNN Model ──────────────────────── */

static const ai_knn_sample_t s_ble_samples[] = {
    { .features = {-60.0f, 100.0f, 3.0f, 0x004C, 5.0f, 1.0f, 0.0f, 0.0f, 0.5f}, .class_id = 0 },
    { .features = {-70.0f, 200.0f, 2.0f, 0x00E0, 8.0f, 0.0f, 1.0f, 0.0f, 0.3f}, .class_id = 1 },
    { .features = {-55.0f, 150.0f, 1.0f, 0x0075, 6.0f, 0.0f, 0.0f, 1.0f, 0.4f}, .class_id = 2 },
    { .features = {-80.0f, 500.0f, 0.0f, 0x0006, 10.0f, 0.0f, 1.0f, 0.0f, 0.2f}, .class_id = 3 },
    { .features = {-65.0f, 300.0f, 4.0f, 0x004C, 7.0f, 1.0f, 0.0f, 0.0f, 0.6f}, .class_id = 0 },
    { .features = {-45.0f, 100.0f, 2.0f, 0x00E0, 9.0f, 0.0f, 1.0f, 0.0f, 0.3f}, .class_id = 1 },
};

static const char *s_ble_class_names[] = {
    "Apple Device", "Google Device", "Samsung Device", "Microsoft Device",
};

static const ai_knn_model_t s_ble_device_classifier = {
    .num_samples = 6,
    .num_features = 9,
    .num_classes = 4,
    .k = 3,
    .samples = s_ble_samples,
    .class_names = s_ble_class_names,
};

const ai_knn_model_t *ai_get_ble_device_classifier(void)
{
    return &s_ble_device_classifier;
}

/* ── Digital Twin Core ─────────────────────────── */

static uint64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

static int find_free_twin(void)
{
    for (int i = 0; i < AI_TWIN_PROFILES_MAX; i++) {
        if (s_twin_lib.profiles[i].name[0] == '\0') return i;
    }
    return -1;
}

esp_err_t ai_engine_init(void)
{
    if (s_initialized) return ESP_OK;
    memset(&s_twin_lib, 0, sizeof(s_twin_lib));
    ai_twin_load_library();
    s_initialized = true;
    ESP_LOGI(TAG, "AI engine initialized (%d twin profiles loaded)", s_twin_lib.count);
    return ESP_OK;
}

esp_err_t ai_engine_deinit(void)
{
    if (!s_initialized) return ESP_OK;
    ai_twin_save_library();
    s_initialized = false;
    ESP_LOGI(TAG, "AI engine deinitialized");
    return ESP_OK;
}

esp_err_t ai_twin_create_from_ble(const uint8_t *addr, const char *name,
                                   uint16_t manufacturer, const uint8_t *adv, uint16_t adv_len)
{
    int idx = find_free_twin();
    if (idx < 0) return ESP_ERR_NO_MEM;

    ai_twin_profile_t *p = &s_twin_lib.profiles[idx];
    memset(p, 0, sizeof(ai_twin_profile_t));

    p->type = TWIN_TYPE_BLE_DEVICE;
    snprintf(p->name, sizeof(p->name), "BLE_%s", name ? name : "unknown");
    p->ble.manufacturer_id = manufacturer;
    if (name) snprintf(p->ble.device_type, sizeof(p->ble.device_type), "%s", name);
    p->ble.is_apple = (manufacturer == 0x004C);
    p->ble.is_google = (manufacturer == 0x00E0);
    p->ble.is_samsung = (manufacturer == 0x0075);

    if (adv && adv_len > 0) {
        uint16_t copy = adv_len < 64 ? adv_len : 64;
        memcpy(p->ble.adv_data, adv, copy);
        p->ble.adv_len = copy;
    }

    p->ble.adv_interval_ms = 100;
    p->usage_count = 0;
    p->last_used = now_ms();
    s_twin_lib.count++;

    ESP_LOGI(TAG, "Twin created: %s (BLE, mfg=0x%04X)", p->name, manufacturer);
    return ESP_OK;
}

esp_err_t ai_twin_create_from_wifi(const char *ssid, const uint8_t *bssid,
                                    int channel, uint8_t authmode, const char *vendor)
{
    int idx = find_free_twin();
    if (idx < 0) return ESP_ERR_NO_MEM;

    ai_twin_profile_t *p = &s_twin_lib.profiles[idx];
    memset(p, 0, sizeof(ai_twin_profile_t));

    p->type = TWIN_TYPE_WIFI_AP;
    snprintf(p->name, sizeof(p->name), "AP_%s", ssid ? ssid : "unknown");

    if (ssid) strncpy(p->wifi.ssid, ssid, sizeof(p->wifi.ssid) - 1);
    if (bssid) memcpy(p->wifi.bssid, bssid, 6);
    p->wifi.channel = channel > 0 ? channel : 6;
    p->wifi.authmode = authmode;
    if (vendor) strncpy(p->wifi.oui_vendor, vendor, sizeof(p->wifi.oui_vendor) - 1);
    p->wifi.beacon_interval_ms = 100;
    p->usage_count = 0;
    p->last_used = now_ms();
    s_twin_lib.count++;

    ESP_LOGI(TAG, "Twin created: %s (WiFi, ch=%d)", p->name, channel);
    return ESP_OK;
}

esp_err_t ai_twin_create_from_usb(uint16_t vid, uint16_t pid,
                                   const char *manufacturer, const char *product)
{
    int idx = find_free_twin();
    if (idx < 0) return ESP_ERR_NO_MEM;

    ai_twin_profile_t *p = &s_twin_lib.profiles[idx];
    memset(p, 0, sizeof(ai_twin_profile_t));

    p->type = TWIN_TYPE_USB_DEVICE;
    snprintf(p->name, sizeof(p->name), "USB_%04X_%04X", vid, pid);
    p->usb.vid = vid;
    p->usb.pid = pid;
    if (manufacturer) strncpy(p->usb.manufacturer, manufacturer, sizeof(p->usb.manufacturer) - 1);
    if (product) strncpy(p->usb.product, product, sizeof(p->usb.product) - 1);
    p->usage_count = 0;
    p->last_used = now_ms();
    s_twin_lib.count++;

    ESP_LOGI(TAG, "Twin created: %s (USB)", p->name);
    return ESP_OK;
}

int ai_twin_list(ai_twin_profile_t *profiles, int max)
{
    if (!profiles || max <= 0) return 0;
    int count = max < s_twin_lib.count ? max : s_twin_lib.count;
    int out = 0;
    for (int i = 0; i < AI_TWIN_PROFILES_MAX && out < count; i++) {
        if (s_twin_lib.profiles[i].name[0]) {
            memcpy(&profiles[out++], &s_twin_lib.profiles[i], sizeof(ai_twin_profile_t));
        }
    }
    return out;
}

esp_err_t ai_twin_delete(int index)
{
    int real_idx = -1;
    int seen = 0;
    for (int i = 0; i < AI_TWIN_PROFILES_MAX; i++) {
        if (s_twin_lib.profiles[i].name[0]) {
            if (seen == index) { real_idx = i; break; }
            seen++;
        }
    }
    if (real_idx < 0) return ESP_ERR_NOT_FOUND;

    memset(&s_twin_lib.profiles[real_idx], 0, sizeof(ai_twin_profile_t));
    s_twin_lib.count--;
    ESP_LOGI(TAG, "Twin deleted: index=%d", index);
    return ESP_OK;
}

esp_err_t ai_twin_spawn_ble(int index, uint32_t duration_ms)
{
    int real_idx = -1;
    int seen = 0;
    for (int i = 0; i < AI_TWIN_PROFILES_MAX; i++) {
        if (s_twin_lib.profiles[i].name[0]) {
            if (seen == index) { real_idx = i; break; }
            seen++;
        }
    }
    if (real_idx < 0 || s_twin_lib.profiles[real_idx].type != TWIN_TYPE_BLE_DEVICE) {
        return ESP_ERR_NOT_FOUND;
    }

    ai_twin_profile_t *p = &s_twin_lib.profiles[real_idx];
    p->usage_count++;
    p->last_used = now_ms();

    ESP_LOGI(TAG, "Spawning BLE twin: %s (mfg=0x%04X, %lu ms)",
             p->name, p->ble.manufacturer_id, (unsigned long)duration_ms);

    int spam_type = BLE_SPAM_AIRDROP;
    if (p->ble.is_google) spam_type = BLE_SPAM_ANDROID_FASTPAIR;
    else if (p->ble.is_samsung) spam_type = BLE_SPAM_SAMSUNG;
    else if (p->ble.manufacturer_id == 0x0006) spam_type = BLE_SPAM_WINDOWS_SWIFTPAIR;

    ble_spam_start((ble_spam_type_t)spam_type, p->ble.adv_interval_ms);
    vTaskDelay(pdMS_TO_TICKS(duration_ms > 0 ? duration_ms : 5000));
    ble_spam_stop();

    return ESP_OK;
}

esp_err_t ai_twin_spawn_wifi(int index, uint32_t duration_ms)
{
    int real_idx = -1;
    int seen = 0;
    for (int i = 0; i < AI_TWIN_PROFILES_MAX; i++) {
        if (s_twin_lib.profiles[i].name[0]) {
            if (seen == index) { real_idx = i; break; }
            seen++;
        }
    }
    if (real_idx < 0 || s_twin_lib.profiles[real_idx].type != TWIN_TYPE_WIFI_AP) {
        return ESP_ERR_NOT_FOUND;
    }

    ai_twin_profile_t *p = &s_twin_lib.profiles[real_idx];
    p->usage_count++;
    p->last_used = now_ms();

    ESP_LOGI(TAG, "Spawning WiFi twin: %s (ch=%d, %lu ms)",
             p->name, p->wifi.channel, (unsigned long)duration_ms);

    const char *ssids[2] = { p->wifi.ssid, NULL };
    wifi_beacon_flood_start(ssids, 1, p->wifi.channel, p->wifi.beacon_interval_ms);
    vTaskDelay(pdMS_TO_TICKS(duration_ms > 0 ? duration_ms : 5000));
    wifi_beacon_flood_stop();

    return ESP_OK;
}

esp_err_t ai_twin_spawn_all(uint32_t duration_ms)
{
    int spawned = 0;
    for (int i = 0; i < AI_TWIN_PROFILES_MAX; i++) {
        if (!s_twin_lib.profiles[i].name[0]) continue;

        switch (s_twin_lib.profiles[i].type) {
            case TWIN_TYPE_BLE_DEVICE:
                for (int j = 0; j < AI_TWIN_PROFILES_MAX; j++) {
                    if (s_twin_lib.profiles[j].name[0] &&
                        s_twin_lib.profiles[j].type == TWIN_TYPE_BLE_DEVICE) {
                        ai_twin_spawn_ble(j, duration_ms / 2);
                        spawned++;
                        break;
                    }
                }
                break;
            case TWIN_TYPE_WIFI_AP: {
                int ap_count = 0;
                const char *ssid_list[AI_TWIN_PROFILES_MAX + 1];
                for (int j = 0; j < AI_TWIN_PROFILES_MAX; j++) {
                    if (s_twin_lib.profiles[j].name[0] &&
                        s_twin_lib.profiles[j].type == TWIN_TYPE_WIFI_AP) {
                        ssid_list[ap_count++] = s_twin_lib.profiles[j].wifi.ssid;
                    }
                }
                ssid_list[ap_count] = NULL;
                if (ap_count > 0) {
                    wifi_beacon_flood_start(ssid_list, ap_count, 6, 100);
                    vTaskDelay(pdMS_TO_TICKS(duration_ms / 2));
                    wifi_beacon_flood_stop();
                    spawned++;
                }
                break;
            }
            default:
                break;
        }
    }

    ESP_LOGI(TAG, "Spawned %d twin profiles (%lu ms)", spawned, (unsigned long)duration_ms);
    return spawned > 0 ? ESP_OK : ESP_ERR_NOT_FOUND;
}

esp_err_t ai_twin_save_library(void)
{
    esp_err_t ret = storage_write_file(TWIN_LIBRARY_PATH,
                                        (uint8_t *)&s_twin_lib, sizeof(s_twin_lib), false);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Twin library saved (%d profiles)", s_twin_lib.count);
    }
    return ret;
}

esp_err_t ai_twin_load_library(void)
{
    size_t len = sizeof(s_twin_lib);
    esp_err_t ret = storage_read_file(TWIN_LIBRARY_PATH,
                                       (uint8_t *)&s_twin_lib, len, &len);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Twin library loaded (%d profiles)", s_twin_lib.count);
    } else {
        memset(&s_twin_lib, 0, sizeof(s_twin_lib));
    }
    return ret;
}

/* ── Fingerprinting ───────────────────────────── */

static void sha256_fingerprint(const uint8_t *data, uint16_t len, char *hex_out, size_t max_len)
{
    uint32_t h = 0x6A09E667;
    for (int i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x01000193;
        h ^= h >> 16;
    }
    snprintf(hex_out, max_len, "%08lX", (unsigned long)h);
}

esp_err_t ai_fingerprint_ble_device(const uint8_t *adv_data, uint16_t adv_len,
                                     char *fingerprint, size_t max_len)
{
    if (!adv_data || adv_len == 0 || !fingerprint) return ESP_ERR_INVALID_ARG;
    sha256_fingerprint(adv_data, adv_len, fingerprint, max_len);
    return ESP_OK;
}

esp_err_t ai_fingerprint_wifi_device(const char *ssid, const uint8_t *bssid,
                                      char *fingerprint, size_t max_len)
{
    if (!ssid || !bssid || !fingerprint) return ESP_ERR_INVALID_ARG;

    uint8_t buf[128];
    uint16_t len = 0;
    len += snprintf((char *)buf + len, sizeof(buf) - len, "%s", ssid);
    memcpy(buf + len, bssid, 6);
    len += 6;

    sha256_fingerprint(buf, len, fingerprint, max_len);
    return ESP_OK;
}

bool ai_fingerprint_compare(const char *fp1, const char *fp2, float *similarity)
{
    if (!fp1 || !fp2) return false;

    if (strcmp(fp1, fp2) == 0) {
        if (similarity) *similarity = 1.0f;
        return true;
    }

    int match = 0;
    for (int i = 0; fp1[i] && fp2[i]; i++) {
        if (fp1[i] == fp2[i]) match++;
    }
    if (similarity) *similarity = (float)match / (strlen(fp1) > strlen(fp2) ? strlen(fp1) : strlen(fp2));
    return false;
}
