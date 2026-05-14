#include "ble_engine.h"
#include "esp_log.h"
#include "esp_random.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "nimble/nimble_port.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "BLEADV";

#define MAX_EXT_ADV_SETS 4

typedef struct {
    bool     in_use;
    uint8_t  instance;
    uint8_t  phy;
    bool     periodic;
    bool     running;
    char     tag[16];
} ext_adv_set_t;

static ext_adv_set_t s_adv_sets[MAX_EXT_ADV_SETS];

static int find_free_set(void)
{
    for (int i = 0; i < MAX_EXT_ADV_SETS; i++) {
        if (!s_adv_sets[i].in_use) return i;
    }
    return -1;
}

static ext_adv_set_t *find_set(uint8_t instance)
{
    for (int i = 0; i < MAX_EXT_ADV_SETS; i++) {
        if (s_adv_sets[i].in_use && s_adv_sets[i].instance == instance) return &s_adv_sets[i];
    }
    return NULL;
}

static void ext_adv_stop_cb(int rc, void *arg)
{
    if (rc != 0) {
        ESP_LOGW(TAG, "Ext adv stopped with rc=%d", rc);
    }
}

esp_err_t ble_adv_ext_create_set(uint8_t phy, const char *tag, ble_adv_ext_set_handle_t *handle)
{
    if (!handle) return ESP_ERR_INVALID_ARG;

    int idx = find_free_set();
    if (idx < 0) return ESP_ERR_NO_MEM;

    uint8_t instance;
    int rc = ble_gap_ext_adv_set_alloc(0, &instance, phy, BLE_GAP_EXT_ADV_DATA_STATUS_COMPLETE);
    if (rc != 0) {
        ESP_LOGE(TAG, "Failed to allocate ext adv set: %d", rc);
        return ESP_FAIL;
    }

    s_adv_sets[idx].in_use = true;
    s_adv_sets[idx].instance = instance;
    s_adv_sets[idx].phy = phy;
    s_adv_sets[idx].periodic = false;
    s_adv_sets[idx].running = false;
    if (tag) {
        strncpy(s_adv_sets[idx].tag, tag, sizeof(s_adv_sets[idx].tag) - 1);
    } else {
        snprintf(s_adv_sets[idx].tag, sizeof(s_adv_sets[idx].tag), "set%d", instance);
    }

    *handle = instance;
    ESP_LOGI(TAG, "Ext adv set created: instance=%d phy=%d tag=%s", instance, phy, s_adv_sets[idx].tag);
    return ESP_OK;
}

esp_err_t ble_adv_ext_set_data(ble_adv_ext_set_handle_t handle, const uint8_t *data, uint16_t len)
{
    ext_adv_set_t *set = find_set(handle);
    if (!set) return ESP_ERR_NOT_FOUND;

    if (len > 1650) len = 1650;

    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (!om) return ESP_ERR_NO_MEM;

    struct ble_hs_adv_fields ad;
    memset(&ad, 0, sizeof(ad));
    ad.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    int rc = ble_gap_ext_adv_set_data(handle, om);
    if (rc != 0) {
        ESP_LOGE(TAG, "Failed to set ext adv data (instance %d): %d", handle, rc);
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t ble_adv_ext_set_params(ble_adv_ext_set_handle_t handle, uint32_t interval_min_ms, uint32_t interval_max_ms)
{
    ext_adv_set_t *set = find_set(handle);
    if (!set) return ESP_ERR_NOT_FOUND;

    struct ble_gap_ext_adv_params params;
    memset(&params, 0, sizeof(params));
    params.connectable = 0;
    params.scannable = 0;
    params.directed = 0;
    params.legacy_pdu = (set->phy != BLE_GAP_LE_PHY_2M && set->phy != BLE_GAP_LE_PHY_CODED) ? 1 : 0;
    params.anonymous = 0;
    params.include_tx_power = 0;
    params.primary_phy = BLE_GAP_LE_PHY_1M;
    params.secondary_phy = set->phy;

    if (set->phy == BLE_GAP_LE_PHY_CODED) {
        params.primary_phy = BLE_GAP_LE_PHY_CODED;
        params.legacy_pdu = 0;
    }

    params.itvl_min = (interval_min_ms * 1000) / 625;
    params.itvl_max = (interval_max_ms * 1000) / 625;
    if (params.itvl_min < 160) params.itvl_min = 160;
    if (params.itvl_max < 160) params.itvl_max = 160;
    if (params.itvl_max > 16384) params.itvl_max = 16384;

    int rc = ble_gap_ext_adv_set_params(handle, &params);
    if (rc != 0) {
        ESP_LOGE(TAG, "Failed to set ext adv params: %d", rc);
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t ble_adv_ext_start(ble_adv_ext_set_handle_t handle, uint32_t duration_ms)
{
    ext_adv_set_t *set = find_set(handle);
    if (!set) return ESP_ERR_NOT_FOUND;

    if (set->running) return ESP_OK;

    int rc = ble_gap_ext_adv_start(handle, duration_ms, 0, ext_adv_stop_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "Failed to start ext adv (instance %d): %d", handle, rc);
        return ESP_FAIL;
    }

    set->running = true;
    ESP_LOGI(TAG, "Ext adv started: instance=%d duration=%lu", handle, (unsigned long)duration_ms);
    return ESP_OK;
}

esp_err_t ble_adv_ext_stop(ble_adv_ext_set_handle_t handle)
{
    ext_adv_set_t *set = find_set(handle);
    if (!set) return ESP_ERR_NOT_FOUND;

    if (!set->running) return ESP_OK;

    int rc = ble_gap_ext_adv_stop(handle);
    if (rc != 0) {
        ESP_LOGW(TAG, "Failed to stop ext adv: %d", rc);
    }

    set->running = false;
    ESP_LOGI(TAG, "Ext adv stopped: instance=%d", handle);
    return ESP_OK;
}

esp_err_t ble_adv_ext_destroy_set(ble_adv_ext_set_handle_t handle)
{
    ext_adv_set_t *set = find_set(handle);
    if (!set) return ESP_ERR_NOT_FOUND;

    if (set->running) ble_adv_ext_stop(handle);

    ble_gap_ext_adv_remove(handle, 0, 0);

    set->in_use = false;
    ESP_LOGI(TAG, "Ext adv set destroyed: instance=%d", handle);
    return ESP_OK;
}

esp_err_t ble_adv_ext_set_periodic_data(ble_adv_ext_set_handle_t handle, const uint8_t *data, uint16_t len)
{
    ext_adv_set_t *set = find_set(handle);
    if (!set) return ESP_ERR_NOT_FOUND;

    struct ble_gap_periodic_adv_params params;
    memset(&params, 0, sizeof(params));
    params.itvl_min = 400;
    params.itvl_max = 800;
    params.adv_properties = BLE_GAP_PERIODIC_ADV_PROP_INCLUDE_TX_POWER;

    int rc = ble_gap_periodic_adv_set_params(handle, &params);
    if (rc != 0) {
        ESP_LOGE(TAG, "Failed to set periodic adv params: %d", rc);
        return ESP_FAIL;
    }

    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (!om) return ESP_ERR_NO_MEM;

    rc = ble_gap_periodic_adv_set_data(handle, om);
    if (rc != 0) {
        ESP_LOGE(TAG, "Failed to set periodic adv data: %d", rc);
        return ESP_FAIL;
    }

    rc = ble_gap_periodic_adv_start(handle, 0, 0);
    if (rc != 0) {
        ESP_LOGE(TAG, "Failed to start periodic adv: %d", rc);
        return ESP_FAIL;
    }

    set->periodic = true;
    ESP_LOGI(TAG, "Periodic advertising started: instance=%d len=%d", handle, len);
    return ESP_OK;
}

esp_err_t ble_adv_ext_long_range_beacon(const char *name, uint32_t interval_ms)
{
    ble_adv_ext_set_handle_t handle;

    esp_err_t ret = ble_adv_ext_create_set(BLE_GAP_LE_PHY_CODED, "LRbeacon", &handle);
    if (ret != ESP_OK) return ret;

    ret = ble_adv_ext_set_params(handle, interval_ms, interval_ms);
    if (ret != ESP_OK) return ret;

    uint8_t buf[64];
    int len = 0;
    buf[len++] = 0x02;
    buf[len++] = 0x01;
    buf[len++] = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    if (name && strlen(name) > 0) {
        int nl = strlen(name);
        if (nl > 28) nl = 28;
        buf[len++] = nl + 1;
        buf[len++] = BLE_HS_ADV_TYPE_FULL_NAME;
        memcpy(buf + len, name, nl);
        len += nl;
    }

    ret = ble_adv_ext_set_data(handle, buf, len);
    if (ret != ESP_OK) return ret;

    ret = ble_adv_ext_start(handle, 0);
    return ret;
}

esp_err_t ble_adv_ext_2m_scan_rsp(const uint8_t *data, uint16_t len)
{
    ble_adv_ext_set_handle_t handle;

    esp_err_t ret = ble_adv_ext_create_set(BLE_GAP_LE_PHY_2M, "2Mscan", &handle);
    if (ret != ESP_OK) return ret;

    struct ble_gap_ext_adv_params params;
    memset(&params, 0, sizeof(params));
    params.connectable = 0;
    params.scannable = 1;
    params.legacy_pdu = 0;
    params.primary_phy = BLE_GAP_LE_PHY_1M;
    params.secondary_phy = BLE_GAP_LE_PHY_2M;
    params.itvl_min = 160;
    params.itvl_max = 320;

    int rc = ble_gap_ext_adv_set_params(handle, &params);
    if (rc != 0) return ESP_FAIL;

    ret = ble_adv_ext_set_data(handle, data, len);
    if (ret != ESP_OK) return ret;

    ret = ble_adv_ext_start(handle, 0);
    return ret;
}

void ble_adv_ext_cleanup_all(void)
{
    for (int i = 0; i < MAX_EXT_ADV_SETS; i++) {
        if (s_adv_sets[i].in_use) {
            ble_adv_ext_destroy_set(s_adv_sets[i].instance);
        }
    }
    ESP_LOGI(TAG, "All ext adv sets cleaned up");
}
