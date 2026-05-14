#include "ble_engine.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include <string.h>

static const char *TAG = "BLE";

static bool s_initialized = false;
static volatile bool s_synced = false;

static const char *s_device_name = "VIPER-S3";

static void ble_store_config_init(void);

static void ble_on_sync(void)
{
    s_synced = true;
    int rc = ble_hs_util_ensure_addr(0);
    if (rc == 0) {
        ESP_LOGI(TAG, "BLE host synced");
    }

    ble_svc_gap_device_name_set(s_device_name);
}

static void ble_host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t ble_engine_init(void)
{
    if (s_initialized) return ESP_OK;

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    if (ret != ESP_OK) return ret;

    nimble_port_init();
    ble_svc_gap_init();
    ble_svc_gatt_init();

    ble_hs_cfg.sync_cb = ble_on_sync;

    ble_store_config_init();

    ble_uart_init();

    nimble_port_freertos_init(ble_host_task);

    s_initialized = true;
    ESP_LOGI(TAG, "BLE engine initialized (NimBLE)");
    return ESP_OK;
}

esp_err_t ble_engine_deinit(void)
{
    if (!s_initialized) return ESP_OK;
    ble_spam_stop();
    ble_scanner_stop();
    ble_mitm_stop();
    ble_adv_ext_cleanup_all();
    s_initialized = false;
    nimble_port_stop();
    nimble_port_deinit();
    ESP_LOGI(TAG, "BLE engine deinitialized");
    return ESP_OK;
}

bool ble_engine_is_synced(void) { return s_synced; }

void ble_store_config_init(void)
{
    ble_store_util_status_rr();
}
