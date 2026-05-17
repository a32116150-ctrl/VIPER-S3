#include "ble_engine.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "services/gatt/ble_svc_gatt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "BLEMITM";

#define MAX_GATT_CHARS 32
#define MITM_RELAY_BUF 512

typedef enum {
    MITM_IDLE,
    MITM_SCANNING,
    MITM_CONNECTING,
    MITM_DISCOVERING,
    MITM_ACTIVE,
    MITM_ERROR,
} mitm_state_t;

typedef struct {
    uint16_t handle;
    uint16_t uuid;
    uint8_t  properties;
    uint8_t  value[256];
    uint16_t value_len;
} mitm_gatt_char_t;

typedef struct {
    bool     in_use;
    uint16_t conn_handle;
    uint16_t svc_start;
    uint16_t svc_end;
    mitm_gatt_char_t chars[MAX_GATT_CHARS];
    int      char_count;
} mitm_gatt_svc_t;

static mitm_state_t s_state = MITM_IDLE;
static uint8_t s_target_addr[6];
static char s_target_name[64];
static uint16_t s_central_conn = 0;
static uint16_t s_peri_conn = 0;
static bool s_central_connected = false;
static bool s_peri_connected = false;

static mitm_gatt_svc_t s_discovered_svcs[8];
static int s_svc_count = 0;

static mitm_intercept_cb_t s_intercept_cb = NULL;
static void *s_intercept_ctx = NULL;

static volatile bool s_mitm_running = false;
static SemaphoreHandle_t s_relay_lock = NULL;

static void mitm_set_state(mitm_state_t st)
{
    s_state = st;
    ESP_LOGI(TAG, "MITM state -> %d", st);
}

static const char *mitm_state_str(void)
{
    switch (s_state) {
        case MITM_IDLE: return "idle";
        case MITM_SCANNING: return "scanning";
        case MITM_CONNECTING: return "connecting";
        case MITM_DISCOVERING: return "discovering";
        case MITM_ACTIVE: return "active";
        case MITM_ERROR: return "error";
        default: return "unknown";
    }
}

static int central_disc_svc_cb(uint16_t conn_handle,
                                const struct ble_gatt_error *error,
                                const struct ble_gatt_svc *svc, void *arg);
static int central_disc_chr_cb(uint16_t conn_handle,
                                const struct ble_gatt_error *error,
                                const struct ble_gatt_chr *chr, void *arg);
static int central_read_cb(uint16_t conn_handle,
                            const struct ble_gatt_error *error,
                            struct ble_gatt_attr *attr, void *arg);
static int central_gap_event_cb(struct ble_gap_event *event, void *arg);
static int mitm_peri_gap_event_cb(struct ble_gap_event *event, void *arg);

static uint8_t s_adv_buf[64];
static int s_adv_len = 0;

static void build_advertised_services(void)
{
    s_adv_len = 0;

    s_adv_buf[s_adv_len++] = 0x02;
    s_adv_buf[s_adv_len++] = 0x01;
    s_adv_buf[s_adv_len++] = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;

    if (s_svc_count > 0) {
        int uuid_count = 0;
        uint16_t uuids[8];
        for (int i = 0; i < s_svc_count && uuid_count < 8; i++) {
            for (int c = 0; c < s_discovered_svcs[i].char_count && uuid_count < 8; c++) {
                if (s_discovered_svcs[i].chars[c].uuid != 0) {
                    uuids[uuid_count++] = s_discovered_svcs[i].chars[c].uuid;
                }
            }
        }
        if (uuid_count > 0) {
            int uuid_bytes = uuid_count * 2;
            s_adv_buf[s_adv_len++] = uuid_bytes + 1;
            s_adv_buf[s_adv_len++] = BLE_HS_ADV_TYPE_INCOMP_UUIDS16;
            for (int i = 0; i < uuid_count; i++) {
                s_adv_buf[s_adv_len++] = uuids[i] & 0xFF;
                s_adv_buf[s_adv_len++] = (uuids[i] >> 8) & 0xFF;
            }
        }
    }

    if (s_target_name[0]) {
        int nl = strlen(s_target_name);
        if (nl > 28) nl = 28;
        s_adv_buf[s_adv_len++] = nl + 1;
        s_adv_buf[s_adv_len++] = BLE_HS_ADV_TYPE_COMP_NAME;
        memcpy(s_adv_buf + s_adv_len, s_target_name, nl);
        s_adv_len += nl;
    }
}

static int central_disc_chr_cb(uint16_t conn_handle,
                                const struct ble_gatt_error *error,
                                const struct ble_gatt_chr *chr, void *arg)
{
    mitm_gatt_svc_t *gs = (mitm_gatt_svc_t *)arg;
    if (!gs) return 0;

    if (error->status == BLE_HS_EDONE) return 0;
    if (error->status != 0) return 0;

    if (chr && gs->char_count < MAX_GATT_CHARS) {
        mitm_gatt_char_t *gc = &gs->chars[gs->char_count++];
        gc->handle = chr->val_handle;
        gc->uuid = chr->uuid.u16.value;
        gc->properties = chr->properties;
        gc->value_len = 0;

        char props_str[16];
        int pi = 0;
        if (chr->properties & BLE_GATT_CHR_PROP_READ) props_str[pi++] = 'R';
        if (chr->properties & BLE_GATT_CHR_PROP_WRITE) props_str[pi++] = 'W';
        if (chr->properties & BLE_GATT_CHR_PROP_NOTIFY) props_str[pi++] = 'N';
        if (chr->properties & BLE_GATT_CHR_PROP_INDICATE) props_str[pi++] = 'I';
        props_str[pi] = '\0';

        ESP_LOGI(TAG, "    Char: handle=0x%04x uuid=0x%04x props=%s",
                 chr->val_handle, chr->uuid.u16.value, props_str);

        if (chr->properties & BLE_GATT_CHR_PROP_READ) {
            uint8_t read_buf[256];
            int rc = ble_gattc_read(conn_handle, chr->val_handle, central_read_cb, gc);
            if (rc == 0) vTaskDelay(pdMS_TO_TICKS(10));
        }
    }

    return 0;
}

static int central_read_cb(uint16_t conn_handle,
                            const struct ble_gatt_error *error,
                            struct ble_gatt_attr *attr, void *arg)
{
    mitm_gatt_char_t *gc = (mitm_gatt_char_t *)arg;
    if (!gc) return 0;

    if (error->status == 0 && attr && attr->om) {
        uint16_t len = OS_MBUF_PKTLEN(attr->om);
        if (len > 0 && len <= 256) {
            ble_hs_mbuf_to_flat(attr->om, gc->value, len, NULL);
            gc->value_len = len;
        }
    }

    return 0;
}

static int central_disc_svc_cb(uint16_t conn_handle,
                                const struct ble_gatt_error *error,
                                const struct ble_gatt_svc *svc, void *arg)
{
    if (error->status == BLE_HS_EDONE) {
        ESP_LOGI(TAG, "Service discovery complete: %d services", s_svc_count);
        mitm_set_state(MITM_ACTIVE);

        build_advertised_services();

        uint8_t own_addr_type;
        ble_hs_id_infer_auto(0, &own_addr_type);

        struct ble_gap_adv_params adv_params = {
            .conn_mode = BLE_GAP_CONN_MODE_UND,
            .disc_mode = BLE_GAP_DISC_MODE_GEN,
        };

        ble_gap_adv_set_data(s_adv_buf, s_adv_len);
        ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER,
                          &adv_params, mitm_peri_gap_event_cb, NULL);

        return 0;
    }

    if (error->status != 0) {
        ESP_LOGW(TAG, "Service discovery error: %d", error->status);
        return 0;
    }

    if (svc && s_svc_count < 8) {
        mitm_gatt_svc_t *gs = &s_discovered_svcs[s_svc_count++];
        memset(gs, 0, sizeof(mitm_gatt_svc_t));
        gs->in_use = true;
        gs->conn_handle = conn_handle;
        gs->svc_start = svc->start_handle;
        gs->svc_end = svc->end_handle;
        ESP_LOGI(TAG, "  Service: start=0x%04x end=0x%04x",
                 svc->start_handle, svc->end_handle);

        int rc = ble_gattc_disc_all_chrs(conn_handle, svc->start_handle,
                                          svc->end_handle,
                                          central_disc_chr_cb, gs);
        if (rc != 0) {
            ESP_LOGW(TAG, "Failed to discover characteristics: %d", rc);
        }
    }

    return 0;
}

static int central_gap_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT: {
            if (event->connect.status == 0) {
                s_central_conn = event->connect.conn_handle;
                s_central_connected = true;
                ESP_LOGI(TAG, "MITM connected to target (handle=%d)", s_central_conn);
                mitm_set_state(MITM_DISCOVERING);

                s_svc_count = 0;
                memset(s_discovered_svcs, 0, sizeof(s_discovered_svcs));

                int rc = ble_gattc_disc_all_svcs(s_central_conn,
                                                   central_disc_svc_cb, NULL);
                if (rc != 0) {
                    ESP_LOGE(TAG, "Failed to discover services: %d", rc);
                    mitm_set_state(MITM_ERROR);
                }
            } else {
                ESP_LOGE(TAG, "MITM connect failed: %d", event->connect.status);
                mitm_set_state(MITM_ERROR);
            }
            break;
        }
        case BLE_GAP_EVENT_DISCONNECT: {
        ESP_LOGI(TAG, "MITM disconnected from target (reason=%d)",
                 event->disconnect.reason);
            s_central_connected = false;
            s_central_conn = 0;
            mitm_set_state(MITM_IDLE);
            break;
        }
        default:
            break;
    }
    return 0;
}

static int mitm_peri_gap_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT: {
            if (event->connect.status == 0) {
                s_peri_conn = event->connect.conn_handle;
                s_peri_connected = true;
                ESP_LOGI(TAG, "MITM peripheral connected (handle=%d)", s_peri_conn);
            }
            break;
        }
        case BLE_GAP_EVENT_DISCONNECT: {
            s_peri_connected = false;
            s_peri_conn = 0;
            ESP_LOGI(TAG, "MITM peripheral disconnected");

            uint8_t own_addr_type;
            ble_hs_id_infer_auto(0, &own_addr_type);

            struct ble_gap_adv_params adv_params = {
                .conn_mode = BLE_GAP_CONN_MODE_UND,
                .disc_mode = BLE_GAP_DISC_MODE_GEN,
            };

            ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER,
                              &adv_params, mitm_peri_gap_event_cb, NULL);
            break;
        }
        case BLE_GAP_EVENT_REPEAT_PAIRING: {
            ESP_LOGW(TAG, "MITM pairing request from client");
            return BLE_GAP_REPEAT_PAIRING_IGNORE;
        }
        case BLE_GAP_EVENT_NOTIFY_RX: {
            if (s_central_connected && s_peri_connected) {
                uint16_t attr_handle = event->notify_rx.attr_handle;

                if (s_intercept_cb) {
                    uint8_t buf[256];
                    uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
                    uint16_t copy_len = len < 256 ? len : 256;
                    ble_hs_mbuf_to_flat(event->notify_rx.om, buf, copy_len, NULL);

                    if (s_intercept_cb(attr_handle, buf, &copy_len, s_intercept_ctx)) {
                        struct os_mbuf *new_om = ble_hs_mbuf_from_flat(buf, copy_len);
                        if (new_om) {
                            ble_gattc_notify_custom(s_peri_conn, attr_handle, new_om);
                        }
                        os_mbuf_free_chain(event->notify_rx.om);
                        return 0;
                    }
                }

                ble_gattc_notify_custom(s_peri_conn, attr_handle, event->notify_rx.om);
            }
            break;
        }
        default:
            break;
    }
    return 0;
}

static void adv_init(void)
{
    uint8_t init_adv[32];
    int len = 0;
    init_adv[len++] = 0x02;
    init_adv[len++] = 0x01;
    init_adv[len++] = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    const char *proxy_name = "VIPER-MITM";
    init_adv[len++] = strlen(proxy_name) + 1;
    init_adv[len++] = BLE_HS_ADV_TYPE_COMP_NAME;
    memcpy(init_adv + len, proxy_name, strlen(proxy_name));
    len += strlen(proxy_name);

    ble_gap_adv_set_data(init_adv, len);
}

esp_err_t ble_mitm_start(const uint8_t *target_addr, const char *target_name, uint32_t scan_timeout_ms)
{
    if (s_mitm_running) {
        ESP_LOGW(TAG, "MITM already running");
        return ESP_FAIL;
    }

    if (target_addr) memcpy(s_target_addr, target_addr, 6);
    else memset(s_target_addr, 0, 6);

    if (target_name) strncpy(s_target_name, target_name, sizeof(s_target_name) - 1);
    else s_target_name[0] = '\0';

    s_relay_lock = xSemaphoreCreateMutex();
    if (!s_relay_lock) return ESP_ERR_NO_MEM;

    s_central_connected = false;
    s_peri_connected = false;
    s_svc_count = 0;

    s_mitm_running = true;
    mitm_set_state(MITM_SCANNING);

    uint8_t own_addr_type;
    ble_hs_id_infer_auto(0, &own_addr_type);

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
    };

    adv_init();
    ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER,
                      &adv_params, mitm_peri_gap_event_cb, NULL);

    if (!target_addr) {
        ESP_LOGI(TAG, "MITM scanning for target: %s", target_name ? target_name : "(any)");

        ble_scanner_clear();
        ble_scanner_start(scan_timeout_ms > 0 ? scan_timeout_ms : 5000);

        if (s_target_name[0]) {
            ble_device_t devices[BLE_MAX_DEVICES];
            int count = ble_scanner_get_results(devices, BLE_MAX_DEVICES);
            for (int i = 0; i < count; i++) {
                if (strstr(devices[i].name, s_target_name)) {
                    memcpy(s_target_addr, devices[i].addr, 6);
                    ESP_LOGI(TAG, "Found target by name: %s", devices[i].name);
                    break;
                }
            }
        }
    } else {
        memcpy(s_target_addr, target_addr, 6);
    }

    uint8_t zero_addr[6] = {0};
    if (memcmp(s_target_addr, zero_addr, 6) == 0) {
        ESP_LOGE(TAG, "No target found");
        ble_mitm_stop();
        return ESP_FAIL;
    }

    ble_gap_adv_stop();
    mitm_set_state(MITM_CONNECTING);

    struct ble_gap_conn_params conn_params = {
        .scan_itvl = 200,
        .scan_window = 60,
        .itvl_min = 40,
        .itvl_max = 80,
        .latency = 0,
        .supervision_timeout = 400,
        .min_ce_len = 0,
        .max_ce_len = 0,
    };

    char addr_str[18];
    snprintf(addr_str, sizeof(addr_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             s_target_addr[5], s_target_addr[4], s_target_addr[3],
             s_target_addr[2], s_target_addr[1], s_target_addr[0]);

    ble_addr_t peer_addr = {0};
    memcpy(peer_addr.val, s_target_addr, 6);
    peer_addr.type = BLE_ADDR_PUBLIC;
    int rc = ble_gap_connect(own_addr_type, &peer_addr, 3000, &conn_params,
                              central_gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "MITM connect failed: %d", rc);
        mitm_set_state(MITM_ERROR);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "BLE MITM proxy started (target: %s [%s])", s_target_name, addr_str);
    return ESP_OK;
}

esp_err_t ble_mitm_stop(void)
{
    if (!s_mitm_running) return ESP_OK;

    s_mitm_running = false;

    if (s_peri_connected) {
        ble_gap_terminate(s_peri_conn, BLE_ERR_REM_USER_CONN_TERM);
    }
    if (s_central_connected) {
        ble_gap_terminate(s_central_conn, BLE_ERR_REM_USER_CONN_TERM);
    }

    ble_gap_adv_stop();

    s_central_connected = false;
    s_peri_connected = false;
    s_central_conn = 0;
    s_peri_conn = 0;
    s_svc_count = 0;

    if (s_relay_lock) {
        vSemaphoreDelete(s_relay_lock);
        s_relay_lock = NULL;
    }

    mitm_set_state(MITM_IDLE);
    ESP_LOGI(TAG, "BLE MITM proxy stopped");
    return ESP_OK;
}

bool ble_mitm_is_active(void)
{
    return s_mitm_running && s_state == MITM_ACTIVE;
}

ble_mitm_status_t ble_mitm_get_status(void)
{
    ble_mitm_status_t st;
    memset(&st, 0, sizeof(st));
    st.active = s_mitm_running;
    st.central_connected = s_central_connected;
    st.peripheral_connected = s_peri_connected;
    st.services_discovered = s_svc_count;
    strncpy(st.state_str, mitm_state_str(), sizeof(st.state_str) - 1);
    memcpy(st.target_addr, s_target_addr, 6);
    strncpy(st.target_name, s_target_name, sizeof(st.target_name) - 1);
    return st;
}

esp_err_t ble_mitm_register_intercept_cb(mitm_intercept_cb_t cb, void *ctx)
{
    s_intercept_cb = cb;
    s_intercept_ctx = ctx;
    return ESP_OK;
}

int ble_mitm_get_discovered_services(mitm_service_t *services, int max)
{
    if (!services || max <= 0) return 0;

    int count = max < s_svc_count ? max : s_svc_count;
    for (int i = 0; i < count; i++) {
        mitm_service_t *out = &services[i];
        out->start_handle = s_discovered_svcs[i].svc_start;
        out->end_handle = s_discovered_svcs[i].svc_end;
        out->char_count = s_discovered_svcs[i].char_count < 16 ?
                          s_discovered_svcs[i].char_count : 16;

        for (int c = 0; c < out->char_count; c++) {
            out->chars[c].handle = s_discovered_svcs[i].chars[c].handle;
            out->chars[c].uuid = s_discovered_svcs[i].chars[c].uuid;
            out->chars[c].properties = s_discovered_svcs[i].chars[c].properties;
            out->chars[c].value_len = s_discovered_svcs[i].chars[c].value_len;
            memcpy(out->chars[c].value, s_discovered_svcs[i].chars[c].value,
                   s_discovered_svcs[i].chars[c].value_len > 128 ?
                   128 : s_discovered_svcs[i].chars[c].value_len);
        }
    }

    return count;
}
