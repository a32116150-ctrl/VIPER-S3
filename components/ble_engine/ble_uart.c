#include "ble_engine.h"
#include "esp_log.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "services/gatt/ble_svc_gatt.h"
#include <string.h>

static const char *TAG = "BLEUART";

#define UART_SVC_UUID       0x6E40
#define UART_CHR_TX_UUID    0x6E41
#define UART_CHR_RX_UUID    0x6E42

static uint16_t s_conn_handle = 0;
static bool s_connected = false;

static uint16_t s_chr_tx_handle = 0;
static uint16_t s_chr_rx_handle = 0;

static ble_uart_rx_cb_t s_rx_cb = NULL;
static void *s_rx_ctx = NULL;

static uint8_t s_rx_buf[256];
static int s_rx_len = 0;

static int uart_gatt_event_cb(struct ble_gatt_event *event, void *arg);

static int uart_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                           struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    switch (ctxt->op) {
        case BLE_GATT_ACCESS_OP_READ_CHR:
            if (attr_handle == s_chr_tx_handle) {
                return BLE_ATT_ERR_READ_NOT_PERMITTED;
            }
            break;

        case BLE_GATT_ACCESS_OP_WRITE_CHR:
            if (attr_handle == s_chr_rx_handle) {
                uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
                if (len > 0) {
                    int copy = len < 256 ? len : 256;
                    memset(s_rx_buf, 0, sizeof(s_rx_buf));
                    ble_hs_mbuf_to_flat(ctxt->om, s_rx_buf, copy, NULL);
                    s_rx_len = copy;

                    if (s_rx_cb) {
                        s_rx_cb(s_rx_buf, s_rx_len, s_rx_ctx);
                    }
                }
            }
            break;

        default:
            break;
    }
    return 0;
}

static void uart_connect_cb(uint16_t conn_handle)
{
    s_conn_handle = conn_handle;
    s_connected = true;
    ESP_LOGI(TAG, "BLE UART connected (handle: %d)", conn_handle);
}

static void uart_disconnect_cb(void)
{
    s_conn_handle = 0;
    s_connected = false;
    ESP_LOGI(TAG, "BLE UART disconnected");
}

esp_err_t ble_uart_init(void)
{
    const ble_uuid128_t svc_uuid = BLE_UUID128_INIT(
        0x9E, 0xCA, 0x24, 0x0E, 0xA9, 0xE0, 0x93, 0xF3,
        0xA3, 0x93, 0xF5, 0xA3, 0x01, 0x40, 0x6E, 0x00);

    const ble_uuid128_t tx_uuid = BLE_UUID128_INIT(
        0x9E, 0xCA, 0x24, 0x0E, 0xA9, 0xE0, 0x93, 0xF3,
        0xA3, 0x93, 0xF5, 0xA3, 0x02, 0x40, 0x6E, 0x00);

    const ble_uuid128_t rx_uuid = BLE_UUID128_INIT(
        0x9E, 0xCA, 0x24, 0x0E, 0xA9, 0xE0, 0x93, 0xF3,
        0xA3, 0x93, 0xF5, 0xA3, 0x03, 0x40, 0x6E, 0x00);

    struct ble_gatt_svc_def svcs[] = {
        {
            .type = BLE_GATT_SVC_TYPE_PRIMARY,
            .uuid = &svc_uuid.u,
            .characteristics = (struct ble_gatt_chr_def[]) {
                {
                    .uuid = &tx_uuid.u,
                    .access_cb = uart_access_cb,
                    .flags = BLE_GATT_CHR_F_NOTIFY,
                    .val_handle = &s_chr_tx_handle,
                }, {
                    .uuid = &rx_uuid.u,
                    .access_cb = uart_access_cb,
                    .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,
                    .val_handle = &s_chr_rx_handle,
                }, {
                    0,
                },
            },
        }, {
            0,
        },
    };

    int rc = ble_gatts_count_cfg(svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "GATT count failed: %d", rc);
        return ESP_FAIL;
    }

    rc = ble_gatts_add_svcs(svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "GATT add failed: %d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "BLE UART GATT service initialized");
    return ESP_OK;
}

esp_err_t ble_uart_send(const uint8_t *data, size_t len)
{
    if (!s_connected || !s_conn_handle) return ESP_FAIL;

    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (!om) return ESP_ERR_NO_MEM;

    int rc = ble_gattc_notify_custom(s_conn_handle, s_chr_tx_handle, om);
    if (rc != 0) {
        ESP_LOGW(TAG, "Notify failed: %d", rc);
        return ESP_FAIL;
    }
    return ESP_OK;
}

int ble_uart_receive(uint8_t *buf, size_t max_len)
{
    if (s_rx_len == 0) return 0;
    int copy = s_rx_len < (int)max_len ? s_rx_len : (int)max_len;
    memcpy(buf, s_rx_buf, copy);
    s_rx_len = 0;
    return copy;
}

bool ble_uart_is_connected(void) { return s_connected; }

esp_err_t ble_uart_register_rx_cb(ble_uart_rx_cb_t cb, void *ctx)
{
    s_rx_cb = cb;
    s_rx_ctx = ctx;
    return ESP_OK;
}
