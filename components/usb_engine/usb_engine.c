#include "usb_engine.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "tinyusb.h"
#include "tusb.h"
#include "class/hid/hid.h"
#include "class/hid/hid_device.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "USB";

static usb_mode_t s_mode = USB_MODE_COMBO;
static bool s_host_connected = false;
static int s_enumeration_us = 0;
static bool s_enum_done = false;

/* ── OS Fingerprinting ──────────────────────────── */

static os_type_t s_detected_os = OS_UNKNOWN;

os_type_t usb_os_fingerprint(void)
{
    if (s_detected_os != OS_UNKNOWN) return s_detected_os;

    if (!s_enum_done) return OS_UNKNOWN;

    if (s_enumeration_us < 150000) {
        s_detected_os = OS_LINUX;
    } else if (s_enumeration_us < 300000) {
        s_detected_os = OS_WINDOWS;
    } else {
        s_detected_os = OS_MACOS;
    }

    ESP_LOGI(TAG, "OS fingerprint: %s (enumeration: %d us)",
             s_detected_os == OS_WINDOWS ? "Windows" :
             s_detected_os == OS_MACOS ? "macOS" : "Linux",
             s_enumeration_us);
    return s_detected_os;
}

/* ── TinyUSB Callbacks ──────────────────────────── */

void tud_mount_cb(void)
{
    s_host_connected = true;
    s_enumeration_us = (int)(esp_timer_get_time() / 1000);
    ESP_LOGI(TAG, "USB host connected (enumeration: %d ms)", s_enumeration_us / 1000);
}

void tud_umount_cb(void)
{
    s_host_connected = false;
    s_enum_done = false;
    s_detected_os = OS_UNKNOWN;
    ESP_LOGI(TAG, "USB host disconnected");
}

void tud_suspend_cb(bool remote_wakeup)
{
    ESP_LOGD(TAG, "USB suspend");
}

void tud_resume_cb(void)
{
    ESP_LOGD(TAG, "USB resume");
}

/* ── HID Callbacks ──────────────────────────────── */

uint16_t tud_hid_get_report_cb(uint8_t itf, uint8_t report_id,
                                hid_report_type_t report_type, uint8_t *buffer, uint16_t reqlen)
{
    return 0;
}

void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id,
                            hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize)
{
}

/* ── CDC Callbacks ──────────────────────────────── */

void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts)
{
    (void)itf;
    if (dtr && rts) {
        ESP_LOGI(TAG, "CDC serial connected");
    }
}

void tud_cdc_rx_cb(uint8_t itf)
{
    (void)itf;
}

/* ── Descriptors ────────────────────────────────── */

enum {
    ITF_NUM_HID,
    ITF_NUM_CDC_COM,
    ITF_NUM_CDC_DATA,
    ITF_NUM_TOTAL
};

enum {
    STRID_LANGID = 0,
    STRID_MANUFACTURER,
    STRID_PRODUCT,
    STRID_SERIAL,
    STRID_HID,
    STRID_CDC,
};

#define USBD_VID 0x303A
#define USBD_PID 0x4001

static const tusb_desc_device_t s_dev_desc = {
    .bLength            = 18,
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = TUSB_CLASS_MISC,
    .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol    = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = USBD_VID,
    .idProduct          = USBD_PID,
    .bcdDevice          = 0x0100,
    .iManufacturer      = STRID_MANUFACTURER,
    .iProduct           = STRID_PRODUCT,
    .iSerialNumber      = STRID_SERIAL,
    .bNumConfigurations = 1,
};

static const uint8_t s_hid_report_desc[] = {
    TUD_HID_REPORT_DESC_KEYBOARD(HID_REPORT_ID(1))
};

static const uint8_t s_config_desc[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, 0x00C8, TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),

    TUD_HID_DESCRIPTOR(ITF_NUM_HID, STRID_HID, HID_ITF_PROTOCOL_NONE,
                       sizeof(s_hid_report_desc), 0x81, CFG_TUD_HID_EP_BUFSIZE, 10),

    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC_COM, STRID_CDC, 0x82, 64, 0x83, 64, 64),
};

/* ── String Descriptor Table ─────────────────────── */

static const char s_langid[2] = {0x09, 0x04};
static char s_serial_str[16];

static const char *s_str_desc[] = {
    s_langid,
    "VIPER-S3",
    "VIPER-S3 HID/CDC",
    s_serial_str,
    "HID Keyboard",
    "CDC Serial",
    NULL
};

const uint8_t *tud_hid_descriptor_report_cb(uint8_t itf)
{
    (void)itf;
    return s_hid_report_desc;
}

/* ── Core Init / Deinit ─────────────────────────── */

esp_err_t usb_engine_init(void)
{
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(s_serial_str, sizeof(s_serial_str), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    const tinyusb_config_t tusb_cfg = {
        .device_descriptor = &s_dev_desc,
        .string_descriptor = s_str_desc,
        .string_descriptor_count = 6,
        .external_phy = false,
        .configuration_descriptor = s_config_desc,
    };

    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    ESP_LOGI(TAG, "USB engine initialized (composite HID + CDC)");
    return ESP_OK;
}

esp_err_t usb_engine_deinit(void)
{
    tud_disconnect();
    vTaskDelay(pdMS_TO_TICKS(100));
    return ESP_OK;
}

usb_mode_t usb_engine_get_mode(void) { return s_mode; }

esp_err_t usb_engine_set_mode(usb_mode_t mode)
{
    if (mode == s_mode) return ESP_OK;

    if (mode == USB_MODE_RNDIS || mode == USB_MODE_MSC) {
        ESP_LOGW(TAG, "Mode %d requires USB re-enumeration — feature not yet implemented", mode);
        return ESP_ERR_NOT_SUPPORTED;
    }

    s_mode = mode;
    ESP_LOGI(TAG, "USB mode set to %d", mode);
    return ESP_OK;
}

bool usb_engine_is_host_connected(void) { return s_host_connected; }

/* ── CDC Serial ─────────────────────────────────── */

esp_err_t usb_cdc_write(const char *str)
{
    if (!str || !s_host_connected) return ESP_FAIL;
    tud_cdc_write_str(str);
    tud_cdc_write_flush();
    return ESP_OK;
}

int usb_cdc_read(char *buf, int max_len)
{
    if (!buf || max_len <= 0 || !s_host_connected) return 0;
    return tud_cdc_read(buf, max_len);
}

bool usb_cdc_is_connected(void)
{
    return s_host_connected && tud_cdc_connected();
}

/* ── MSC (stub) ─────────────────────────────────── */

esp_err_t usb_msc_start(const char *flash_path)
{
    ESP_LOGW(TAG, "MSC mode not yet implemented");
    (void)flash_path;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t usb_msc_stop(void)
{
    return ESP_OK;
}
