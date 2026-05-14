# VIPER-S3 Project Memory

## Overview

VIPER-S3 (**V**isual **I**ntelligence **P**entesting & **E**xploitation **R**outer — **S3**) is a multi-function ESP32-S3 security testing tool with WiFi, BLE, USB, camera, NFC, IR, and AI capabilities.

---

## Hardware

- **SoC**: ESP32-S3 WROOM N16R8
- **Flash**: 16MB (dio mode, 80MHz)
- **PSRAM**: 8MB (octal SPI)
- **Camera**: OV3660 (MJPEG stream, QR decode, motion detection)
- **NFC**: PN532 module (UART: GPIO18=TX, GPIO5=RX)
- **IR**: LED TX (GPIO2) + Receiver (GPIO4) via RMT

---

## Development Environment

| Item | Value |
|------|-------|
| ESP-IDF | v5.3 at `~/esp/esp-idf` |
| Target | `esp32s3` |
| Python | 3.13.7 (IDF v5.3 venv at `~/.espressif/python_env/idf5.3_py3.13_env/bin/python`) |
| OS | macOS (darwin) |
| esptool | v4.11.0 |
| Compiler | xtensa-esp-elf (esp-13.2.0_20240530) |

### Setup

```bash
. ~/esp/esp-idf/export.sh
idf.py set-target esp32s3
idf.py build
```

---

## Directory Structure

```
antigravity/
├── CMakeLists.txt
├── partitions.csv
├── sdkconfig                # Generated build config (do not commit changes without sdkconfig.defaults)
├── sdkconfig.defaults       # Persistent build config overrides
├── dependencies.lock        # Managed component versions
├── README.md
├── PROGRESS.md
├── PROJECT_MEMORY.md        # This file
├── main/
│   └── main.c               # Boot sequence
├── components/
│   ├── storage_manager/     # LittleFS, JSONL logging, wordlist iterator
│   ├── wifi_engine/         # 11 files: scanner, deauth, evil twin, beacon flood, PMKID, karma, captive portal, DNS spoof, HTTP sniffer
│   ├── camera_engine/       # 5 files: OV3660 driver, MJPEG, motion detect, QR decode (quirc)
│   ├── usb_engine/          # 6 files: TinyUSB HID+CDC, Ducky Script, OS fingerprint
│   ├── ble_engine/          # 10 files: NimBLE scanner, spam, GATT UART C2, MITM, proprietary scans
│   ├── web_dashboard/       # 3 files: ESP HTTP server, 27 REST endpoints, WebSocket, dark SPA
│   ├── attack_orchestrator/ # 3 files: attack chains, triggers, scheduler, health monitor
│   ├── responder/           # 4 files: LLMNR, NBT-NS, mDNS poisoning
│   ├── crack_engine/        # 3 files: on-device NTLM/MD5/SHA1/PMKID cracking
│   ├── protocol_attacks/    # 5 files: WPA3→WPA2 downgrade, SSL strip, canary tokens, behavioral fingerprinting
│   ├── ir_engine/           # 3 files: RMT IR TX/RX, NEC/Sony/Samsung encode/decode, learn/replay
│   ├── nfc_engine/          # 3 files: PN532 driver, MIFARE/Ultralight/DESFire, NDEF, emulation
│   └── ai_engine/           # 3 files: decision tree, KNN, feature extraction, digital twin
├── managed_components/
│   └── espressif__esp_tinyusb/  # TinyUSB port for ESP-IDF v5.3 (managed component)
├── data/                    # LittleFS flash data
├── build/                   # Build output
│   ├── viper_s3.bin         # App binary (at 0x10000)
│   ├── viper_s3_combined.bin # Single-file flashable (bootloader + partition + app merged)
│   ├── bootloader/bootloader.bin
│   └── partition_table/partition-table.bin
└── .cache/                  # Build cache
```

---

## Partition Table (16MB)

| Partition | Offset | Size | Description |
|-----------|--------|------|-------------|
| NVS | 0x9000 | 24KB | Non-volatile storage |
| PHY | 0xF000 | 4KB | PHY calibration data |
| Factory | 0x10000 | 4MB | Application (ota_0) |
| LittleFS | 0x410000 | 10MB | Storage for wordlists, captures, configs |
| Coredump | 0xE10000 | 1MB | Core dump on panic |
| Scratch | 0xF10000 | 960KB | Scratch/backup |

---

## Boot Sequence (main/main.c)

1. Mount LittleFS
2. Start WiFi (AP on 192.168.4.1 + STA)
3. Start BLE (NimBLE scanner + UART C2)
4. Start USB (TinyUSB HID + CDC)
5. Start Camera (OV3660 MJPEG)
6. Start Web Dashboard (port 80)
7. Initialize Responder + Crack Engine
8. Start Protocol Attacks
9. Start IR (GPIO2=TX, GPIO4=RX)
10. Start NFC (PN532 UART: GPIO18=TX, GPIO5=RX)
11. Start AI Engine
12. Launch Attack Orchestrator

---

## Build Configuration (sdkconfig / sdkconfig.defaults)

### Critical Settings

| Config | Value | Reason |
|--------|-------|--------|
| `CONFIG_HTTPD_WS_SUPPORT` | `y` | Required for WebSocket API endpoints |
| `CONFIG_TINYUSB_HID_COUNT` | `1` | HID keyboard code compiled out at 0 |
| `CONFIG_TINYUSB_MSC_ENABLED` | (unset) | Disabled — no MSC callbacks implemented |
| `CONFIG_TINYUSB_CDC_ENABLED` | `y` | CDC serial for Ducky Script |
| `CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ` | `240` | Max CPU freq |

### Flash Configuration

- `CONFIG_ESPTOOLPY_FLASHMODE_DIO` = y (dio mode)
- `CONFIG_ESPTOOLPY_FLASHFREQ_80M` = y (80MHz)
- `CONFIG_ESPTOOLPY_FLASHSIZE_16MB` = y (16MB)

### TinyUSB Config

- `CONFIG_TINYUSB_HID_COUNT=1`
- `CONFIG_TINYUSB_CDC_ENABLED=1`
- `CONFIG_TINYUSB_DESC_USE_ESPRESSIF_VID` = y (VID: 0x303A)
- USB PID: 0x4001 (custom, manually set in `usb_engine.c`)

---

## Web Dashboard

- **Port**: 80 (HTTP)
- **Mode**: Dark SPA with 27 REST endpoints + WebSocket live updates
- **Access**: http://192.168.4.1 (AP mode) or device IP on STA network
- **WebSocket**: `/ws` for real-time event stream

### API Endpoints (27 total)
WiFi: scan, deauth, evil-twin, beacon-flood, pmkid, karma, captive-portal, dns-spoof, sniffer
BLE: scan, spam, proprietary-scan, mitm
Responder: start/stop/status
SMB: start/stop
Crack: start/status
Downgrade: start
Canary: create/list
Behavioral: list
Orchestrator: chains, triggers, health

---

## TinyUSB Architecture (Critical — Descriptor System)

### Files Involved

| File | Role |
|------|------|
| `components/usb_engine/usb_engine.c` | USB engine: init, descriptors, HID/CDC callbacks |
| `managed_components/espressif__esp_tinyusb/descriptors_control.c` | Built-in descriptor callback implementations |
| `managed_components/espressif__esp_tinyusb/usb_descriptors.c` | Default descriptors from Kconfig |
| `managed_components/espressif__esp_tinyusb/include/tinyusb.h` | Public API: `tinyusb_driver_install()`, `tinyusb_config_t` |
| `managed_components/espressif__esp_tinyusb/include_private/descriptors_control.h` | `tinyusb_set_descriptors()`, `tinyusb_set_str_descriptor()` |

### How It Works

1. `tinyusb_driver_install(&config)` calls `tinyusb_set_descriptors(&config)`
2. `tinyusb_set_descriptors()` stores descriptor pointers in a static `s_desc_cfg` struct
3. TinyUSB core requests descriptors via callbacks in `descriptors_control.c`
4. These callbacks read from `s_desc_cfg` and return the pointers

### The Fix (Duplicate Symbol Conflict)

**Problem**: `usb_engine.c` defined `tud_descriptor_device_cb`, `tud_descriptor_configuration_cb`, `tud_descriptor_string_cb` directly, but `descriptors_control.c` also defines the same symbols. Linker error: duplicate symbols.

**Solution**:
1. Removed the three conflicting callback functions from `usb_engine.c`
2. Created a static string descriptor table in `usb_engine.c`:
   ```c
   static const char *s_str_desc[] = {
       (char[]){0x09, 0x04},           // 0: LANGID (US English)
       "VIPER-S3",                      // 1: Manufacturer
       "VIPER-S3 HID/CDC",              // 2: Product
       s_serial_str,                    // 3: Serial (MAC-based, populated at init)
       "HID Keyboard",                  // 4: HID Interface
       "CDC Serial",                    // 5: CDC Interface
       NULL                             // terminator
   };
   ```
3. Pass descriptors via `tinyusb_config_t` in `usb_engine_init()`:
   ```c
   const tinyusb_config_t tusb_cfg = {
       .device_descriptor = &s_dev_desc,
       .string_descriptor = s_str_desc,
       .string_descriptor_count = 6,
       .external_phy = false,
       .configuration_descriptor = s_config_desc,
   };
   ```

**Important**: If `configuration_descriptor` is NULL and `CFG_TUD_HID > 0`, `tinyusb_set_descriptors()` returns `ESP_ERR_INVALID_ARG`. The custom config descriptor MUST be provided.

### String Descriptor Format

Index 0 (LANGID): 2 bytes `{0x09, 0x04}` = US English (0x0409 LE)
Index 1+: null-terminated UTF-8 strings. The built-in `tud_descriptor_string_cb` in `descriptors_control.c` converts them to UTF-16LE.

### Serial Number

Populated at runtime from WiFi STA MAC address:
```c
uint8_t mac[6] = {0};
esp_read_mac(mac, ESP_MAC_WIFI_STA);
snprintf(s_serial_str, sizeof(s_serial_str), "%02X%02X%02X%02X%02X%02X",
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
```

---

## ESP-IDF v5.3 API Migration — Complete Fix Log

### 1. `esp_efuse_mac_get_default()` → `esp_read_mac()`

- **File**: `components/usb_engine/usb_engine.c`
- **Change**: `esp_efuse_mac_get_default(NULL)` replaced with `esp_read_mac(mac, ESP_MAC_WIFI_STA)`
- **Reason**: `esp_efuse_mac_get_default()` signature changed in v5.3; the new API requires explicit MAC type

### 2. Missing `#include "esp_mac.h"`

- **File**: `components/usb_engine/usb_engine.c`
- **Change**: Added `#include "esp_mac.h"`
- **Reason**: `esp_mac.h` was decoupled from `esp_system.h` in v5.3; `esp_read_mac()` now requires explicit include

### 3. `TUD_CDC_DESCRIPTOR` extra argument

- **File**: `components/usb_engine/usb_engine.c`
- **Change**: Added 7th argument `64` to `TUD_CDC_DESCRIPTOR(ITF_NUM_CDC_COM, STRID_CDC, 0x82, 64, 0x83, 64, 64)`
- **Reason**: Newer TinyUSB version requires a buffer size parameter for CDC

### 4. `httpd_req_get_url_query_str()` return type change

- **File**: `components/web_dashboard/web_dashboard.c`
- **Change**: Replaced `httpd_req_get_url_query_str(req) ?: ""` (GNU extension, returned `const char*`) with proper buffer-based call: `httpd_req_get_url_query_str(req, buf, len)`
- **Reason**: Return type changed from `const char*` to `esp_err_t` in ESP-IDF v5.3

### 5. `rmt_rx_stop()` → `rmt_disable()`

- **File**: `components/ir_engine/ir_engine.c` (lines 320, 331)
- **Change**: `rmt_rx_stop(chan)` → `rmt_disable(chan)`
- **Reason**: `rmt_rx_stop()` was removed in ESP-IDF v5.3 RMT API

### 6. `rmt_receive()` argument order

- **File**: `components/ir_engine/ir_engine.c` (line 347)
- **Change**: Corrected argument order to `rmt_receive(chan, buf, buf_size, wait_ms)`
- **Reason**: API changed in v5.3 — new order is `(channel, buffer, buffer_size, wait_ms)`

### 7. Sequence point violation in IR callback

- **File**: `components/ir_engine/ir_engine.c` (`rx_done_cb`)
- **Change**: Fixed undefined behavior where `pulses[++i]` was used on same `i` as loop index variable
- **Reason**: C sequence point rule violation (undefined behavior)

### 8. `NFC_TAG_TYPE_MAX` overflow

- **File**: `components/nfc_engine/include/nfc_engine.h`
- **Change**: Increased from 16 to 32
- **Reason**: `snprintf` into tag type buffer was truncating because the tag type name exceeded the buffer size

### 9. Missing includes in AI engine

- **File**: `components/ai_engine/ai_engine.c`
- **Change**: Added `#include "freertos/FreeRTOS.h"`, `#include "freertos/task.h"`, `#include "ble_engine.h"`, `#include "wifi_engine.h"`
- **Reason**: Used FreeRTOS APIs and engine extern declarations without including their headers

### 10. `web_dashboard_broadcast()` argument format

- **File**: `components/attack_orchestrator/attack_orchestrator.c`
- **Change**: All 7 calls to `web_dashboard_broadcast()` rebuilt with pre-formatted `snprintf` buffers
- **Reason**: Function signature is `(event_type, json_data)` — no printf-style variadic args. Original code passed format strings directly

### 11. Format specifier fixes

- **File**: `components/attack_orchestrator/attack_orchestrator.c` (lines 371, 377)
- **Change**: `bool` → `%d`, `uint32_t` → `%lu`
- **Reason**: Mismatched format specifiers caused undefined behavior

### 12. Camera init signature

- **File**: `main/main.c` (line 86)
- **Change**: `camera_engine_init()` now passes `&CAMERA_CONFIG_DEFAULT`
- **Reason**: Function signature changed when the camera config header was updated

### 13. Web dashboard forward declarations

- **File**: `components/web_dashboard/web_dashboard.c`
- **Change**: Added forward declarations for all 16 REST API handlers before the `uri` array
- **Reason**: `esp_http_server` requires handlers to be declared before use in the URI table; was implicitly declared causing potential issues

### 14. HTML string escaping

- **File**: `components/web_dashboard/web_dashboard.c` (line 515)
- **Change**: `"Scan Now"` → `&quot;Scan Now&quot;`
- **Reason**: Double quotes inside C string literal would terminate the string early

### 15. `TINYUSB_HID_COUNT=0` → `=1`

- **File**: `sdkconfig`, `sdkconfig.defaults`
- **Change**: Set `CONFIG_TINYUSB_HID_COUNT=1`
- **Reason**: At 0, the HID code path was preprocessor-excluded, causing `tud_hid_n_keyboard_report()` to be undefined at link

### 16. `TINYUSB_MSC_ENABLED` disabled

- **File**: `sdkconfig`, `sdkconfig.defaults`
- **Change**: Unset `CONFIG_TINYUSB_MSC_ENABLED`
- **Reason**: MSC endpoint was enabled but no MSC callbacks were implemented; the MSC stub returned `ESP_ERR_NOT_SUPPORTED`, causing linker errors from TinyUSB expecting real MSC callbacks

### 17. WebSocket support enabled

- **File**: `sdkconfig`, `sdkconfig.defaults`
- **Change**: Set `CONFIG_HTTPD_WS_SUPPORT=y`
- **Reason**: Dashboard uses WebSocket API; without this config, `httpd_ws_*` functions are stubs

---

## Flash Commands

### Combined Binary (Single File — Easiest)

```bash
python3 -m esptool --chip esp32s3 -b 460800 write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 build/viper_s3_combined.bin
```

### Separate Files

```bash
python3 -m esptool --chip esp32s3 -b 460800 write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 build/bootloader/bootloader.bin \
  0x8000 build/partition_table/partition-table.bin \
  0x10000 build/viper_s3.bin
```

### Monitor

```bash
idf.py -p /dev/ttyACM0 monitor
```

### Merge Command (to regenerate combined binary)

```bash
cd build && python3 -m esptool --chip esp32s3 merge_bin \
  --output viper_s3_combined.bin \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 bootloader/bootloader.bin \
  0x8000 partition_table/partition-table.bin \
  0x10000 viper_s3.bin
```

---

## Build Output Files

| File | Size | Flash Offset |
|------|------|-------------|
| `build/bootloader/bootloader.bin` | ~22KB | 0x0 |
| `build/partition_table/partition-table.bin` | 3KB | 0x8000 |
| `build/viper_s3.bin` | ~1.3MB | 0x10000 |
| `build/viper_s3_combined.bin` | ~1.3MB | 0x0 (merged) |

---

## Managed Components / Dependencies

From `dependencies.lock`:
- `espressif/esp-tinyusb` — TinyUSB port (version managed by dependency manager)

All other components are local in `components/`.

---

## Wi-Fi Configuration

- **AP**: 192.168.4.1/24
- **STA**: Connects to configured network
- **Dashboard**: port 80

---

## Attack Orchestrator Chains

1. **CHAIN_BLE_MITM**: Scan → connect → proxy 30s → report
2. **CHAIN_DEAUTH**: Scan → sequential deauth on each AP
3. (Additional chains defined in `attack_orchestrator.c`)

---

## Known Issues / Gotchas

1. **sdkconfig vs sdkconfig.defaults**: After `idf.py reconfigure` or `idf.py build`, sdkconfig can be overwritten. Always update `sdkconfig.defaults` for persistent changes.
2. **Managed components**: `espressif__esp_tinyusb` is in `managed_components/` — do NOT edit these files directly if they can be re-downloaded. If you need to modify them, copy to `components/` first.
3. **USB Descriptor conflict**: If you re-add `tud_descriptor_*` callbacks to `usb_engine.c`, you will get duplicate symbol errors with `descriptors_control.c`. Always pass descriptors via `tinyusb_config_t` instead.
4. **MSC**: Not implemented — `CONFIG_TINYUSB_MSC_ENABLED` is disabled. If you add MSC support, re-enable it and implement `tud_msc_*` callbacks.
5. **PSRAM**: 8MB available but not explicitly configured for all components — check if large allocations need PSRAM support.
6. **Camera init**: `camera_engine_init()` takes a config pointer — ensure `CAMERA_CONFIG_DEFAULT` is defined in the camera component.
7. **LittleFS**: 10MB partition at 0x410000 — used for wordlists, captures, payloads, configs.
8. **Build from clean**: Run `idf.py fullclean` then `idf.py build` if you see stale object errors.

---

## Debugging Tips

1. **Monitor logs**: `idf.py -p /dev/ttyACM0 monitor` — log levels are configurable per component
2. **USB enumeration**: Check `dmesg` on macOS/Linux after plugging in — should show HID and CDC devices
3. **WebSocket**: Use browser DevTools → Network → WS to inspect real-time events
4. **Core dumps**: Stored in Coredump partition (0xE10000, 1MB) — retrieve with `espcoredump.py`
5. **sdkconfig diff**: After `idf.py reconfigure`, diff sdkconfig against sdkconfig.defaults to see what changed
6. **Linker errors**: Check `CONFIG_TINYUSB_*` settings first — many TinyUSB features are compile-time gated
7. **Stack overflow**: Increase task stack sizes in component init functions if you see watchdog resets

---

## Recent Commits (as of last build)

```
4cbfb29 — main — fixed usb_engine descriptor conflict — pass descriptors via tinyusb_config_t
```

Prior commits include all the individual API migration fixes listed above.

---

## Build Status

| Check | Status |
|-------|--------|
| Compile | ✅ Clean (no warnings treated as errors) |
| Link | ✅ Clean (no undefined symbols) |
| Binary generation | ✅ viper_s3.bin + combined generated |
| Flash size | 1.3MB / 4MB app partition (69% free) |
| Bootloader size | 22KB / 32KB (31% free) |

---

## Contact / Notes

- Project root: `/Users/anoircherif/Desktop/S3/antigravity`
- IDF path: `~/esp/esp-idf`
- Built by opencode with assistant guidance
- Last build: May 14, 2026
