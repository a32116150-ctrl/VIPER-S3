# VIPER-S3 Project Memory

## Overview

VIPER-S3 (**V**isual **I**ntelligence **P**entesting & **E**xploitation **R**outer — **S3**) is a multi-function ESP32-S3 security testing tool with WiFi, BLE, USB, camera, NFC, IR, and AI capabilities.

---

## Hardware

- **SoC**: ESP32-S3 WROOM N16R8
- **Flash**: 16MB (qio mode, 80MHz)
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
2. **Start Camera engine** — moved to step 2 to allocate DMA descriptor buffers before internal DRAM pool gets fragmented by dashboard+WiFi
3. **Start Web Dashboard (port 80)** — CRITICAL: done BEFORE WiFi to maximize available DRAM; retries with smaller config if needed; heap logged before/after; /ping endpoint for quick test
4. Start WiFi (AP on 192.168.4.1 + STA) — HTTP server already bound to 0.0.0.0:80, accepts connections once AP is up
5. Start IR (GPIO2=TX, GPIO4=RX) — **graceful fallback**: logs warning, continues
6. Start NFC (PN532 UART: GPIO18=TX, GPIO5=RX) — **graceful fallback**: logs warning, continues
7. Initialize Crack Engine + Protocol Attacks — **graceful fallback**: logs warning, continues
8. Start BLE (NimBLE scanner + UART C2) — **graceful fallback**: logs warning, continues (BLE controller disabled to save DRAM)
9. Start USB (TinyUSB HID + CDC) — **graceful fallback**: logs warning, continues
10. Start AI Engine — **graceful fallback**: logs warning, continues
11. Launch Attack Orchestrator; Retry dashboard init if failed at step 3

**Note**: All steps after the dashboard are fully optional — any failure is logged as a warning but does not halt boot. The watchdog task monitors the HTTP server every 30s and attempts restart if it dies.

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
| `CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL` | `y` | Move NimBLE host memory to PSRAM to free internal DRAM for controller |
| `CONFIG_BT_CTRL_BLE_MAX_ACT` | `3` | Reduce controller DRAM pool size (was 6, lowered to 3) |
| `CONFIG_LWIP_MAX_SOCKETS` | `16` | HTTP server socket pool; actual max_open_sockets=8 in code to save DRAM |

### Flash Configuration

- `CONFIG_ESPTOOLPY_FLASHMODE_QIO` = y (qio mode)
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
- **Mode**: Dark SPA with 37 REST endpoints + WebSocket live updates
- **Access**: http://192.168.4.1 (AP mode) or device IP on STA network
- **WebSocket**: `/ws` for real-time event stream (fixed `.is_websocket = true` — was missing, causing browser to never receive 101 Switching Protocols)

### Frontend Tabs (13 implemented)
| Tab | Features | Status |
|-----|----------|--------|
| Overview | Status cards (heap, WiFi mode, clients, uptime, JS status), activity log | ✅ |
| WiFi | Scan APs | ✅ |
| Attacks | Evil twin, deauth, stop all | ✅ |
| Captures | Credentials, PMKID hashes, wipe | ✅ |
| Camera | MJPEG stream placeholder | ⚠️ Camera not active (DRAM issue) |
| Logs | WebSocket system log viewer | ✅ |
| BLE | Proprietary scan, MITM proxy | ✅ |
| Config | View device config via `/api/config` | ✅ |
| Responder | LLMNR/NBT-NS/mDNS poisoner + SMB honeypot start/stop/status | ✅ |
| Crack | Hash submission (NTLM/MD5/SHA1/SHA256), engine status, results | ✅ |
| Protocol | WPA3→WPA2 downgrade, canary tokens (create/list), behavioral analysis | ✅ |
| IR | IR Transceiver: Capture (NEC/Sony), Transmit (NEC), Learn/Replay | ✅ |
| NFC | NFC Reader/Cloner: Detect UID/Type, Clone (Magic tags) | ✅ |

### Nav Tab Switch Fix
Nav tabs stopped working after JS changes. **Root cause**: `addEventListener` registration broke after adding `loadConfig()` JS. **Fix**: Replaced `addEventListener('click', ...)` with inline `onclick='return switchPanel("name")'` attributes and a dedicated `switchPanel()` function.
**Update May 14**: Dashboard was "stuck in overview" due to panels being outside the `main` container and JS errors in capture parsing. **Fix**: Wrapped all panels in `main`, added robust `try-catch` to `switchPanel`, and updated `refreshCaptures` to handle line-delimited JSON (JSONL).

### Backend API Endpoints (28 total)
WiFi: scan, deauth, evil-twin, beacon-flood, pmkid, karma, captive-portal, dns-spoof, sniffer
BLE: scan, spam, proprietary-scan, mitm
Responder: start/stop/status
SMB: start/stop
Crack: start/status
Downgrade: start
Canary: create/list
Behavioral: list
Orchestrator: chains, triggers, health

### Missing Frontend Tabs (backend APIs exist, no frontend UI)
USB, AI/ML, Orchestrator

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

### 18. JavaScript syntax error — missing semicolon in embedded JS

- **File**: `components/web_dashboard/web_dashboard.c` (line 740)
- **Change**: Added `;` after `'}` in the `loadConfig` function's `forEach` call
- **Before**: `...JSON.stringify(d[k])+'</td></tr>'})"` followed by `"h+='</table>';"`
- **After**: `...JSON.stringify(d[k])+'</td></tr>'});"` followed by `"h+='</table>';"`
- **Root cause**: Two adjacent C string literals concatenated into `})h+='...'` with no semicolon. JS ASI does not insert a semicolon after `)` when followed by an identifier on the same logical line, causing `SyntaxError: Unexpected identifier 'h'`.
- **Detection**: Extracted JS was validated with `node --check`. Binary search across 500-char chunks found the exact error at offset 6509. The fix was verified by re-extracting and passing `node --check` and `new Function()`.

### 19. HTTP server stack overflow — dashboard HTML response hangs (v1)

- **File**: `components/web_dashboard/web_dashboard.c` (lines 1241, 847)
- **Change**: 
  - Increased `cfg.stack_size` from 2048 → 4096 (default)
  - Added `ESP_LOGI`/`ESP_LOGE` logging to `root_get_handler` for debugging
- **Before**: `cfg.stack_size = 2048;` — `httpd_resp_send` would hang silently when serving the ~27KB dashboard HTML due to insufficient handler task stack
- **After**: `cfg.stack_size = 4096;` — sufficient stack for chunked response of large HTML payload
- **Root cause**: The dashboard HTML grew to ~27KB with the addition of 3 new panels (Responder, Crack, Protocol), expanded JS, and inline CSS. The HTTP handler task's 2048-byte stack was too small for `httpd_resp_send` to allocate buffers and chunk the response. The connection would accept but no data was returned, causing the browser to show an infinite loading spinner.

### 20. HTTP server fails to start — ERR_CONNECTION_TIMED_OUT (May 14, v2)

- **File**: `components/web_dashboard/web_dashboard.c`, `main/main.c`, `sdkconfig.defaults`
- **Symptom**: Dashboard was unreachable (ERR_CONNECTION_TIMED_OUT) — browser couldn't connect to port 80 at all. WiFi AP existed and clients could connect, but HTTP server never responded.
- **Root cause**: The v1 fix set `cfg.stack_size = 8192;` (from 2048). This 6KB increase in task stack pushed internal DRAM over the limit during `httpd_start()`. With WiFi stack (~50KB) already allocated, there wasn't enough contiguous DRAM for the HTTP server task creation + LWIP socket buffers. `httpd_start()` returned an error silently, leaving port 80 unbound.
- **Fix applied** (May 14, 2026):
  1. **Moved dashboard BEFORE WiFi** in boot order (`main/main.c`): Dashboard init is now step [2/11] right after storage, before WiFi consumes ~50KB DRAM. The HTTP server binds to 0.0.0.0:80, and when WiFi comes up later the AP interface routes traffic to it.
  2. **Reduced `cfg.stack_size` to 4096** (from 8192): With chunked transfer encoding (512-byte chunks), the handler's peak stack usage is minimal. 4096 is the ESP-IDF default and sufficient.
  3. **Disabled BLE controller** (`sdkconfig.defaults`): Set `CONFIG_BT_CONTROLLER_DISABLED=y`. The BLE controller consumes ~30KB of internal DRAM. Disabling it saves this memory. The NimBLE host code still compiles; `ble_engine_init()` will fail gracefully with a logged warning. Re-enable by setting `CONFIG_BT_CONTROLLER_DISABLED=n` and `CONFIG_BT_CTRL_BLE_MAX_ACT=3`.
  4. **Added retry-with-fallback in `try_start_server()`**: First tries 8 sockets / 4KB stack. If that fails, retries with 4 sockets / 3KB stack. Logs heap and largest free block at each attempt.
  5. **Added `/ping` endpoint**: Returns "OK" immediately — quick way to test if the HTTP server is alive at `http://192.168.4.1/ping`.
  6. **Retry dashboard init after WiFi**: If dashboard failed before WiFi, it tries again after WiFi is up (DRAM may have shifted).
  7. **Increased LWIP memory pools** (`sdkconfig.defaults`): `CONFIG_LWIP_MEM_NUMBUF=64`, `CONFIG_LWIP_TCP_MSS=1460`, `CONFIG_LWIP_TCP_WND=32768` for more reliable socket buffer allocation.
- **Result**: Dashboard starts reliably because it allocates its task stack before WiFi and BLE consume DRAM. Even if `httpd_start()` fails with the full config, it automatically retries with a smaller config.

---

## Flash Commands

### Combined Binary (Single File — Easiest)

```bash
. ~/esp/esp-idf/export.sh
esptool.py --chip esp32s3 -b 115200 write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 build/viper_s3_combined.bin --verify
```

> **Note**: 115200 baud is most reliable. Use `--verify` to confirm all bytes written.

### Separate Files

```bash
. ~/esp/esp-idf/export.sh
esptool.py --chip esp32s3 -b 115200 write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 build/bootloader/bootloader.bin \
  0x8000 build/partition_table/partition-table.bin \
  0x10000 build/viper_s3.bin --verify
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
- **SSID**: `VIPER-S3` (was `AndroidAP_3F7A`)
- **Password**: `00000000` (⚠️ Currently open/no-password — WPA2-PSK auth is broken, needs investigation)
- **STA**: Connects to configured network
- **Dashboard**: port 80
- **HTTP Server Config** (`web_dashboard_init`): `max_open_sockets=8`, `max_uri_handlers=37`, `stack_size=8192`, `lru_purge_enable=true`, retry fallback: 4 sockets / 6KB stack

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
9. **Internal DRAM fragmentation**: ESP32-S3 has ~153KB internal DRAM split across 3 regions. WiFi + BLE controller + camera DMA consume/fragment it severely. Camera DMA allocation fails (`DMA buffer 16384 Byte malloc failed, largest free block:2816 Byte`). HTTP server was moved before camera to avoid this.
10. **BLE init failure is graceful**: `nimble_port_init()` returns `ESP_ERR_NO_MEM` during controller init, but the system logs a warning and continues without BLE. No reboot loop.
11. **USB init failure is graceful**: `tinyusb_driver_install()` failure no longer triggers `ESP_ERROR_CHECK` abort. System logs and continues.
12. **HTTP server may fail to start**: If camera engine runs before HTTP server, DRAM fragmentation causes `httpd_start()` to fail. **Fixed** by moving dashboard before camera in boot order.
13. **Flash baud rate**: 115200 is reliable for esptool. Higher rates (460800) may fail on some USB-serial adapters.
14. **WPA2-PSK auth broken**: AP with `WIFI_AUTH_WPA2_PSK` and password `00000000` fails authentication on all clients. Temporarily using open AP. Needs investigation — possibly PMF, cipher, or ESP-IDF v5.3 WiFi config quirk.
15. **Dashboard limited frontend**: 11 of 20+ documented tabs are implemented in the SPA HTML/JS. Backend REST APIs exist for USB, NFC, IR, AI/ML, Orchestrator but have no frontend UI. Responder, Crack, and Protocol Attacks tabs added May 14.
16. **Camera placeholder**: Camera tab shows "not active" because DMA allocation fails (DRAM fragmentation). Graceful fallback works — no crash.
17. **HTTP server boot-loop**: Setting `max_open_sockets=12` + `stack_size=3072` + `max_uri_handlers=31` simultaneously exhausted internal DRAM during `httpd_start()`. Error: `lwip_arch: thread_sem_init: out of memory`. **Fix**: `max_open_sockets` reduced to 8, `max_uri_handlers=31` kept (just a pointer table, ~124 bytes). All 31 URI handlers now register cleanly.
18. **HTTP server stack_size regression (May 14)**: After a refactor, `cfg.stack_size` was reset from 4096 back to 2048. Combined with HTML growth to ~30KB (IR + NFC panels), the dashboard hung with infinite loading spinner. **Fix**: Set to 4096 (with chunked transfer), retry w/ smaller config on failure, watchdog, fallback error page. See fix #20 above.
 
---

## Internal DRAM Pressure

The ESP32-S3 has ~153KB of internal DRAM split across 3 address regions. This is the critical bottleneck.

### DRAM Consumers

| Component | Estimated DRAM Usage |
|-----------|---------------------|
| WiFi stack (LWIP + netif) | ~40-50KB |
| BLE controller (BT_CTRL_BLE_MAX_ACT=3) | ~25-30KB |
| BLE host (NimBLE) | Moved to PSRAM via `CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL=y` |
| Camera DMA buffers | ~32KB (2 × 16KB for MJPEG) |
| HTTP server task stack | 2-4KB |
| FreeRTOS kernel + tasks | ~10-15KB |
| Other (USB, IR, NFC, etc.) | ~10-20KB |

### Current Failures

1. **Camera DMA**: `DMA buffer 16384 Byte malloc failed, largest free block:2816 Byte` — no 16KB contiguous block available after WiFi + BLE controller allocate.
2. **BLE controller**: `controller init failed: Malloc failed` — even at MAX_ACT=3, the controller's internal DRAM pool can't be satisfied alongside WiFi + camera.

### Mitigation Strategies

- **Move HTTP server before camera** in boot order (change `main.c` sequence) — dashboard is more critical than camera
- **Reduce HTTP server stack** from 4096 to 2048 (already done) — keep at 2048, do not raise
- **Reduce max_open_sockets** from 12 to 8 (saves ~6KB DRAM from LWIP socket buffers)
- **Set max_uri_handlers explicitly** to 31 (all URI handlers fit, cost is ~124B for pointer table)
- **Disable BLE controller entirely** (`CONFIG_BT_CONTROLLER_DISABLED=y`) if BLE is non-functional
- **Reduce camera DMA buffer** size from 16KB to 8KB (may affect MJPEG quality)
- **Use PSRAM for camera frame buffers** if camera driver supports it

---

## Debugging Tips

1. **Monitor logs**: `idf.py -p /dev/ttyACM0 monitor` — log levels are configurable per component
2. **USB enumeration**: Check `dmesg` on macOS/Linux after plugging in — should show HID and CDC devices
3. **WebSocket**: Use browser DevTools → Network → WS to inspect real-time events
4. **Core dumps**: Stored in Coredump partition (0xE10000, 1MB) — retrieve with `espcoredump.py`
5. **sdkconfig diff**: After `idf.py reconfigure`, diff sdkconfig against sdkconfig.defaults to see what changed
6. **Linker errors**: Check `CONFIG_TINYUSB_*` settings first — many TinyUSB features are compile-time gated
7. **Stack overflow**: Increase task stack sizes in component init functions if you see watchdog resets
8. **DRAM fragmentation**: Use `heap_caps_get_free_size(MALLOC_CAP_INTERNAL)` and `heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)` to diagnose fragmentation. ESP-IDF `heap_trace` can track allocations.
9. **Check free DRAM at boot**: Insert `heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)` calls between each init step in `main.c` to pinpoint where fragmentation occurs.
10. **Flash baud rate**: Use `-b 115200` if higher rates fail. The combined binary at 115200 is verified working.

---

## Recent Commits (as of last build)

```
4cbfb29 — main — fixed usb_engine descriptor conflict — pass descriptors via tinyusb_config_t
4cb78db — main — BLE graceful fallback, WiFi AP rename, USB graceful init, LWIP MAX_SOCKETS=16, BT_CTRL_BLE_MAX_ACT=3, BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL=y, HTTP server stack 2048
```

Prior commits include all the individual API migration fixes listed above.

---

## Build Status

| Check | Status |
|-------|--------|
| Compile | ✅ Clean (0 errors, pre-existing unused-variable warnings only) |
| Link | ✅ Clean (no undefined symbols) |
| Binary generation | ✅ viper_s3.bin (0x136a10) + combined generated |
| Flash size | ~1.24MB / 4MB app partition (70% free) |
| Bootloader size | 22KB / 32KB (31% free) |
| WiFi AP | ✅ PMF fix applied (inline `.pmf_cfg` in config struct) |
| WiFi Scanner | ✅ Fixed (ap_count init'd to WIFI_MAX_SCAN_RESULTS) |
| NTLM Cracking | ✅ Fixed (MD4 Round 3 permutation corrected) |
| BLE init | ⚠️ Graceful fallback — controller disabled (`CONFIG_BT_CONTROLLER_DISABLED=y`), NimBLE host compiles |
| USB init | ⚠️ Graceful fallback — logs warning on failure, continues |
| Camera init | ✅ PSRAM DMA mode enabled — skips 16KB internal DRAM allocation |
| Web Dashboard | ✅ **Reliable**: starts before WiFi (max DRAM), 16 frontend tabs, 53 REST endpoints, WS live updates, chunked transfer, watchdog, fallback error page |
| Code Health | ⚠️ ~15 medium/low issues remaining after Fix #27 batch |

---

---

## Vulnerability Report (May 17, 2026)

Source-verified findings from code audit across all 13 components.

### 🔴 CRITICAL (All 3 Fixed May 17, 2026)

| # | Component | Vulnerability | Fix |
|---|-----------|--------------|-----|
| **C1** | `downgrade.c:101,106` | SSL strip task stack overflow — 8KB stack buffers on 4KB task | Moved `buf`, `modified`, `resp` from stack to heap (malloc/free); increased task stack to 6144 |
| **C2** | `downgrade.c:146-148` | Infinite read loop — no limit on proxy recv | Added `reads < 256` guard to while loop |
| **C3** | `web_dashboard.c:31,38-50` | Race condition on `s_ws_count` — non-atomic counter | Added `SemaphoreHandle_t s_ws_mutex` protecting all WS client list operations |

### 🟠 HIGH (All 9 Fixed May 17, 2026)

| # | Component | Vulnerability | Fix |
|---|-----------|--------------|-----|
| **H1** | `ir_engine.c:429-430` | Off-by-one OOB write — `buf[len]='\0'` when read > 4096 | Added `if (len >= sizeof(buf))` guard |
| **H2** | `nfc_engine.h:50` vs `nfc_engine.c:341-351` | Misleading API contract — writes `data[0..3]` | Added `NFC_BLOCKS_PER_SECTOR` + `num_blocks` param capped to 4 |
| **H3** | `nfc_engine.c:425,430` | `%s` on non-null-terminated NFC payload | Replaced `snprintf` with `memcpy` + explicit length + null terminator |
| **H4** | `wifi_beacon_flood.c:86-89,128-131` | Double-free race on stop | Added `s_task_freeing_list` flag to prevent concurrent free |
| **H5** | `attack_orchestrator.c:477-487` | Unsafe `vTaskDelete` no sync | Replaced with `xTaskNotifyGive` + `ulTaskNotifyTake` self-delete |
| **H6** | `canary.c:54-55` | String not null-terminated at max length | Added `c->token[i]='\0'`, `c->target_url[i]='\0'` after copy |
| **H7** | `ir_engine.h:60-62` | Declared but unimplemented (runtime crash) | Added stub implementations returning 0 |
| **H8** | `responder.c:49,69` | ARCOUNT not explicitly set — relies on memset | Added `resp[10]=0; resp[11]=0;` |
| **H9** | `ir_engine.c:316-323` | RMT enable/disable race | Added `s_ir_mutex` around capture state transitions |

### 🟡 MEDIUM (All 13 Fixed May 17, 2026)

| # | Component | Vulnerability | Fix |
|---|-----------|--------------|-----|
| **M1** | `web_dashboard.c:157` | Hardcoded 4096 in snprintf — heap overflow on small scans | Changed to use `buf_size` (actual allocated size) |
| **M2** | `web_dashboard.c:463-464` | Fuzzy `strstr` query match — unintended file access | Changed to `strcmp` exact match |
| **M3** | `behavioral.c:165` | Confidence always 0.7f — misleading results | Now scales with packet count (0.0–0.85) |
| **M4** | `wifi_eviltwin.c:19,42` | Non-atomic client counter — counter drift | Changed to `atomic_uint_fast8_t` with atomic ops |
| **M5** | `wifi_karma.c:101-105` | Unchecked esp_wifi_* returns — silent failure | Added checks + `return ESP_FAIL` on failure |
| **M6** | `crack_engine.c:173,209` | Unchecked mbedTLS returns — garbage hash on fail | Added return check + skip on failure |
| **M7** | `ir_engine.c` | Unchecked RMT returns — silent init failure | Added return checks with error logging |
| **M8** | `responder.c:260` | Multicast join failure silently ignored | Closes socket + returns -1 on failure |
| **M9** | `storage_manager.c` | Wordlist buffer 128B — passwords >127 chars truncated | Increased to 512B |
| **M10** | `downgrade.c:188-194` | `deinit` doesn't stop evil twin — orphan AP | Added `wifi_eviltwin_stop()` call |
| **M11** | `nfc_engine.c:419-432` | `%s` on non-null-terminated buffer — overread | Fixed in H3 — `memcpy` + explicit length |
| **M12** | `wifi_pmkid.c:130` | `esp_timer_start_periodic` return unchecked | Added return check + cleanup on failure |
| **M13** | `sdkconfig.defaults` | CPU 240MHz config missing — 33% lower perf | Added `CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240` |

### 🔵 LOW / INFORMATIONAL

| # | Component | Vulnerability | Fix |
|---|-----------|--------------|-----|
| **L1** | All API endpoints | **No authentication** — any network client can trigger attacks, read captures | Fixed — pre-shared API key `X-API-Key` header on all endpoints; `POST /api/auth` login; default `"viper"`; stored in config.json |
| **L2** | Dashboard | **No HTTPS** — all traffic (including captures viewed in UI) in plaintext | Fixed — HTTPS server on port 443 with embedded self-signed cert (SAN: 192.168.4.1, viper-s3.local); falls back to HTTP if SSL init fails |
| **L3** | `wifi_engine.h:105` | `wifi_set_mac` declared but never defined | Fixed — removed dead declaration |
| **L4** | Multiple files | 20+ REST endpoints missing `Content-Type: application/json` (defaults to `text/html`) | Fixed — added `httpd_resp_set_type(req, "application/json")` to all 25+ JSON endpoints |
| **L5** | `sdkconfig.defaults` | 8 unknown Kconfig symbols (renamed/removed in ESP-IDF v5.3) | Not started — run `idf.py reconfigure` to diff |
| **L6** | WPA2-PSK | AP uses open auth — WPA2-PSK broken, any client can connect | Code fix attempted (WPA2 with PMF disabled) but untested; USB enumeration broken prevents flash |

---

## Contact / Notes

- Project root: `/Users/anoircherif/Desktop/S3/antigravity`
- IDF path: `~/esp/esp-idf`
- Built by opencode with assistant guidance
- Last build: May 15, 2026 (Build succeeded — 0x136a10, 70% app partition free)
- Last fix batch: May 15, 2026 (Fix #27 — 17 critical/high runtime bugs fixed across 9 components)

---

## Pending Issues (May 15, 2026) — Updated

### USB Enumeration Failure After Flash
- **Symptom**: After a successful `idf.py flash` + hard reset, the ESP32-S3 USB serial port (`/dev/cu.usbmodem5B3E0963551`) disappeared and never re-enumerated. The device is not visible in `system_profiler SPUSBDataType` or `ioreg`.
- **Impact**: Cannot run `idf.py monitor` to read boot logs, cannot flash new firmware.
- **Tried**: Unplug/replug, hold BOOT while plugging in, `sudo killall -STOP/COMT usbd`, `ifconfig awdl0 down/up`, different USB ports.
- **Hypothesis**: Possibly a USB cable issue (power-only), or the ESP32-S3 USB-serial-JTAG bridge entered an unrecoverable state after the hard reset.
- **Next step**: Reboot MacBook, try different USB cable. If device still doesn't enumerate, check if ESP32-S3 board has a hardware fault (e.g., burnt USB-serial bridge).

### Fixes Applied (all 20 critical/high runtime bugs from May 15 audit now fixed)

**Fix #26 batch** (PMF, scanner, MD4 — 3 critical compile bugs):
1. PMF fix v2 — replaced removed `esp_wifi_disable_pmf_config()` with inline `.pmf_cfg = {.required = false}`
2. WiFi scanner fix — `ap_count` init'd to `WIFI_MAX_SCAN_RESULTS` instead of `0`
3. MD4 Round 3 fix — fixed OOB permutation `x[k + (i%4)*4]` → `x[k + i/4]`

**Fix #27 batch** (17 critical/high runtime bugs):
4. WS client FD removed on drop — fixes stale WS client pool exhaustion
5. `POST /api/usb/payload/run` endpoint added — fixes USB Run button 404
6. IR capture timeout reduced 5s → 0.5s — fixes HTTP handler blocking
7. JSONL → valid JSON conversion — fixes unparseable creds/hashes API response
8. mDNS responder port check removed — mDNS now functional (was filtering ALL queries)
9. SSL strip connects to target server — proxy now relays HTTP responses
10. Credential trigger uses `fseek(SEEK_END)` — detects file growth beyond 64 bytes
11. Ducky Script REPEAT/DEFAULTDELAY fixed — consolidated implementation
12. AI twin spawn_all spawns each BLE device once (not N times)
13. AI beacon flood runs once (not N times) with correct PPS conversion
14. BLE MITM mbuf freed on intercept path — memory leak fixed
15. JSON escaping in credential/hash logging — prevents JSON injection from special chars
16. `storage_read_file` NULL check on `read_len` — prevents crash
17. `crack_engine_crack` returns per-run (not cumulative) attempt count
18. Multicast join failure now logged as warning

### Fix Log

#### Fix #27 — 17 Critical/High Runtime Bugs Fixed (2025-05-15)
- **Problem**: Comprehensive code review (May 15, 2026) identified 20 critical runtime bugs and 12+ high-severity issues. 3 critical compile bugs were fixed immediately (Fix #26). 17 remaining critical/high bugs were fixed in this batch.
- **Fixes applied May 15, 2026**:
  1. **#4 WS client leak** (`web_dashboard.c`): Removed WS client FD from pool on `httpd_ws_recv_frame` error (not just CLOSE frame)
  2. **#5 Missing USB endpoint** (`web_dashboard.c`): Added `POST /api/usb/payload/run` handler — reads payload from LittleFS and executes
  3. **#6 IR capture blocks HTTP** (`web_dashboard.c`): Reduced IR capture poll timeout from 5s (50×100ms) to 0.5s (10×50ms) to unblock HTTP handler
  4. **#7 JSONL invalid JSON** (`web_dashboard.c`): Added `jsonl_to_json_array()` helper — replaces `\n` with `,` between JSONL entries, strips trailing comma, corrects count
  5. **#8 mDNS responder broken** (`responder.c`): Removed `ntohs(src.sin_port) != 5353` guard — mDNS queries always originate from port 5353, the check was filtering ALL queries
  6. **#9 SSL strip doesn't connect** (`downgrade.c`): Rewrote proxy to parse Host header, resolve target via `lwip_gethostbyname`, connect to target, forward modified request, and relay response back to client
  7. **#10 Cred trigger 64B limit** (`attack_orchestrator.c`): Replaced 64-byte read with `fseek(SEEK_END)` to get actual file size for change detection
  8. **#11-13 Ducky Script REPEAT/DEFAULTDELAY** (`usb_payloads.c`, `usb_ducky.c`): Fixed return-value contract (`r==1` stores repeat line, `r>1` triggers repeat), consolidated `usb_ducky_execute` to delegate to `usb_payload_execute_script`, added shared `usb_payload_set_default_delay()` setter, fixed `execute_line` to return 1 for normal commands
  9. **#14-16 AI twin spawn bugs** (`ai_engine.c`): Fixed `ai_twin_spawn_all` — spawns each BLE device once (was inner loop always finding first BLE), builds SSID list once (was running N flood tasks), converts `beacon_interval_ms` to PPS (`1000/interval`)
  10. **#17 BLE MITM mbuf leak** (`ble_mitm.c`): Added `os_mbuf_free_chain(event->notify_rx.om)` on intercept path to free original mbuf when creating modified copy
  11. **#18 JSON injection in credentials** (`storage_manager.c`): Added `json_escape()` helper — escapes `"`, `\`, `\n`, `\r`, `\t` in all credential/hash log fields before writing JSONL
  12. **#19 NULL read_len crash** (`storage_manager.c`): Added null check before `*read_len = fread(...)`
  13. **#20 Cumulative attempt count** (`crack_engine.c`): Captured `s_total_attempts` before each crack run and computed per-run attempts as delta
  14. **#21 Multicast join silent failure** (`responder.c`): Added `ESP_LOGW` when `IP_ADD_MEMBERSHIP` setsockopt fails
- **Build**: Clean compile (0 errors, pre-existing unused-variable warnings only), binary size `0x136a10` (70% app partition free)

#### Fix #26 — PMF API removed in ESP-IDF v5.3, WiFi scan returns zero APs, MD4 Round 3 OOB (2025-05-15)
- **Problem**: Three critical bugs found by comprehensive agent-based code review:
  1. `esp_wifi_disable_pmf_config()` was removed in ESP-IDF v5.3 — compilation blocker
  2. `wifi_scanner.c:103` — `ap_count = 0` caused `esp_wifi_scan_get_ap_records()` to return zero APs every scan
  3. `crack_engine.c:41` — MD4 Round 3 used `x[k + (i%4)*4]` causing out-of-bounds read at `x[24]` (array is `x[16]`); NTLM hashes were always wrong
- **Fixes applied May 15, 2026**:
  1. Replaced `esp_wifi_disable_pmf_config()` with inline `.pmf_cfg = {.required = false}` in `wifi_config_t.ap`
  2. Changed `uint16_t ap_count = 0` to `uint16_t ap_count = WIFI_MAX_SCAN_RESULTS`
  3. Changed `x[k + (i%4)*4]` to `x[k + i/4]` in MD4 Round 3
- **Build**: Clean compile, 0 errors, 2 pre-existing unused-variable warnings

#### Fix #25 — WPA2-PSK auth fails on all clients (2025-02-22, revised 2025-05-15)
- **Problem**: WiFi AP with `WIFI_AUTH_WPA2_PSK` and password "00000000" fails authentication on all clients.
- **Root cause**: ESP-IDF v5.3 adds `pmf_cfg` to `wifi_ap_config_t` with PMF Optional by default. Stale NVS values (`ap.pmf_r=1`) from prior WPA3 usage or internal state cause PMF Required, which WPA2 clients don't support.
- **Fix v1**: `esp_wifi_disable_pmf_config(WIFI_IF_AP)` called after `esp_wifi_set_config()` in `wifi_engine.c`.
- **Fix v2 (May 15, 2026)**: `esp_wifi_disable_pmf_config()` was removed in ESP-IDF v5.3 — replaced with inline `.pmf_cfg = {.required = false}` in `wifi_config_t` initializer.

#### Fix #22 — Camera DMA OOM persists despite boot reorder (2025-02-22)
- **Problem**: Camera DMA buffer (16KB `MALLOC_CAP_DMA`) still fails despite moving camera to boot step 2.
- **Root cause**: Frame buffers use PSRAM (`fb_location=CAMERA_FB_IN_PSRAM`) but driver's internal DMA working buffer (`dma_buffer`) still required internal DRAM. `CONFIG_CAMERA_PSRAM_DMA` was not set, so `g_psram_dma_mode=false`.
- **Fix**: Added `CONFIG_CAMERA_PSRAM_DMA=y` to `sdkconfig.defaults`. PSRAM DMA mode skips the 16KB internal allocation entirely — DMA descriptors point directly to PSRAM.

#### Fix #21 — Missing Protocol nav link, no USB/AI/Orch frontend (2025-02-22)
- **Problem**: Protocol panel existed in HTML/JS but no nav link. USB, AI/ML, Orchestrator had no frontend UI at all.
- **Fix**: Added Protocol nav link + 3 new complete tabs (USB, AI, Orchestrator) with nav links, panels, JS, C API handlers, URI entries; 15 new endpoints; auto-calculated URI handler count.

#### Fix #20 — WebSocket never upgrade + handler OOM crash (2025-02-22)
- **Problem**: ESP-IDF never sent 101 Switching Protocols for `/ws`; OOM crash from `char buf[4096]` on 4096-byte stack.
- **Root cause**: `.is_websocket = true` missing from URI entry; stack overflow from 4096-byte local buffer on 4096-byte task stack.
- **Fix**: Added `.is_websocket = true` to `/ws` URI; doubled HTTP handler stack; moved large stack buffers to heap.

#### Fix #19 — MJPEG Streaming corrupted (2025-02-21)
- **Problem**: ESP32-S3 hardware JPEG encoder produces corrupt/tiled output on OV3660.
- **Root cause**: OV3660 outputs raw RGB/YUV, not MJPEG — JPEG compression must be done in software.
- **Solution**: Stream raw YUV or use software JPEG encoder (e.g. TinyJPEG).

#### Fix #18 — IR TX rebinds IR RX on same driver init (2025-02-21)
- **Problem**: RMT half-duplex mode caused TX and RX to claim the same GPIO/output pair.
- **Root cause**: Single RMT channel can't do TX+RX in half-duplex without explicit time-division.
- **Solution**: Two separate RMT driver instances — TX (GPIO2→RMT0), RX (GPIO4→RMT1).

#### Fix #17 — Pre-built ESP-WHO binary didn't include new camera/psram config (sdkconfig)
- **Problem**: Flashing pre-built ESP-WHO binary applies its own sdkconfig, not the project's.
- **Fix**: Built from source with `idf.py build` after setting correct config.

---

## Comprehensive Code Review — May 15, 2026

Agent-based audit across all 13 components. **30+ issues found, 3 critical compilation/runtime bugs fixed.**

### 🔴 CRITICAL (Fixed)

| # | Component | Issue | Fix |
|---|-----------|-------|-----|
| 1 | `wifi_engine.c:49` | `esp_wifi_disable_pmf_config()` removed in ESP-IDF v5.3 — compilation blocker | Replaced with inline `.pmf_cfg = {.required = false}` in `wifi_config_t` |
| 2 | `wifi_scanner.c:103` | `ap_count=0` passed to `esp_wifi_scan_get_ap_records` — returns zero APs every scan | Changed to `ap_count = WIFI_MAX_SCAN_RESULTS` |
| 3 | `crack_engine.c:41` | MD4 Round 3: `x[k + (i%4)*4]` reads `x[24]` (OOB, array is `x[16]`) | Changed to `x[k + i/4]` |

### 🔴 CRITICAL (All 17 Fixed in Fix #27 batch — May 15, 2026)

All 20 critical runtime bugs from the May 15 code review have been fixed:

| # | Component | Fix |
|---|-----------|-----|
| 4 | `web_dashboard.c` | WS client FD removed on recv error (not just CLOSE frame) |
| 5 | `web_dashboard.c` | Added `POST /api/usb/payload/run` handler |
| 6 | `web_dashboard.c` | Reduced IR capture poll from 5s to 0.5s |
| 7 | `web_dashboard.c` | Added JSONL→JSON comma conversion |
| 8 | `responder.c:228` | Removed `ntohs(src.sin_port) != 5353` mDNS guard |
| 9 | `downgrade.c:80-106` | Rewrote proxy to connect to target and relay responses |
| 10 | `attack_orchestrator.c:386` | Replaced 64B read with `fseek(SEEK_END)` |
| 11-13 | `usb_payloads.c`, `usb_ducky.c` | Consolidated Ducky Script executors, fixed REPEAT/DEFAULTDELAY |
| 14-16 | `ai_engine.c` | Fixed twin spawn logic, beacon flood once with correct PPS |
| 17 | `ble_mitm.c:318-327` | Added `os_mbuf_free_chain` on intercept path |
| 18-19 | `storage_manager.c` | Added JSON escaping + NULL read_len check |
| 20 | `crack_engine.c:257` | Per-run attempts via pre-call snapshot |

### 🟠 HIGH (All Fixed May 17, 2026)

| # | Component | Issue | Fix |
|---|-----------|-------|-----|
| 21 | `ir_engine.c:428` | Off-by-one: `buf[len]='\0'` writes beyond `buf` when read exceeds 4096 | Added `if (len >= sizeof(buf)) len = sizeof(buf) - 1` guard |
| 22 | `nfc_engine.h:50` vs `nfc_engine.c:341` | `nfc_read_sector` writes `data[0..3]` but signature hides array contract | Added `NFC_BLOCKS_PER_SECTOR` define, `num_blocks` param capped to 4 |
| 23 | `ir_engine.h:60-62` | 3 declared functions with no implementation | Added stub implementations returning 0 |
| 24 | `ir_engine.c:316-324` | `rmt_disable/enable` race on timeout | Added `s_ir_mutex` protecting capture state |
| 25 | `responder.c:66-85` | ARCOUNT bytes not explicitly set | Added `resp[10]=0; resp[11]=0;` after header setup |
| 26 | `smb_honey.c` | Stack buffer on small task | Reviewed — buffer is heap-allocated (`malloc`), no stack issue; removed from tracker |
| 27 | `wifi_eviltwin.c` | Event handler accumulates on restart | Reviewed — `stop()` unregisters handlers, `start()` calls `stop()` first; no issue |
| 28 | `wifi_beacon_flood.c` | Double-free race on stop | Added `s_task_freeing_list` flag to prevent concurrent free by task and stop() |
| 29 | `wifi_pmkid.c:123` | `esp_timer_create` return unchecked | Reviewed — return IS checked with early exit; no issue |
| 30 | `canary.c:54-56` | `load_canaries` doesn't null-terminate token/URL | Added `c->token[i]='\0'` and `c->target_url[i]='\0'` after copy loops |
| 31 | `behavioral.c:165` | Confidence hardcoded to 0.7f | Open — cosmetic, no runtime risk |
| 32 | `attack_orchestrator.c:467` | `vTaskDelete` without sync | Replaced with `xTaskNotifyGive` + self-deleting task via `ulTaskNotifyTake` |

### 🟡 MEDIUM (All Fixed May 17, 2026)

| # | Component | Issue | Fix |
|---|-----------|-------|-----|
| M1 | `web_dashboard.c` | Hardcoded `4096` as snprintf limit | Changed to use `buf_size` (actual allocated size) |
| M2 | `web_dashboard.c` | `strstr` fuzzy query match in download_handler | Changed to `strcmp` for exact match |
| M3 | `behavioral.c` | Confidence hardcoded to `0.7f` | Now scales with packet count: 0.0 (<10) to 0.85 (≥1000) |
| M4 | `wifi_eviltwin.c` | Non-atomic client counter | Changed to `atomic_uint_fast8_t` with `atomic_fetch_add/sub` |
| M5 | `wifi_karma.c` | `esp_wifi_*` return values unchecked | Added checks + `ESP_LOGE` + return `ESP_FAIL` on failure |
| M6 | `crack_engine.c` | `mbedtls_md5`/`mbedtls_sha1` returns unchecked | Added return check + `ESP_LOGW` + `continue` |
| M7 | `ir_engine.c` | `rmt_new_copy_encoder`/`rmt_enable` unchecked | Added return checks with error logging |
| M8 | `responder.c` | Multicast join failure silently ignored | Now closes socket and returns `-1` on join failure |
| M9 | `storage_manager.c` | Wordlist buffer 128 bytes | Increased `line[128]` → `line[512]` |
| M10 | `downgrade.c` | `deinit` doesn't stop evil twin | Added `wifi_eviltwin_stop()` on `DOWNGRADE_WPA3` active |
| M11 | `nfc_engine.c` | `%s` on non-null-terminated buffer | Fixed in H3 — replaced with `memcpy` + explicit length |
| M12 | `wifi_pmkid.c` | `esp_timer_start_periodic` return unchecked | Added check + cleanup + early return on failure |
| M13 | `sdkconfig.defaults` | CPU 240MHz config missing | Added `CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240` |

### Build System Notes

- `sdkconfig.defaults` has 8 unknown/warning Kconfig symbols (renamed or removed in v5.3)
- `EXTRA_COMPONENT_DIRS` lists `ir_engine`/`nfc_engine` separately but `components/` already covers them (harmless)
- `<dirent.h>` included in `storage_manager.c` but never used
- `<event_groups.h>` included in `attack_orchestrator.c` but never used
