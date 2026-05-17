# VIPER-S3

**V**isual **I**ntelligence **P**entesting & **E**xploitation **R**outer — **S3**

Multi-function ESP32-S3 security testing tool with WiFi, BLE, USB, camera, NFC, IR, and AI capabilities.

## Hardware

- ESP32-S3 WROOM N16R8 (16MB Flash, 8MB PSRAM)
- OV3660 camera (MJPEG stream, QR decode, motion detection)
- PN532 NFC module (UART)
- IR LED + receiver (RMT)

## Features

| Engine | Capabilities |
|---|---|
| **WiFi** | Scanner, deauth, evil twin, beacon flood, PMKID capture, karma, captive portal, DNS spoof, HTTP sniffer, SSL strip |
| **BLE** | Scanner, spam (7 types), UART C2, MITM proxy, extended advertising, proprietary scans (Apple/Google/Samsung/Tile/Microsoft) |
| **Camera** | MJPEG stream, motion detection, QR decode (quirc), burst capture |
| **USB** | HID keyboard, Ducky Script interpreter, payload library, OS fingerprint |
| **NFC** | MIFARE Classic/Ultralight/DESFire read/write, NDEF parse, tag emulation, clone |
| **IR** | NEC/Sony/Samsung encode/decode, learn, replay |
| **Responder** | LLMNR, NBT-NS, mDNS poisoning, SMB honey trap (NTLMSSP capture) |
| **Crack Engine** | On-device NTLM (~4M/s), MD5 (~5M/s), SHA1 (~3M/s), PMKID |
| **Protocol Attacks** | WPA3→WPA2 downgrade, SSL strip, canary tokens, behavioral fingerprinting |
| **AI/ML** | Decision tree, KNN classifier, packet feature extraction, digital twin generation |
| **Orchestrator** | Attack chains, triggers, scheduler, health monitor |
| **Dashboard** | Dark SPA with 53 REST endpoints, WebSocket live updates, 16 frontend tabs, HTTPS, API key auth |

## Partition Table (16MB)

| Partition | Offset | Size |
|---|---|---|
| NVS | 0x9000 | 24KB |
| PHY | 0xF000 | 4KB |
| Factory | 0x10000 | 4MB |
| LittleFS | 0x410000 | 10MB |
| Coredump | 0xE10000 | 1MB |
| Scratch | 0xF10000 | 960KB |

## Build

```bash
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

## Boot Sequence

1. Mount LittleFS
2. **Start Camera (OV3660 MJPEG)** — runs early to allocate DMA descriptor buffers before DRAM gets fragmented
3. **Start Web Dashboard (port 443 HTTPS + port 80 HTTP)** — **BEFORE WiFi** to maximize available DRAM; retries with smaller config on failure; self-signed certs auto-generated at build
4. Start WiFi (AP on 192.168.4.1 + STA) — SSID `VIPER-S3`, WPA2-PSK (pmf_cfg.required=false)
5. Start IR (GPIO2=TX, GPIO4=RX) — **graceful fallback** on failure
6. Start NFC (PN532 UART: GPIO18=TX, GPIO5=RX) — **graceful fallback** on failure
7. Initialize Crack Engine + Protocol Attacks — **graceful fallback** on failure
8. Start BLE (NimBLE) — **graceful skip** when controller disabled (`CONFIG_BT_CONTROLLER_DISABLED=y`)
9. Start USB (TinyUSB HID + CDC) — **graceful fallback** on failure
10. Start AI Engine — **graceful fallback** on failure
11. Launch Attack Orchestrator; retry dashboard init if failed at step 3

**All steps 3+ use graceful fallback. Dashboard: HTTPS on port 443 + HTTP fallback, API key auth (default: "viper"), 512-byte chunked transfer, watchdog auto-restart, `/ping` health endpoint, fallback error page.**

## Access

- **Dashboard**: https://192.168.4.1 (HTTPS, self-signed cert) or http://192.168.4.1 (HTTP fallback)
- **Auth**: API key — default `"viper"`, change via `POST /api/auth`
- **WiFi AP**: SSID `VIPER-S3`, WPA2-PSK password `00000000` (⚠️ untested — may need open AP)
- **BLE**: Controller disabled by default (re-enable in `sdkconfig.defaults`)
- **USB**: Ducky Script payloads via CDC serial

## Build Environment

- **ESP-IDF**: v5.3 (`~/esp/esp-idf`)
- **Target**: `esp32s3`
- **Python**: 3.13.7 (IDF v5.3 environment)

### Build

HTTPS certs are auto-generated at build time by `components/web_dashboard/gen_certs.sh`. Requires `openssl`.

```bash
. ~/esp/esp-idf/export.sh
idf.py build
```

### Flash Once (combined binary)

```bash
. ~/esp/esp-idf/export.sh
esptool.py --chip esp32s3 -b 115200 write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 build/viper_s3_combined.bin --verify
```

> **Note**: Baud rate 115200 is the most reliable. Higher rates (460800) may fail.

### Flash & Monitor (via idf.py)

```bash
. ~/esp/esp-idf/export.sh
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

## ESP-IDF v5.3 Migration Fixes

The codebase was originally written for ESP-IDF v4.x/early v5.x. These fixes were applied for v5.3 compatibility:

### USB / TinyUSB (`components/usb_engine/usb_engine.c`)
| Fix | Details |
|-----|---------|
| MAC API | `esp_efuse_mac_get_default()` → `esp_read_mac(mac, ESP_MAC_WIFI_STA)` |
| Missing include | Added `#include "esp_mac.h"` (decoupled from `esp_system.h` in v5.3) |
| CDC descriptor | `TUD_CDC_DESCRIPTOR` now requires 7th argument `64` (buffer size) |
| Descriptor conflict | Removed `tud_descriptor_device_cb`, `tud_descriptor_configuration_cb`, `tud_descriptor_string_cb` from usb_engine.c — pass descriptors via `tinyusb_config_t` instead (built-in `descriptors_control.c` provides the callbacks) |

### Web Dashboard (`components/web_dashboard/web_dashboard.c`)
| Fix | Details |
|-----|---------|
| Query string API | `httpd_req_get_url_query_str()` return type changed from `const char*` to `esp_err_t` — replaced `?: ""` with proper buffer-based call |
| Forward declarations | Added forward declarations for all 16 REST API handlers before the `uri` array |
| HTML escaping | Escaped double quotes in HTML string literal at line 515 (`&quot;Scan Now&quot;`) |
| JS semicolon | Added missing `;` after forEach in `loadConfig` (line 740) — C string concatenation produced `})h+=''` with no semicolon, causing `SyntaxError: Unexpected identifier 'h'` |
| Server stack size | Increased `cfg.stack_size` from 2048→4096 (line 1241) — 2KB caused `httpd_resp_send` to hang on ~27KB dashboard HTML; browser showed infinite loading spinner |

### IR Engine (`components/ir_engine/ir_engine.c`)
| Fix | Details |
|-----|---------|
| RMT API | `rmt_rx_stop()` → `rmt_disable()` (removed in v5.3 RMT) |
| RMT argument order | `rmt_receive()` argument order changed — correct order: `(chan, buf, buf_size, wait_ms)` |
| Sequence point | Fixed undefined behavior in `rx_done_cb` loop (`pulses[++i]` on same `i` as index) |

### NFC Engine (`components/nfc_engine/include/nfc_engine.h`)
| Fix | Details |
|-----|---------|
| Buffer overflow | Increased `NFC_TAG_TYPE_MAX` from 16 → 32 to prevent `snprintf` truncation |

### AI Engine (`components/ai_engine/ai_engine.c`)
| Fix | Details |
|-----|---------|
| Missing includes | Added `freertos/FreeRTOS.h`, `freertos/task.h`, `ble_engine.h`, `wifi_engine.h` |

### Attack Orchestrator (`components/attack_orchestrator/attack_orchestrator.c`)
| Fix | Details |
|-----|---------|
| Broadcast API | All 7 `web_dashboard_broadcast()` calls rebuilt with pre-formatted `snprintf` buffers (function takes `(event_type, json_data)` only, no printf-style args) |
| Format specifiers | `bool` → `%d`, `uint32_t` → `%lu` |

### Main (`main/main.c`)
| Fix | Details |
|-----|---------|
| Camera init | `camera_engine_init()` now passes `&CAMERA_CONFIG_DEFAULT` (signature changed) |

### sdkconfig / sdkconfig.defaults
| Change | Reason |
|--------|--------|
| `CONFIG_HTTPD_WS_SUPPORT=y` | WebSocket API compile failure |
| `CONFIG_TINYUSB_HID_COUNT=1` | HID keyboard code was compiled out at 0 |
| `CONFIG_TINYUSB_MSC_ENABLED=` (disabled) | No MSC callbacks implemented, caused linker errors |
| `CONFIG_BT_CONTROLLER_DISABLED=y` | Saves ~30KB DRAM; NimBLE host skipped gracefully at runtime |
| `CONFIG_CAMERA_PSRAM_DMA=y` | Camera DMA descriptors use PSRAM instead of internal DRAM |

## License

For authorized security research only.
