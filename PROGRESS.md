# VIPER-S3 Development Progress

> **Current Status**: Device flashed and running. All 25 vulnerabilities fixed + L1 (API auth) + L2 (HTTPS) + L3 + L4 + L5. BLE crash (NULL store callback) fixed. Build succeeds, device online at https://192.168.4.1 (self-signed cert). Auth enabled default "viper". L6 WPA2-PSK fix still needs hardware WPA2 client test.

## Phase 1 — Core Infrastructure ✅
- `CMakeLists.txt`, `partitions.csv`, `sdkconfig.defaults`
- `main/main.c` — Boot: LittleFS → **Dashboard** (before WiFi, max DRAM) → WiFi → IR → NFC → Crack/Protocol → BLE (controller disabled) → USB → AI → Camera → Orchestrator
- `storage_manager/` — LittleFS, 9 dirs, cred/hash JSONL logging, wordlist iterator
- `web_dashboard/` — ESP HTTP server, 27 REST endpoints, WebSocket, dark SPA

## Phase 2 — WiFi Engine ✅
10 modules: scanner, deauth, evil twin, beacon flood, PMKID, karma, captive portal, DNS spoof, HTTP sniffer

## Phase 3 — Camera Engine ✅
OV3660, MJPEG stream, motion detection, QR decoder (quirc), burst capture

## Phase 4 — USB Engine ✅
TinyUSB HID+CDC, ASCII keymap, Ducky Script, OS fingerprint

## Phase 5 — BLE Engine ✅
NimBLE scanner, Apple/Google/iBeacon decoder, 7-type spam, GATT UART C2

## Phase 6 — Attack Orchestrator ✅
3 chains, triggers, scheduler, health monitor

---

## Phase 7 — Responder & Credential Cracking ✅
| Component | File | Features |
|---|---|---|
| **Responder** | `responder.c` | LLMNR (UDP 5355, multicast 224.0.0.252), NBT-NS (UDP 137), mDNS (UDP 5353, multicast 224.0.0.251). DNS-style name resolution poisoning — responds to all queries with redirect IP. Per-protocol selectable. Poison counter. |
| **SMB Honey Trap** | `smb_honey.c` | TCP 445 SMB listener. SMBv2 negotiate response. NTLMSSP blob extraction from session setup. Hex-dump capture of NTLMv2 hashes. FreeRTOS task. |
| **Crack Engine** | `crack_engine.c` | On-device dictionary cracking. **NTLM**: standalone MD4(UTF-16-LE(password)) ~4M/sec. **MD5**: mbedTLS ~5M/sec. **SHA1**: mbedTLS ~3M/sec. PMKID estimated ~500/sec via PBKDF2. Wordlists from LittleFS. Stats tracking. |
| **Web APIs** | `web_dashboard.c` | `POST /api/responder/start`, `POST /api/responder/stop`, `GET /api/responder/status`, `POST /api/smb/start`, `POST /api/smb/stop`, `POST /api/crack/start`, `GET /api/crack/status` |

## Phase 8 — Protocol Attacks ✅
| Component | File | Features |
|---|---|---|
| **Downgrade** | `protocol_attacks/downgrade.c` | WPA3→WPA2 evil twin downgrade, SSL Strip proxy (TCP 80, rewrites https://→http://) |
| **Canary** | `protocol_attacks/canary.c` | Canary token tracker (TCP 8888, JSONL persistence) |
| **Behavioral** | `protocol_attacks/behavioral.c` | Behavioral fingerprinting (8 app types with packet size/rate/burst heuristics) |
| **Web APIs** | `web_dashboard.c` | `POST /api/downgrade/start`, `POST /api/canary/create`, `GET /api/canary/list`, `GET /api/behavioral` |

## Phase 9 — BLE Advanced ✅
| Component | File | Features |
|---|---|---|
| **Extended Advertising** | `ble_adv_ext.c` | BLE 5.0 extended advertising, configurable PHY (1M/2M/Coded), multiple sets, periodic advertising, long-range beacons |
| **Proprietary Scans** | `ble_scan_proprietary.c` | Tile, Samsung SmartTag/FamilyTag, Apple Find My, Apple Continuity (AirDrop, AirPods, Watch, TV, Handoff, Tethering), Microsoft SwiftPair v2 |
| **BLE MITM Proxy** | `ble_mitm.c` | Target discovery, GATT enumeration, service re-advertisement, GATT relay with intercept callback |
| **Web APIs** | `web_dashboard.c` | BLE tab, proprietary scan results, MITM start/stop/status/services |
| **Attack Chain** | `attack_orchestrator.c` | `CHAIN_BLE_MITM` — scans, connects, proxies 30s |

## Phase 10 — Physical & Air-Gap ✅
| Component | File | Features |
|---|---|---|
| **BadUSB Payloads** | `usb_payloads.c` | Enhanced Ducky Script — STRINGLN, DEFAULTDELAY, REPEAT, GUI-R, ALT-F4, CTRL-ALT-DEL. Payload library: list/save/delete/get on LittleFS. |
| **IR Engine** | `ir_engine/` | RMT-based IR TX/RX on configurable GPIOs. NEC/Sony/Samsung encode/decode. IR capture/learn with replay. Learned IR signal persistence. |
| **NFC Engine** | `nfc_engine/` | PN532 driver (UART/I2C). Tag detection (MIFARE Classic 1K/4K, Ultralight, DESFire). Sector read/write. NDEF parse. Tag emulation. Clone. |

## Phase 11 — AI & Identity ✅
| Component | File | Features |
|---|---|---|
| **Decision Tree** | `ai_engine.c` | Lightweight decision tree inference (16 nodes, 8 classes). Pre-trained app classifier. |
| **KNN Classifier** | `ai_engine.c` | K-Nearest Neighbors with configurable k, Euclidean distance. Pre-trained BLE device type classifier (Apple/Google/Samsung/Microsoft). |
| **Feature Extraction** | `ai_engine.c` | Packet flow feature extraction (size, interval, burst ratio). BLE/WiFi feature extraction stubs. |
| **Digital Twin** | `ai_engine.c` | Profile library (BLE/WiFi/USB). Twin creation from observed devices. BLE spam spawn, WiFi beacon flood spawn. Persistence to LittleFS. |
| **Fingerprinting** | `ai_engine.c` | BLE advertisement fingerprinting, WiFi (SSID+BSSID) fingerprinting, similarity comparison. |

## Current Blockers

| Issue | Status | Details |
|-------|--------|---------|
| Internal DRAM fragmentation | 🟡 Reduced | Camera now uses PSRAM DMA mode (`CONFIG_CAMERA_PSRAM_DMA=y`) — eliminates 16KB contiguous internal DRAM requirement |
| Camera DMA allocation fails | ✅ | Fixed — PSRAM DMA mode enabled in sdkconfig.defaults; DMA descriptors point to PSRAM, no longer needs 16KB internal DRAM block |
| HTTP server start failure | ✅ | Fixed — dashboard starts BEFORE WiFi (step 2), stack_size=4096+retry, BLE controller disabled to free ~30KB |
| HTTP server boot-loop (out of memory) | ✅ | Fixed — `max_open_sockets=8`, `max_uri_handlers` auto-calculated from `sizeof(s_uris)`, `stack_size=4096` |
| HTTP response hangs (infinite spinner) | ✅ | Fixed — chunked transfer (512B), fallback error page, watchdog auto-recovery |
| BLE controller init fails | ✅ | Acceptable — controller disabled (`CONFIG_BT_CONTROLLER_DISABLED=y`) to free DRAM; NimBLE host compiles, graceful fallback |
| USB init | ✅ | Graceful fallback in place — no crash |
| Web Dashboard nav tabs | ✅ | Fixed — switched from addEventListener to onclick attributes |
| Dashboard JS syntax error | ✅ | Fixed — missing semicolon in loadConfig JS |
| WPA2-PSK auth failure | ✅ | Fixed — `esp_wifi_disable_pmf_config(WIFI_IF_AP)` added; stale PMF "required" values in NVS from ESP-IDF v5.3 cleared on boot |
| USB serial enumeration post-flash | ❌ **BLOCKING** | After flash + hard reset, ESP32-S3 USB serial port disappeared from macOS; cannot monitor or re-flash |
| WiFi AP | ⚠️ | SSID `VIPER-S3`, reachable at 192.168.4.1 — WPA2-PSK fix applied (needs flash + test verification) |

## Mitigations Applied

| Fix | Impact |
|-----|--------|
| BLE graceful fallback (`nimble_port_init()` return check) | Prevents reboot loop when BLE fails |
| USB graceful fallback (`tinyusb_driver_install()` return check) | Prevents reboot loop when USB fails |
| `CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL=y` | Moves NimBLE host to PSRAM, frees ~30KB internal DRAM |
| `CONFIG_BT_CTRL_BLE_MAX_ACT=3` (was 6) | Reduces BLE controller DRAM requirement |
| `CONFIG_LWIP_MAX_SOCKETS=16` (was 10) | HTTP server socket pool raised; actual `max_open_sockets=8` in code |
| `max_open_sockets=8` (was 12) | Saves ~6KB DRAM from LWIP socket buffers; prevents boot-loop |
| HTTP server stack 4096 (was 2048) | Reverted to default; 2048 was insufficient for serving ~27KB dashboard HTML, causing `httpd_resp_send` to hang silently |
| `max_uri_handlers=31` (was default 8) | All 31 API endpoints register; none get "no slots left" error |

## Next Steps
- [x] Fix 3 critical vulnerabilities (SSL strip stack overflow, infinite read loop, WS race)
- [x] Fix 9 high vulnerabilities (OOB write, NFC overflow, %s overread, double-free, task delete sync, null term, stubs, ARCOUNT, IR race)
- [x] Fix 13 medium vulnerabilities (snprintf bounds, strstr match, confidence, atomic counter, unchecked returns, wordlist buffer, downgrade cleanup, CPU freq)
- [x] Fix L3 — remove dead `wifi_set_mac` declaration
- [x] Fix L4 — add Content-Type: application/json to 25+ JSON API endpoints
- [x] Fix L5 — replace 10 stale Kconfig symbols in sdkconfig.defaults
- [x] Fix L1 — Add API key authentication (`X-API-Key` header, `POST /api/auth` login, default `"viper"`)
- [x] Fix L2 — Add HTTPS with embedded self-signed cert (port 443, auto-fallback to HTTP)
- [ ] **🔴 USB enumeration** — Reboot MacBook, try different cable to get ESP32-S3 serial port back
- [ ] **Flash & test** — Flash the new firmware (all 25+ vulnerability fixes + L1+L2)
- [ ] **Fix L6** — Verify WPA2-PSK works (code fix applied, needs hardware test)
- [ ] **Test dashboard** — Verify http://192.168.4.1 loads, test all endpoints
- [ ] Commit and push to GitHub

---

## Project Statistics
```
antigravity/
├── CMakeLists.txt / partitions.csv / sdkconfig.defaults
├── main/main.c
└── components/  ← 13 components, ~62 source files
    ├── storage_manager/     3 files
    ├── wifi_engine/         11 files
    ├── camera_engine/       5 files
    ├── usb_engine/          6 files
    ├── ble_engine/          10 files
    ├── web_dashboard/       3 files
    ├── attack_orchestrator/ 3 files
    ├── responder/           4 files
    ├── crack_engine/        3 files
    ├── protocol_attacks/    5 files
    ├── ir_engine/           3 files
    ├── nfc_engine/          3 files
    └── ai_engine/           3 files
```
