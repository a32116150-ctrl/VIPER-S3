# VIPER-S3 User Manual

## What is VIPER-S3?

VIPER-S3 (**V**isual **I**ntelligence **P**entesting & **E**xploitation **R**outer — **S3**) is a multi-function ESP32-S3 security testing tool. It combines WiFi, BLE, USB HID/CDC, camera, NFC, IR, and AI into a single portable device with a web dashboard.

---

## Hardware Requirements

| Component | Specification |
|-----------|---------------|
| **SoC** | ESP32-S3 WROOM N16R8 |
| **Flash** | 16MB |
| **PSRAM** | 8MB |
| **Camera** | OV3660 (optional) |
| **NFC** | PN532 UART module (optional) |
| **IR** | IR LED + TSOP receiver (optional) |
| **USB** | Micro-USB / USB-C for flashing and HID/CDC |

---

## Flashing the Device

### Method 1: Single Command (Easiest)

Flash everything at once from the project root:

```bash
python3 -m esptool --chip esp32s3 -b 115200 write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 build/viper_s3_combined.bin --verify
```

> **Note**: Baud rate 115200 is the most reliable. Higher rates (460800) may fail on some USB-serial adapters. The `--verify` flag confirms all bytes were written correctly.

### Method 2: Separate Binaries

```bash
python3 -m esptool --chip esp32s3 -b 115200 write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 build/bootloader/bootloader.bin \
  0x8000 build/partition_table/partition-table.bin \
  0x10000 build/viper_s3.bin --verify
```

### Flash Memory Layout

| Address | Region | Size | Contents |
|---------|--------|------|----------|
| `0x00000` | Bootloader | 32KB | First-stage bootloader |
| `0x08000` | Partition Table | 3KB | Partition layout |
| `0x09000` | NVS | 24KB | WiFi config, calibration |
| `0x0F000` | PHY | 4KB | RF calibration data |
| `0x10000` | Factory (App) | 4MB | VIPER-S3 firmware |
| `0x410000` | LittleFS | 10MB | Wordlists, payloads, captures, configs |
| `0xE10000` | Coredump | 1MB | Crash dump storage |
| `0xF10000` | Scratch | 960KB | Scratch data |

### Build from Source

```bash
# Set up environment (do once per terminal)
. ~/esp/esp-idf/export.sh

# Build
idf.py build

# Flash + monitor
idf.py -p /dev/ttyACM0 flash monitor
```

Replace `/dev/ttyACM0` with your port (`/dev/cu.usbmodem*` on macOS).

---

## First-Time Setup

1. **Flash** the device using one of the methods above.
2. **Power cycle** — plug the device into USB.
3. **Connect to WiFi AP** — the device creates a network named `VIPER-S3`. Password: `00000000` (⚠️ WPA2 auth currently broken — AP is open/temporary no-password).
4. **Open dashboard** — navigate to `http://192.168.4.1` in your browser.
5. **Optional**: Connect the device to your local network via the dashboard WiFi settings.

---

## Web Dashboard

The dashboard is the main interface. Access it at:

- **AP mode**: `http://192.168.4.1`
- **STA mode**: device IP on your network

### Pages/Tabs (Frontend Implemented)

| Tab | Features | Status |
|-----|----------|--------|
| **Overview** | Status cards (heap, WiFi mode, clients, uptime), activity log | ✅ |
| **WiFi** | Scan APs | ✅ |
| **Attacks** | Evil twin, deauth, stop all | ✅ |
| **Captures** | Credentials, PMKID hashes, wipe | ✅ |
| **Camera** | MJPEG stream placeholder | ⚠️ Camera not active (DRAM) |
| **Logs** | WebSocket system log viewer | ✅ |
| **BLE** | Proprietary scan, MITM proxy | ✅ |
| **Config** | View device config | ✅ |
| **Responder** | LLMNR/NBT-NS/mDNS poisoner + SMB honeypot start/stop | ✅ |
| **Crack** | Hash cracker (NTLM/MD5/SHA1/SHA256) with type selector and engine stats | ✅ |
| **Protocol** | WPA3→WPA2 downgrade AP, canary tokens (create/list), behavioral analysis | ✅ |

### Backend APIs Only (No Frontend Tab Yet)
USB (Ducky Script), NFC, IR, AI/ML, Orchestrator — backend REST endpoints exist but no frontend UI built yet.

---

## USB Modes

When plugged into a computer via USB, the device appears as:

1. **HID Keyboard** — Can inject keystrokes (Ducky Script compatible)
2. **CDC Serial** — Serial console for text communication

### Ducky Script

Upload `.txt` Ducky Script payloads via the dashboard USB tab or flash them to LittleFS.

### OS Fingerprinting

The device automatically detects the connected OS (Windows/macOS/Linux) based on USB enumeration timing.

---

## BLE C2 Channel

Connect via BLE GATT to the UART C2 service for out-of-band command and control.

---

## Storage (LittleFS)

The 10MB LittleFS partition stores:

- `/wordlists/` — Password dictionaries for cracking
- `/payloads/` — Ducky Script payloads
- `/captures/` — PMKID, handshake, NTLM hash captures
- `/config/` — Device configuration

Upload files via the dashboard or mount LittleFS over USB when MSC mode is enabled.

---

## GPIO Pinout

| Function | GPIO | Notes |
|----------|------|-------|
| IR TX | GPIO2 | IR LED output |
| IR RX | GPIO4 | TSOP receiver input |
| NFC TX | GPIO18 | PN532 UART TX |
| NFC RX | GPIO5 | PN532 UART RX |
| Camera | various | OV3660 via ESP32-S3 camera interface |

---

## Troubleshooting

### Device won't flash
- Hold BOOT button while connecting USB, then release after flash starts
- Check you're using the correct port: `ls /dev/cu.usbmodem*` (macOS) or `ls /dev/ttyACM*` (Linux)
- Try lower baud rate: `-b 115200`

### Dashboard not loading
- Check you're connected to the device's AP or same network
- Verify the IP: `192.168.4.1` in AP mode
- Ping the device to confirm connectivity
- If the device is reachable (AP works, ping succeeds) but the page doesn't load, the HTTP server may not have started due to internal DRAM fragmentation. Check the serial monitor for: `E (1947) DASHBOARD: Failed to start HTTP server`
- **Fix**: Boot order adjusted — dashboard starts before camera. If still fails after reflash, check serial logs.

### Dashboard tabs not switching
- If clicking nav tabs stays on Overview page, the JavaScript may have a syntax error
- **Fix**: Switch to `onclick` attributes instead of `addEventListener` — much more reliable
- Check the JS Status card on the Overview page — if it shows "Running (N)", JavaScript is executing
- On MacBook: open browser console (Cmd+Option+J) and look for `Switch panel: xxx` log messages

### Dashboard loads but JS shows "Running (0)" (never increments)
- The JS heartbeat counter stays at 0, meaning `setInterval` or `jsCount++` is broken by a syntax error earlier in the script
- A missing `;` after `forEach` or other callbacks in C string concatenation can cause `SyntaxError: Unexpected identifier`
- **Fix**: Re-extract the JS from the C source and validate with `node --check`. Look for `'})` followed immediately by an identifier (e.g., `'})h`) — these need a `;` between the `)` and the identifier

### MacBook can't open dashboard (phone works)
- Check the assigned IP in MacBook WiFi settings — should be `192.168.4.x`
- If it shows a `169.254.x.x` IP, the DHCP server didn't respond
- Try: turn WiFi off/on, or manually set IP to `192.168.4.100`
- If all else fails, connect via phone and use the phone as a hotspot for the MacBook

### USB not detected
- Try a different USB cable (some cables are power-only)
- Check `dmesg` on Linux/macOS for USB enumeration messages
- The device should appear as both a keyboard and a serial port

### BLE not scanning
- Ensure BLE is enabled in the dashboard
- Move closer to target devices
- Some proprietary scans (Apple Find My, Tile) require BLE 5.0 extended advertising

### Camera not working
- Verify OV3660 is connected properly
- Check camera ribbon cable is fully inserted
- Reset the camera engine via the dashboard

### Crashes / Panics
- Core dumps are saved to the Coredump partition
- Retrieve with: `espcoredump.py -p /dev/ttyACM0 info_corefile`
- Review serial monitor output for panic details

---

## License

For authorized security research and educational purposes only.
