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
python3 -m esptool --chip esp32s3 -b 460800 write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 build/viper_s3_combined.bin
```

### Method 2: Separate Binaries

```bash
python3 -m esptool --chip esp32s3 -b 460800 write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 build/bootloader/bootloader.bin \
  0x8000 build/partition_table/partition-table.bin \
  0x10000 build/viper_s3.bin
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
3. **Connect to WiFi AP** — the device creates a network named `VIPER-S3-XXXX`.
4. **Open dashboard** — navigate to `http://192.168.4.1` in your browser.
5. **Optional**: Connect the device to your local network via the dashboard WiFi settings.

---

## Web Dashboard

The dashboard is the main interface. Access it at:

- **AP mode**: `http://192.168.4.1`
- **STA mode**: device IP on your network

### Pages/Tabs

- **WiFi** — Scan, deauth, evil twin, beacon flood, PMKID capture, karma, captive portal, DNS spoof, HTTP sniffer
- **BLE** — Scan, spam (7 types), proprietary scans (Apple/Google/Samsung/Tile/Microsoft), MITM proxy
- **USB** — Ducky Script payloads, payload library management
- **NFC** — Tag detection, read/write MIFARE/Ultralight/DESFire, NDEF parsing, tag emulation, clone
- **IR** — Capture, learn, replay IR signals (NEC/Sony/Samsung)
- **Camera** — MJPEG live stream, motion detection, QR code scanning
- **Responder** — LLMNR, NBT-NS, mDNS poisoning, SMB honey trap with NTLM capture
- **Crack** — On-device NTLM (~4M/s), MD5 (~5M/s), SHA1 (~3M/s), PMKID cracking
- **Protocol Attacks** — WPA3→WPA2 downgrade, SSL strip, canary tokens
- **AI/ML** — Decision tree, KNN classifier, digital twin generation
- **Orchestrator** — Attack chains, triggers, scheduler, health monitor

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
