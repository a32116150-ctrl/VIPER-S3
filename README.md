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
| **Dashboard** | Dark SPA with 27 REST endpoints, WebSocket live updates |

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
2. Start WiFi (AP on 192.168.4.1 + STA)
3. Start BLE (NimBLE scanner + UART C2)
4. Start USB (TinyUSB HID)
5. Start Camera (OV3660 MJPEG)
6. Start Web Dashboard (port 80)
7. Initialize Responder + Crack Engine
8. Start Protocol Attacks
9. Start IR (GPIO2=TX, GPIO4=RX)
10. Start NFC (PN532 UART: GPIO18=TX, GPIO5=RX)
11. Start AI Engine
12. Launch Attack Orchestrator

## Access

- **Dashboard**: http://192.168.4.1 (AP mode) or device IP
- **BLE UART C2**: Connect via GATT
- **USB**: Ducky Script payloads via CDC

## License

For authorized security research only.
