# AQUAPULSE — Water Level Monitor

ESP32 firmware for a wireless water-tank level monitoring system built on ESP-NOW.

## Hardware

| Board | Role |
|---|---|
| ESP32 Dev Module (COM19) | **Hub** — TFT touch display, WiFi AP, OTA |
| Seeed XIAO ESP32-C3 (COM18) | **Node** — DYP-A02YYTW ultrasonic sensor |

## Features

- 📡 **ESP-NOW** wireless (no WiFi router needed)
- 💾 **NVS pairing** — pair once, reconnects automatically on reboot
- 📺 **320×240 TFT UI** — grid view + animated tank view
- ⚙️ **Settings** — tank calibration, alert threshold
- 🔄 **ArduinoOTA** — flash Hub wirelessly after first upload
- 🔊 **Sensor filtering** — median-of-5 + EMA + deadband

## Build

```bash
# Hub (ESP32)
pio run -e esp32dev -t upload --upload-port COM19

# Node (XIAO C3)
pio run -e seeed_xiao_esp32c3 -t upload --upload-port COM18
```

## OTA (Hub only — after first cable flash)

Open PlatformIO and change `upload_protocol = espota` + set `upload_port` to the Hub's IP address shown on the AQUAPULSE screen.
