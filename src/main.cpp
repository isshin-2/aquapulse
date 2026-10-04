#include <Arduino.h>
#include <WiFi.h>
#include <ArduinoOTA.h>

#define PAIRING_CHANNEL 1

typedef struct __attribute__((packed)) {
    uint8_t deviceId;
    int distance;
    unsigned long timestamp;
} SensorData;

// Shared secret for pairing authentication (must match on hub and node)
// XOR-HMAC: auth = XOR of all bytes in packet ^ key bytes (cycling)
static const uint8_t PAIR_KEY[8] = {0xA5, 0x2B, 0x7C, 0x4D, 0x71, 0x3A, 0xF2, 0x9B};
// Note: resolved at compile time to:
#define PAIR_KEY_0 0xA5
#define PAIR_KEY_1 0x2B
#define PAIR_KEY_2 0x7C
#define PAIR_KEY_3 0x4D
#define PAIR_KEY_4 0x71
#define PAIR_KEY_5 0x3A
#define PAIR_KEY_6 0xF2
#define PAIR_KEY_7 0x9B

// Compute 4-byte auth tag: XOR of packet bytes with cycling key
static uint32_t pairAuth(const uint8_t *data, int len) {
  static const uint8_t K[8] = {PAIR_KEY_0,PAIR_KEY_1,PAIR_KEY_2,PAIR_KEY_3,
                                PAIR_KEY_4,PAIR_KEY_5,PAIR_KEY_6,PAIR_KEY_7};
  uint32_t acc = 0x55AA55AA;
  for (int i = 0; i < len; i++) acc = ((acc << 5) | (acc >> 27)) ^ (data[i] * K[i & 7]);
  return acc;
}

typedef struct __attribute__((packed)) {
    char magic[8];
    uint8_t hubMAC[6];
    uint8_t channel;
    uint16_t pairingCode;
    uint32_t auth;        // pairAuth of all above fields
} PairingBeacon;

typedef struct __attribute__((packed)) {
    char magic[8];
    uint8_t sensorMAC[6];
    uint8_t deviceId;
    uint16_t pairingCode;
    uint32_t auth;        // pairAuth of all above fields
} PairingRequest;

typedef struct __attribute__((packed)) {
    char magic[8];
    uint8_t hubMAC[6];
    uint8_t deviceId;
    bool accepted;
    uint32_t auth;        // pairAuth of all above fields
} PairingConfirm;

#ifdef NODE_DYP_SENSOR

#include <esp_now.h>
#include <esp_wifi.h>
#include <HardwareSerial.h>
#include <Preferences.h>

// Dynamic pin assignments per node:
// Node 2 (MAC 1C:DB:D4:F0:5C:B4): D3 TX (Xiao TX -> Sensor RX), D4 RX (Xiao RX <- Sensor TX)
// Node 1 (MAC E8:F6:0A:18:E7:70): D1 TX (Xiao TX -> Sensor RX), D2 RX (Xiao RX <- Sensor TX)
uint8_t dypTxPin = D1;
uint8_t dypRxPin = D2;
HardwareSerial dypSerial(1);

uint8_t hubMAC[6];
bool paired = false;
uint8_t currentChan = 1;
uint16_t pairingCode = 0;
uint8_t myDeviceId = 1; 
uint8_t myMAC[6];

unsigned long lastSend = 0;
unsigned char dypData[4] = {};
int sendFailures = 0;          // consecutive send failures
Preferences nodePrefs;

void nodeClearNVS();
void nodeLoadNVS() {
  nodePrefs.begin("node", true); // read-only
  paired = nodePrefs.getBool("paired", false);
  // Removed forced wipe
  if (paired) {
    nodePrefs.getBytes("hubMAC", hubMAC, 6);
    pairingCode = nodePrefs.getUShort("code", 0);
    currentChan = nodePrefs.getUChar("chan", 1);
  }
  nodePrefs.end();
}

void nodeSaveNVS() {
  nodePrefs.begin("node", false);
  nodePrefs.putBool("paired", paired);
  nodePrefs.putBytes("hubMAC", hubMAC, 6);
  nodePrefs.putUShort("code", pairingCode);
  nodePrefs.putUChar("chan", currentChan);
  nodePrefs.end();
}

void nodeClearNVS() {
  nodePrefs.begin("node", false);
  nodePrefs.clear();
  nodePrefs.end();
  paired = false;
  sendFailures = 0;
  memset(hubMAC, 0, 6);
}

void printMAC(const uint8_t *mac) {
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  Serial.print(buf);
}

extern int16_t lastSentMm;
void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  bool ok = (status == ESP_NOW_SEND_SUCCESS);
  Serial.print("[NODE] Send Status: ");
  Serial.println(ok ? "Success" : "Fail");
  if (ok) {
    sendFailures = 0;
  } else {
    lastSentMm = -1; // Force retry on next cycle
  }
}

// Track pending hub info when re-pairing (don't overwrite live hub until confirmed)
uint8_t pendingHubMAC[6] = {};
uint16_t pendingCode = 0;
bool waitingForConfirm = false;
unsigned long lastBeaconRecvTime = 0;

void sendPairingRequest(const uint8_t *targetMAC, uint16_t code) {
  // Register hub as peer if needed
  if (!esp_now_is_peer_exist(targetMAC)) {
    esp_now_peer_info_t p = {};
    memcpy(p.peer_addr, targetMAC, 6);
    p.channel = PAIRING_CHANNEL;
    p.encrypt = false;
    esp_now_add_peer(&p);
  }
  PairingRequest req = {};
  strncpy(req.magic, "WLMSREQ", 8);
  memcpy(req.sensorMAC, myMAC, 6);
  req.deviceId = myDeviceId;
  req.pairingCode = code;
  req.auth = pairAuth((uint8_t*)&req, sizeof(req) - sizeof(req.auth));
  esp_now_send(targetMAC, (uint8_t *)&req, sizeof(PairingRequest));
  Serial.println("[NODE] Pairing request sent");
}

void OnDataRecv(const uint8_t *mac, const uint8_t *incomingData, int len) {
  // ── Hub Beacon (broadcast) ──
  if (len == sizeof(PairingBeacon)) {
    PairingBeacon *b = (PairingBeacon *)incomingData;
    if (strncmp(b->magic, "WLMSHUB", 8) != 0) return;
    Serial.println("[NODE] RX: Received WLMSHUB (PairingBeacon)");
    // Validate auth
    uint32_t expected = pairAuth((uint8_t*)b, sizeof(PairingBeacon) - sizeof(b->auth));
    if (b->auth != expected) {
      Serial.println("[NODE] Beacon auth FAIL - ignoring");
      return;
    }
    lastBeaconRecvTime = millis();
    // Lock onto hub channel from beacon
    uint8_t hubChan = b->channel > 0 && b->channel <= 13 ? b->channel : PAIRING_CHANNEL;
    if (currentChan != hubChan) {
      currentChan = hubChan;
      esp_wifi_set_channel(currentChan, WIFI_SECOND_CHAN_NONE);
      // Re-register broadcast peer on new channel
      uint8_t bcastMac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
      esp_now_del_peer(bcastMac);
      esp_now_peer_info_t bcast = {};
      memset(bcast.peer_addr, 0xFF, 6);
      bcast.channel = currentChan;
      bcast.encrypt = false;
      esp_now_add_peer(&bcast);
    }
    if (paired) {
      // Already paired - only respond if it's the SAME hub (allow re-pairing after hub restart)
      if (memcmp(b->hubMAC, hubMAC, 6) != 0) {
        Serial.println("[NODE] Beacon from different hub - ignoring (already paired)");
        return;
      }
      Serial.println("[NODE] Hub beacon from known hub - re-announcing");
    } else {
      Serial.println("[NODE] Hub beacon received - responding");
    }
    memcpy(pendingHubMAC, b->hubMAC, 6);
    pendingCode = b->pairingCode;
    waitingForConfirm = true;
    sendPairingRequest(b->hubMAC, b->pairingCode);
  }
  // ── Pairing Confirm ──
  else if (len == sizeof(PairingConfirm)) {
    PairingConfirm *conf = (PairingConfirm *)incomingData;
    if (strncmp(conf->magic, "WLMSCONF", 8) != 0) return;
    Serial.println("[NODE] RX: Received WLMSCONF (PairingConfirm)");
    // Validate auth
    uint32_t expected = pairAuth((uint8_t*)conf, sizeof(PairingConfirm) - sizeof(conf->auth));
    if (conf->auth != expected) {
      Serial.println("[NODE] Confirm auth FAIL - ignoring");
      return;
    }
    if (paired && conf->deviceId != myDeviceId) return; // Only check if already paired
    if (conf->accepted) {
      memcpy(hubMAC, conf->hubMAC, 6);
      paired = true;
      waitingForConfirm = false;
      myDeviceId = conf->deviceId;
      // Register hub peer for data sends
      if (!esp_now_is_peer_exist(hubMAC)) {
        esp_now_peer_info_t p = {};
        memcpy(p.peer_addr, hubMAC, 6);
        p.channel = currentChan;
        p.encrypt = false;
        esp_now_add_peer(&p);
      } else {
        // Update channel
        esp_now_peer_info_t p = {};
        memcpy(p.peer_addr, hubMAC, 6);
        esp_now_get_peer(hubMAC, &p);
        p.channel = currentChan;
        esp_now_mod_peer(&p);
      }
      nodeSaveNVS();
      Serial.println("[NODE] Paired! Saved to NVS.");
    } else {
      waitingForConfirm = false;
      Serial.println("[NODE] Pairing rejected.");
    }
  }
}

// ── Calibration / Filtering ─────────────────────────────────────────────────
#define MEDIAN_SAMPLES   5      // 5 pings per cycle
#define EMA_ALPHA_NUM    25     // EMA weight = 25/100 (responsive yet smooth)
#define EMA_ALPHA_DEN    100
#define DEADBAND_MM      10     // suppress transmit unless changed by >10mm
#define PLAUSIBLE_JUMP   100    // outlier threshold (mm) — catches multipath reflection dips
#define MAX_CONSECUTIVE_SPIKES 8 // accept step change only after 8 consecutive readings (~4s)
#define SENSOR_MIN_MM    30     // DYP-A02 min range (30 mm = 3 cm blind zone)
#define SENSOR_MAX_MM    4500   // DYP-A02 max range
#define HEARTBEAT_MS     2000   // Periodic heartbeat interval (ms)
#define ECHO_LOST_CYCLES 10     // ~5s grace period before declaring echo lost (prevents momentary dropout dips)

int16_t emaValue   = -1;
int16_t lastSentMm = -1;
int consecutiveSpikes = 0;

void initSensorPins() {
  // Node 2 (MAC 1C:DB:D4:F0:5C:B4): D3 TX, D4 RX
  // Node 1 (MAC E8:F6:0A:18:E7:70): D1 TX, D2 RX
  if (myMAC[0] == 0x1C && myMAC[1] == 0xDB) {
    dypTxPin = D3;
    dypRxPin = D4;
  } else {
    dypTxPin = D1;
    dypRxPin = D2;
  }
  dypSerial.end();
  delay(15);
  dypSerial.begin(9600, SERIAL_8N1, dypRxPin, dypTxPin);
  pinMode(dypRxPin, INPUT_PULLUP);
  Serial.printf("[NODE] Sensor UART initialized (MAC %02X:%02X): RX=%s, TX=%s @ 9600 8N1\n",
                myMAC[0], myMAC[1], dypRxPin == D4 ? "D4" : "D2", dypTxPin == D3 ? "D3" : "D1");
}

// Clean, robust reading of 1 sample from the DYP sensor via UART
bool readRaw(uint16_t &out) {
  // 1. Discard leading non-0xFF noise bytes from FIFO
  int stale = 0;
  while (dypSerial.available() > 0 && dypSerial.peek() != 0xFF) {
    dypSerial.read();
    stale++;
  }

  // 2. If no complete frame is ready, send trigger 0x55 and wait for response
  if (dypSerial.available() < 4) {
    dypSerial.write(0x55);
    unsigned long t0 = millis();
    while (dypSerial.available() < 4 && (millis() - t0 < 100)) {
      delay(2);
    }
  }

  int avail = dypSerial.available();

  // 3. Align again to 0xFF frame header
  while (dypSerial.available() > 0 && dypSerial.peek() != 0xFF) {
    dypSerial.read();
  }

  // 4. Validate complete 4-byte frame: [0xFF, Data_H, Data_L, Checksum]
  if (dypSerial.available() >= 4) {
    uint8_t h   = dypSerial.read(); // 0xFF
    uint8_t d_h = dypSerial.read();
    uint8_t d_l = dypSerial.read();
    uint8_t sum = dypSerial.read();
    if (((h + d_h + d_l) & 0xFF) == sum) {
      uint16_t v = ((uint16_t)d_h << 8) | d_l;
      if (v >= SENSOR_MIN_MM && v <= SENSOR_MAX_MM) {
        out = v;
        return true;
      }
    }
  }

  static unsigned long lastDiag = 0;
  if (millis() - lastDiag > 2500) {
    lastDiag = millis();
    Serial.printf("[NODE-DIAG] avail=%d stale=%d TX(%s)=%d RX(%s)=%d\n",
                  avail, stale,
                  dypTxPin == D3 ? "D3" : "D1", digitalRead(dypTxPin),
                  dypRxPin == D4 ? "D4" : "D2", digitalRead(dypRxPin));
  }
  return false;
}

void sortArr(uint16_t *a, int n) {
  for (int i = 1; i < n; i++) {
    uint16_t key = a[i]; int j = i - 1;
    while (j >= 0 && a[j] > key) { a[j + 1] = a[j]; j--; }
    a[j + 1] = key;
  }
}

// Take MEDIAN_SAMPLES readings, return median with track affinity and noise rejection
bool readMedian(uint16_t &out) {
  uint16_t buf[MEDIAN_SAMPLES];
  int valid = 0;
  for (int i = 0; i < MEDIAN_SAMPLES; i++) {
    uint16_t v;
    if (readRaw(v)) {
      buf[valid++] = v;
    }
    // 80ms interval ensures compliance with DYP-A02 datasheet (>70ms) allowing boost capacitor to recharge
    delay(80);
  }

  if (valid == 0) return false;

  // 1. Track affinity: if already tracking a surface (emaValue > 0),
  // prefer samples consistent with active level (rejects side-lobe reflections like 1314mm vs 1635mm)
  if (emaValue > 0) {
    uint32_t trackSum = 0;
    int trackCount = 0;
    for (int i = 0; i < valid; i++) {
      if (abs((int)buf[i] - (int)emaValue) <= 100) {
        trackSum += buf[i];
        trackCount++;
      }
    }
    if (trackCount >= 2) {
      out = (uint16_t)(trackSum / trackCount);
      return true;
    }
  }

  // 2. Multi-sample consistency: require at least 2 readings within 100mm
  // (Prevents single-spike false positives like 256mm from latching)
  if (valid >= 2) {
    sortArr(buf, valid);
    for (int j = 0; j < valid - 1; j++) {
      if (abs((int)buf[j+1] - (int)buf[j]) <= 100) {
        out = buf[valid / 2];
        return true;
      }
    }
  }

  // 3. If locked and single sample matches established track within 100mm, accept it
  if (valid == 1 && emaValue > 0 && abs((int)buf[0] - (int)emaValue) <= 100) {
    out = buf[0];
    return true;
  }

  return false;
}

void setup() {
  Serial.begin(115200);
  delay(500); // brief settle — do NOT block on Serial (no USB = infinite hang)

  Serial.println("\n--- AQUAPULSE Node ---");

  // Always start on PAIRING_CHANNEL so hub can find us immediately
  currentChan = PAIRING_CHANNEL;
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_channel(PAIRING_CHANNEL, WIFI_SECOND_CHAN_NONE);
  WiFi.macAddress(myMAC);
  Serial.print("[NODE] MAC: "); printMAC(myMAC); Serial.println();

  initSensorPins();

  if (esp_now_init() != ESP_OK) {
    Serial.println("[NODE] ESP-NOW init failed - restarting");
    delay(1000); ESP.restart(); return;
  }
  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);

  // Register broadcast peer on PAIRING_CHANNEL
  uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  if (!esp_now_is_peer_exist(broadcast)) {
    esp_now_peer_info_t bcast = {};
    memset(bcast.peer_addr, 0xFF, 6);
    bcast.channel = PAIRING_CHANNEL;
    bcast.encrypt = false;
    esp_now_add_peer(&bcast);
  }

  // Load saved pairing from NVS
  nodeLoadNVS();
  if (paired) {
    Serial.print("[NODE] Restored pairing - Hub: "); printMAC(hubMAC); Serial.println();
    // Register hub peer (we still listen for beacons to re-sync if needed)
    if (!esp_now_is_peer_exist(hubMAC)) {
      esp_now_peer_info_t peerInfo = {};
      memcpy(peerInfo.peer_addr, hubMAC, 6);
      peerInfo.channel = PAIRING_CHANNEL;
      peerInfo.encrypt = false;
      esp_now_add_peer(&peerInfo);
    }
    currentChan = PAIRING_CHANNEL;
  } else {
    Serial.println("[NODE] No saved pairing - listening on ch1 for Hub beacon...");
  }
}

void loop() {
  // Channel sweep ONLY when not paired
  if (!paired) {
    static unsigned long lastShout = 0;
    if (millis() - lastShout > 500) {
      lastShout = millis();
      // Shout PairingRequest to broadcast address
      uint8_t bcastMac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
      PairingRequest req = {};
      strncpy(req.magic, "WLMSREQ", 8);
      memcpy(req.sensorMAC, myMAC, 6);
      req.deviceId = 0;
      req.pairingCode = 0;
      req.auth = pairAuth((uint8_t*)&req, sizeof(req) - sizeof(req.auth));
      esp_now_send(bcastMac, (uint8_t *)&req, sizeof(PairingRequest));
      Serial.println("[NODE] TX: Shouting WLMSREQ (PairingRequest) to Broadcast");
    }
  }
  
  if (paired) {
    uint16_t median;
    bool hasReading = readMedian(median);
    static int missingEchoCycles = 0;

    if (hasReading) {
      missingEchoCycles = 0;
      // Seed EMA on first reading
      if (emaValue < 0) {
        emaValue = (int16_t)median;
        consecutiveSpikes = 0;
        Serial.printf("[NODE] Initial surface locked: %d mm\n", emaValue);
      } else {
        // Plausibility check
        if (abs((int)median - (int)emaValue) > PLAUSIBLE_JUMP) {
          consecutiveSpikes++;
          Serial.printf("[NODE] Jump filtered: median=%d  EMA=%d [#%d/%d]\n",
                        median, emaValue, consecutiveSpikes, MAX_CONSECUTIVE_SPIKES);
          // If consecutive readings maintain the new level, accept it as real step change
          if (consecutiveSpikes >= MAX_CONSECUTIVE_SPIKES) {
            Serial.printf("[NODE] Step change confirmed -> new level: %d mm\n", median);
            emaValue = (int16_t)median;
            consecutiveSpikes = 0;
          }
        } else {
          consecutiveSpikes = 0;
          // Apply EMA: new = alpha*median + (1-alpha)*old
          emaValue = (EMA_ALPHA_NUM * (int)median + (EMA_ALPHA_DEN - EMA_ALPHA_NUM) * (int)emaValue) / EMA_ALPHA_DEN;
        }
      }
    } else {
      missingEchoCycles++;
      // If echo lost continuously for ECHO_LOST_CYCLES (~5s), clear EMA so offline is reported
      if (missingEchoCycles >= ECHO_LOST_CYCLES && emaValue > 0) {
        Serial.printf("[NODE] Echo lost (%d cycles) -> cleared EMA %d mm\n", missingEchoCycles, emaValue);
        emaValue = -1;
        lastSentMm = -1;
      }
      static unsigned long lastWarn = 0;
      if (millis() - lastWarn > 3000) {
        lastWarn = millis();
        Serial.println("[NODE] Waiting for ultrasonic echo / target in range");
      }
    }

    // Determine if we should transmit:
    // 1. If distance changed by > DEADBAND_MM (and we have an active reading)
    // 2. OR periodic heartbeat every HEARTBEAT_MS (2000ms) so Hub never times out!
    bool valueChanged = (hasReading && emaValue > 0 && (lastSentMm < 0 || abs((int)emaValue - (int)lastSentMm) > DEADBAND_MM));
    bool heartbeatDue = (millis() - lastSend >= HEARTBEAT_MS);

    if (valueChanged || heartbeatDue) {
      SensorData data;
      data.deviceId  = myDeviceId;
      // Send smoothed EMA (held during grace period); if echo is truly lost/offline send -1
      data.distance  = (emaValue > 0) ? emaValue : -1;
      data.timestamp = millis();
      esp_err_t result = esp_now_send(hubMAC, (uint8_t *)&data, sizeof(SensorData));
      if (result == ESP_OK) {
        lastSend = millis();
        if (data.distance > 0) lastSentMm = data.distance;
        Serial.printf("[NODE] TX: SensorData (Dist: %.2f m [%d mm], raw=%s)\n",
                      data.distance > 0 ? data.distance / 1000.0 : -1.0,
                      data.distance,
                      hasReading ? (String(median / 1000.0, 2) + " m").c_str() : "-1");
      } else {
        sendFailures++;
        Serial.printf("[NODE] Send fail #%d\n", sendFailures);
      }
    }

    // After 20 consecutive send failures, assume hub changed channel or reset
    if (sendFailures >= 20) {
      Serial.println("[NODE] Too many failures — clearing NVS, restarting...");
      nodeClearNVS();
      ESP.restart();
    }
  }
  delay(10);
}

#endif // NODE_DYP_SENSOR


#ifdef HUB_RS485_SENSOR

#include <Arduino.h>
#include <WiFi.h>
#include <TFT_eSPI.h>
#include <WebServer.h>
#include <DNSServer.h>
#include "qrcode.h"
#include <WiFi.h>
#include <Preferences.h>
bool invalidateCache = false;
DNSServer dnsServer;
bool isAPMode = false;
String hubSSID = "";
String hubPASS = "";
const byte DNS_PORT = 53;
void drawDisplay(bool fullRedraw);
void drawHeader();
void drawPage0(bool fullRedraw);
void drawPage1(bool fullRedraw);
void drawStatusBar(bool fullRedraw);
void drawMenu();
void drawSlider();
void drawQRCode(const char *text, const char *title);
void startWifiAP();
void connectToSavedWifi();
void initWebServer();
void broadcastBeacon();

#include <esp_now.h>
#include <esp_wifi.h>

// ─── TANK & SENSOR CALIBRATION ───────────────────────────────────────────────
int tankEmptyMm    = 2000;   // distance when tank is EMPTY (mm)
int tankFullMm     = 200;    // distance when tank is FULL  (mm)
int alertThreshold = 20;     // alert when fill % drops below this
int sensorOffsetMm = 0;      // calibration offset added to raw sensor distance (mm)
#define MAX_NODES 4

// ─── TFT & Calibration ────────────────────────────────────────────────────────
TFT_eSPI tft = TFT_eSPI();
uint16_t calData[5];

// ===== CUSTOM COLORS =====
#define COLOR_BG        0x0000 
#define COLOR_HEADER    0xFFE0 
#define COLOR_ACCENT    0x07E0 
#define COLOR_CYAN      0x07FF 
#define COLOR_WHITE     0xFFFF
#define COLOR_ORANGE    0xFD20
#define COLOR_RED       0xF800
#define COLOR_BLUE      0x001F
#define COLOR_DARK_GRAY 0x2104
#define COLOR_WARM      0xFBE0 
#define COLOR_COLD      0x5D7F 

struct NodeInfo {
  uint8_t mac[6];
  bool paired;
  int distance;
  unsigned long lastRecvTime;
};
NodeInfo nodes[MAX_NODES];

struct DiscoveredNode {
  uint8_t mac[6];
  uint32_t deviceId;
  unsigned long lastSeen;
};
#define MAX_DISCOVERED 4
DiscoveredNode discoveredNodes[MAX_DISCOVERED];
int discoveredNodeCount = 0;
int currentMenuPage = 0; // 0=Main, 1=NodeConfig, 2=DiscoveredNodes

unsigned long startTime = 0;
PairingBeacon beacon;
uint8_t myMAC[6];
uint16_t pairingCode;
unsigned long lastBeaconTime = 0;
bool espNowOk = false;

// UI State
int brightnessLevel = 255; 
const int BL_PIN = 22; 
bool inMenu = false;
int qrMode = 0;
WebServer server(80);
bool serverInitialized = false;
bool inAPSetup = false;
String scannedNetworksHTML = "";
bool newCredentialsSaved = false;
void setupServerRoutes();
String getAPSetupHTML();

bool isPairingMode = false;
unsigned long pairingStartTime = 0;
bool startupBeaconActive = false;
unsigned long startupBeaconStart = 0;
unsigned long lastStartupBeacon = 0;

// ── Buzzer (pin 26, MMBT2222A NPN — HIGH = on) ───────────────────────────────
#define TRANSISTOR_PIN 26
// Beep pattern state (non-blocking)
bool          buzzerAlert     = false; // true when at least one node is below threshold
bool          buzzerDismissed = false; // true when user dismissed/muted the active alert
bool          buzzerOn        = false; // current transistor state
unsigned long buzzerLast      = 0;
int           buzzerPhase     = 0;     // 0 = 1s blast (ON), 1 = 0.5s pause (OFF)

// ── 30-Minute Snooze Configuration ───────────────────────────────────────────
const unsigned long SNOOZE_DURATION_MS = 30UL * 60UL * 1000UL; // 30 minutes in milliseconds
unsigned long snoozeStartTime = 0; // millis() when snooze was activated
bool          snoozeActive    = false; // true while within the 30-minute snooze window

void toggleSnooze() {
  unsigned long now = millis();
  if (!snoozeActive && !buzzerDismissed) {
    // Activate 30-minute snooze
    snoozeActive = true;
    buzzerDismissed = true;
    snoozeStartTime = now;
    if (buzzerOn) {
      digitalWrite(TRANSISTOR_PIN, LOW);
      buzzerOn = false;
    }
    Serial.println("[HUB] Buzzer SNOOZED for 30 minutes.");
  } else {
    // Cancel snooze / un-mute immediately
    snoozeActive = false;
    buzzerDismissed = false;
    snoozeStartTime = 0;
    buzzerLast = 0; // restart alarm blast immediately if in alert
    Serial.println("[HUB] Buzzer SNOOZE CANCELLED / UNMUTED.");
  }
  if (!inMenu) drawHeader();
}

// Call this from loop() — drives the buzzer without delay()
// Pattern: 1 sec blast -> 0.5 sec pause -> repeat
void updateBuzzer() {
  unsigned long now = millis();

  // If snoozed, check if the 30-minute snooze window has expired
  if (snoozeActive) {
    if (now - snoozeStartTime >= SNOOZE_DURATION_MS) {
      snoozeActive = false;
      buzzerDismissed = false;
      snoozeStartTime = 0;
      buzzerLast = 0;
      Serial.println("[HUB] 30-minute snooze expired. Alarm re-armed!");
      if (!inMenu) drawHeader();
    }
  }

  if (!buzzerAlert || buzzerDismissed || snoozeActive) {
    if (buzzerOn) {
      digitalWrite(TRANSISTOR_PIN, LOW);
      buzzerOn = false;
    }
    buzzerPhase = 0;
    buzzerLast = 0;
    return;
  }

  // Pattern: 1000ms ON (blast) -> 500ms OFF (pause)
  static const uint16_t pattern[] = {1000, 500};

  // If entering alert state fresh, start the 1s blast immediately
  if (buzzerLast == 0) {
    buzzerLast = now;
    buzzerPhase = 0;
    buzzerOn = true;
    digitalWrite(TRANSISTOR_PIN, HIGH);
    return;
  }

  if (now - buzzerLast >= pattern[buzzerPhase]) {
    buzzerLast = now;
    buzzerPhase = (buzzerPhase + 1) % 2;
    buzzerOn = (buzzerPhase == 0); // phase 0 = 1000ms ON, phase 1 = 500ms OFF
    digitalWrite(TRANSISTOR_PIN, buzzerOn ? HIGH : LOW);
  }
}

// Audible buzzer test routine: 1s blast -> 0.5s pause -> 1s blast
void triggerBuzzerTest() {
  Serial.println("[HUB] Buzzer Test: sounding 1s blast -> 0.5s pause -> 1s blast...");
  digitalWrite(TRANSISTOR_PIN, HIGH);
  delay(1000);
  digitalWrite(TRANSISTOR_PIN, LOW);
  delay(500);
  digitalWrite(TRANSISTOR_PIN, HIGH);
  delay(1000);
  digitalWrite(TRANSISTOR_PIN, LOW);
  Serial.println("[HUB] Buzzer Test: complete.");
}

// ── NVS (Preferences) for paired node MACs & Calibration ────────────────────
Preferences hubPrefs;

void hubSaveCalibration() {
  hubPrefs.begin("hub", false);
  hubPrefs.putInt("emptyMm", tankEmptyMm);
  hubPrefs.putInt("fullMm", tankFullMm);
  hubPrefs.putInt("alertTh", alertThreshold);
  hubPrefs.putInt("offsetMm", sensorOffsetMm);
  hubPrefs.end();
  Serial.printf("[HUB] Saved calibration: Empty=%d Full=%d Alert=%d%% Offset=%d\n",
                tankEmptyMm, tankFullMm, alertThreshold, sensorOffsetMm);
}

void hubLoadCalibration() {
  hubPrefs.begin("hub", true);
  tankEmptyMm    = hubPrefs.getInt("emptyMm", 2000);
  tankFullMm     = hubPrefs.getInt("fullMm", 200);
  alertThreshold = hubPrefs.getInt("alertTh", 20);
  sensorOffsetMm = hubPrefs.getInt("offsetMm", 0);
  hubPrefs.end();
  Serial.printf("[HUB] Loaded calibration: Empty=%d Full=%d Alert=%d%% Offset=%d\n",
                tankEmptyMm, tankFullMm, alertThreshold, sensorOffsetMm);
}

// Global lowest percentage among nodes currently in alert state
int currentAlertPercent = 100;

// Check all nodes — update buzzerAlert flag & calculate alert percentage
void checkAlerts() {
  bool anyAlert = false;
  int minAlertPct = 100;
  for (int i = 0; i < MAX_NODES; i++) {
    if (!nodes[i].paired) continue;
    if (millis() - nodes[i].lastRecvTime > 15000) continue; // skip offline
    if (nodes[i].distance == -1) continue;
    int dist = constrain(nodes[i].distance + sensorOffsetMm, 0, 5000);
    int pct = map(dist, tankEmptyMm, tankFullMm, 0, 100);
    pct = constrain(pct, 0, 100);
    if (pct <= alertThreshold) {
      anyAlert = true;
      if (pct < minAlertPct) minAlertPct = pct;
    }
  }
  if (!anyAlert) {
    buzzerDismissed = false; // automatically re-arm alarm when water level recovers
    snoozeActive = false;
    snoozeStartTime = 0;
    currentAlertPercent = 100;
  } else {
    currentAlertPercent = (minAlertPct <= 100) ? minAlertPct : alertThreshold;
  }
  static int lastAlertPct = -1;
  static bool lastDismissed = false;
  static bool lastSnooze = false;
  if (anyAlert != buzzerAlert || (anyAlert && currentAlertPercent != lastAlertPct) || buzzerDismissed != lastDismissed || snoozeActive != lastSnooze) {
    buzzerAlert = anyAlert;
    lastAlertPct = currentAlertPercent;
    lastDismissed = buzzerDismissed;
    lastSnooze = snoozeActive;
    if (!inMenu) drawHeader(); // Update header to display new alert/silence button with percentage
  }
}

void hubSaveNodes() {
  hubPrefs.begin("hub", false);
  int count = 0;
  for (int i = 0; i < MAX_NODES; i++) {
    if (nodes[i].paired) {
      char key[10];
      sprintf(key, "mac%d", count);
      hubPrefs.putBytes(key, nodes[i].mac, 6);
      count++;
    }
  }
  hubPrefs.putInt("count", count);
  hubPrefs.end();
}

void hubLoadNodes() {
  hubPrefs.begin("hub", true);
  int count = hubPrefs.getInt("count", 0);
  hubPrefs.end();
  for (int i = 0; i < count && i < MAX_NODES; i++) {
    hubPrefs.begin("hub", true);
    char key[10]; sprintf(key, "mac%d", i);
    hubPrefs.getBytes(key, nodes[i].mac, 6);
    hubPrefs.end();
    nodes[i].paired = true;
    nodes[i].distance = -1;
    nodes[i].lastRecvTime = 0;
    // Register as ESP-NOW peer (will be done after esp_now_init in setup)
    Serial.printf("[HUB] Loaded node %d from NVS: %02X:%02X:%02X:%02X:%02X:%02X\n",
                  i+1, nodes[i].mac[0], nodes[i].mac[1], nodes[i].mac[2],
                  nodes[i].mac[3], nodes[i].mac[4], nodes[i].mac[5]);
  }
}

// Returns how many nodes are currently paired (used instead of activeNodeCount())
int activeNodeCount() {
  int c = 0;
  for (int i = 0; i < MAX_NODES; i++) if (nodes[i].paired) c++;
  return c;
}
int currentPage = 0; // 0 = Number Grid, 1 = Visual Tanks
int lastRenderedPage = -1; // tracks page changes to eliminate screen bleeding
bool forceRedraw = true;

void setBrightness(int level) {
  brightnessLevel = constrain(level, 20, 255);
  ledcSetup(7, 5000, 8); // Move to channel 7 to avoid conflict with tone() on channel 0
  ledcAttachPin(BL_PIN, 7);
  ledcWrite(7, brightnessLevel);
}

void printMAC(const uint8_t *mac) {
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  Serial.print(buf);
}

// ─── ESP-NOW Callback ─────────────────────────────────────────────────────────
void OnDataRecv(const uint8_t *mac, const uint8_t *incomingData, int len) {

  if (len == sizeof(SensorData)) {
    SensorData *data = (SensorData *)incomingData;
    Serial.printf("[HUB] RX: Received SensorData from %02X:%02X:%02X:%02X:%02X:%02X -> Dist: %.2f m (%d mm)\n",
                  mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],
                  data->distance >= 0 ? data->distance / 1000.0 : -1.0, data->distance);
    for (int i = 0; i < MAX_NODES; i++) {
      if (nodes[i].paired && memcmp(nodes[i].mac, mac, 6) == 0) {
        // ── Known paired node: update data ──
        bool wasOffline = (nodes[i].lastRecvTime == 0) || (millis() - nodes[i].lastRecvTime > 10000);
        if (nodes[i].distance != data->distance || wasOffline) forceRedraw = true;
        nodes[i].distance = data->distance;
        nodes[i].lastRecvTime = millis();
        return;
      }
    }
    return;
  }

  if (len == sizeof(PairingRequest)) {
    PairingRequest *req = (PairingRequest *)incomingData;
    if (strncmp(req->magic, "WLMSREQ", 8) != 0) return;
    Serial.printf("[HUB] RX: Received WLMSREQ (PairingRequest) from %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    // Validate auth tag
    uint32_t expected = pairAuth((uint8_t*)req, sizeof(PairingRequest) - sizeof(req->auth));
    if (req->auth != expected) { Serial.println("[HUB] Request auth FAIL"); return; }

    // If this node is already in our NVS paired list, auto-confirm immediately!
    for (int i = 0; i < MAX_NODES; i++) {
      if (nodes[i].paired && memcmp(nodes[i].mac, mac, 6) == 0) {
        if (!esp_now_is_peer_exist(mac)) {
          esp_now_peer_info_t peer = {};
          memcpy(peer.peer_addr, mac, 6);
          peer.channel = 0;
          peer.ifidx = isAPMode ? WIFI_IF_AP : WIFI_IF_STA;
          peer.encrypt = false;
          esp_now_add_peer(&peer);
        }
        PairingConfirm conf = {};
        strncpy(conf.magic, "WLMSCONF", 8);
        memcpy(conf.hubMAC, myMAC, 6);
        conf.deviceId = req->deviceId;
        conf.accepted = true;
        conf.auth = pairAuth((uint8_t*)&conf, sizeof(PairingConfirm) - sizeof(conf.auth));
        esp_now_send(mac, (uint8_t *)&conf, sizeof(PairingConfirm));
        Serial.printf("[HUB] Auto-reconfirmed known Node %d\n", i+1);
        return;
      }
    }

    // Accept any pairing code since node initiates
    if (currentMenuPage != 2) {
      Serial.println("[HUB] Pairing request ignored — not in pairing mode");
      return;
    }
    // Add to discovered nodes list for user to confirm via PAIR button
    bool found = false;
    for (int i = 0; i < discoveredNodeCount; i++) {
      if (memcmp(discoveredNodes[i].mac, mac, 6) == 0) {
        discoveredNodes[i].lastSeen = millis();
        found = true; break;
      }
    }
    if (!found && discoveredNodeCount < MAX_DISCOVERED) {
      memcpy(discoveredNodes[discoveredNodeCount].mac, mac, 6);
      discoveredNodes[discoveredNodeCount].deviceId = req->deviceId;
      discoveredNodes[discoveredNodeCount].lastSeen = millis();
      discoveredNodeCount++;
      forceRedraw = true;
      Serial.printf("[HUB] Discovered node %d\n", discoveredNodeCount);
    }
  }
}

// ===== TFT UI =====
void drawHeader() {
  tft.fillRect(0, 0, 320, 32, COLOR_BG);
  tft.setTextColor(COLOR_HEADER);
  tft.setTextSize(2);
  tft.setCursor(6, 8);
  tft.print("AQUAPULSE");
  tft.drawFastHLine(0, 31, 320, COLOR_ACCENT);

  // Dismiss / Snooze Buzzer button when buzzer is alerting
  // When buzzing: BRIGHT RED button [SILENCE XX%]
  // When snoozed: BLUE button [SNOOZED 30m] (counts down remaining minutes!)
  if (buzzerAlert) {
    char label[24];
    uint16_t btnColor;
    if (!snoozeActive && !buzzerDismissed) {
      sprintf(label, "SILENCE %d%%", currentAlertPercent);
      btnColor = COLOR_RED; // BRIGHT RED when actively buzzing
    } else {
      unsigned long elapsed = millis() - snoozeStartTime;
      int remMin = 30;
      if (elapsed < SNOOZE_DURATION_MS) {
        remMin = (int)((SNOOZE_DURATION_MS - elapsed + 59999UL) / 60000UL);
      }
      sprintf(label, "SNOOZED %dm", remMin);
      btnColor = COLOR_BLUE; // Changes to BLUE when snoozed!
    }

    tft.fillRoundRect(124, 3, 128, 26, 5, btnColor);
    tft.setTextColor(COLOR_WHITE, btnColor);
    tft.setTextSize(1);
    int textW = strlen(label) * 6;
    tft.setCursor(124 + (128 - textW) / 2, 12);
    tft.print(label);
  }

  // Menu Button — top-right
  tft.fillRoundRect(258, 4, 58, 24, 4, COLOR_DARK_GRAY);
  tft.setTextColor(COLOR_WHITE);
  tft.setTextSize(1);
  tft.setCursor(268, 11);
  tft.print("MENU");
}

void startWifiAP() {
  Serial.println("[HUB] Entering WiFi AP Setup Mode...");

  // 1. Drain lingering touches from the button tap that opened AP mode
  uint16_t tx, ty;
  while (tft.getTouch(&tx, &ty)) {
    delay(20);
  }
  delay(150);

  // 2. Configure and start SoftAP on Channel 1
  char apSSID[32];
  sprintf(apSSID, "HUB_%02X%02X", myMAC[4], myMAC[5]);

  WiFi.mode(WIFI_AP_STA);
  IPAddress apIP(192, 168, 4, 1);
  IPAddress netMsk(255, 255, 255, 0);

  bool apOk = WiFi.softAP(apSSID, "12345678", PAIRING_CHANNEL);
  delay(100);
  WiFi.softAPConfig(apIP, apIP, netMsk);
  Serial.printf("[HUB] SoftAP started: %s, SSID='%s', IP=%s\n",
                apOk ? "OK" : "FAILED", apSSID, WiFi.softAPIP().toString().c_str());

  // 3. Start DNS Server for captive portal (port 53 wildcard)
  dnsServer.stop();
  dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
  dnsServer.start(53, "*", apIP);

  // 4. Setup and start Web Server
  setupServerRoutes();
  server.begin();
  inAPSetup = true;
  newCredentialsSaved = false;

  // 5. Draw clean AP UI with QR Code and Cancel button
  tft.fillScreen(COLOR_BG);
  tft.setTextColor(COLOR_HEADER);
  tft.setTextSize(2);
  tft.setCursor(15, 10);
  tft.print("WIFI SETUP (HOTSPOT)");

  tft.setTextColor(COLOR_WHITE);
  tft.setTextSize(1);
  tft.setCursor(15, 34);
  tft.print("1. Connect Phone to: ");
  tft.setTextColor(COLOR_CYAN);
  tft.print(apSSID);

  tft.setTextColor(COLOR_WHITE);
  tft.setCursor(15, 48);
  tft.print("   Password: ");
  tft.setTextColor(COLOR_ACCENT);
  tft.print("12345678");

  tft.setTextColor(COLOR_WHITE);
  tft.setCursor(15, 62);
  tft.print("2. Open: ");
  tft.setTextColor(0x07E0); // Green
  tft.print("http://192.168.4.1");

  // QR Code
  char qrStr[64];
  sprintf(qrStr, "WIFI:T:WPA;S:%s;P:12345678;;", apSSID);
  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(3)];
  qrcode_initText(&qrcode, qrcodeData, 3, 0, qrStr);
  int scale = 3;
  int offsetX = (320 - (qrcode.size * scale)) / 2;
  int offsetY = 80;
  tft.fillRect(offsetX - 4, offsetY - 4, (qrcode.size * scale) + 8, (qrcode.size * scale) + 8, COLOR_WHITE);
  for (uint8_t y = 0; y < qrcode.size; y++) {
    for (uint8_t x = 0; x < qrcode.size; x++) {
      if (qrcode_getModule(&qrcode, x, y)) {
        tft.fillRect(offsetX + x * scale, offsetY + y * scale, scale, scale, TFT_BLACK);
      } else {
        tft.fillRect(offsetX + x * scale, offsetY + y * scale, scale, scale, COLOR_WHITE);
      }
    }
  }

  // Red Cancel Button at bottom
  tft.fillRoundRect(60, 195, 200, 36, 6, COLOR_RED);
  tft.drawRoundRect(60, 195, 200, 36, 6, COLOR_WHITE);
  tft.setTextColor(COLOR_WHITE);
  tft.setTextSize(2);
  tft.setCursor(85, 205);
  tft.print("CANCEL / BACK");

  // Loop while in AP mode
  int lastStationCount = -1;
  while (inAPSetup) {
    dnsServer.processNextRequest();
    server.handleClient();

    // Check station count & update TFT status
    int stCount = WiFi.softAPgetStationNum();
    if (stCount != lastStationCount) {
      lastStationCount = stCount;
      Serial.printf("[HUB-AP] Stations connected: %d\n", stCount);
      tft.fillRect(15, 62, 290, 16, COLOR_BG);
      tft.setCursor(15, 62);
      if (stCount > 0) {
        tft.setTextColor(0x07E0); // Green
        tft.print("Phone connected! Open 192.168.4.1");
      } else {
        tft.setTextColor(COLOR_WHITE);
        tft.print("2. Open: ");
        tft.setTextColor(0x07E0); // Green
        tft.print("http://192.168.4.1");
      }
    }

    // Check Cancel touch: wait for finger lift to confirm deliberate tap
    if (tft.getTouch(&tx, &ty)) {
      if (tx >= 50 && tx <= 270 && ty >= 185 && ty <= 238) {
        unsigned long pressStart = millis();
        while (tft.getTouch(&tx, &ty)) {
          if (millis() - pressStart > 3000) break;
          delay(20);
        }
        delay(80);
        Serial.println("[HUB] AP setup cancelled by user tap");
        break;
      }
    }

    // Handle serial commands in AP mode
    if (Serial.available()) {
      String cmd = Serial.readStringUntil('\n');
      cmd.trim();
      if (cmd.startsWith("wifi set ") || cmd.startsWith("set wifi ")) {
        String rest = cmd.startsWith("set wifi ") ? cmd.substring(9) : cmd.substring(9);
        rest.trim();
        int sp = rest.indexOf(' ');
        String s = "", p = "";
        if (sp > 0) {
          s = rest.substring(0, sp);
          p = rest.substring(sp + 1);
        } else {
          s = rest;
          p = "";
        }
        s.trim(); p.trim();
        if (s.length() > 0) {
          Preferences pr;
          pr.begin("hub", false);
          pr.putString("ssid", s);
          pr.putString("pass", p);
          pr.end();
          hubSSID = s; hubPASS = p;
          newCredentialsSaved = true;
          Serial.printf("[HUB] WiFi credentials set via serial: SSID='%s'\n", hubSSID.c_str());
          break;
        }
      } else if (cmd.equalsIgnoreCase("cancel") || cmd.equalsIgnoreCase("exit") || cmd.equalsIgnoreCase("quit")) {
        Serial.println("[HUB] Exiting AP setup mode via serial command");
        break;
      } else if (cmd.equalsIgnoreCase("status") || cmd.equalsIgnoreCase("wifi")) {
        Serial.printf("[HUB-AP] Active! SSID='%s', IP=%s, Stations=%d\n",
                      apSSID, WiFi.softAPIP().toString().c_str(), stCount);
      }
    }

    yield();
  }

  // Cleanup AP mode
  inAPSetup = false;
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  esp_wifi_set_channel(PAIRING_CHANNEL, WIFI_SECOND_CHAN_NONE);

  if (newCredentialsSaved && hubSSID.length() > 0) {
    connectToSavedWifi();
  } else {
    inMenu = true;
    currentMenuPage = 4;
    drawMenu();
  }
}

void connectToSavedWifi() {
  if (hubSSID.length() == 0) {
    startWifiAP();
    return;
  }
  
  // Show pop-up on TFT screen
  tft.fillRect(20, 60, 280, 120, COLOR_DARK_GRAY);
  tft.drawRect(20, 60, 280, 120, COLOR_CYAN);
  tft.setTextColor(COLOR_WHITE);
  tft.setTextSize(2);
  tft.setCursor(35, 75);
  tft.print("Connecting to WiFi:");
  tft.setTextColor(COLOR_ACCENT);
  tft.setTextSize(1);
  tft.setCursor(35, 102);
  tft.print(hubSSID);
  tft.setTextColor(COLOR_CYAN);
  tft.setCursor(35, 122);
  tft.print("Please wait...");

  WiFi.mode(WIFI_STA);
  WiFi.begin(hubSSID.c_str(), hubPASS.c_str());

  unsigned long start = millis();
  int dotCount = 0;
  while (WiFi.status() != WL_CONNECTED && millis() - start < 9000) {
    delay(300);
    tft.print(".");
    dotCount++;
    if (dotCount % 8 == 0) {
      tft.fillRect(35, 138, 250, 15, COLOR_DARK_GRAY);
      tft.setCursor(35, 138);
    }
  }

  if (WiFi.status() == WL_CONNECTED) {
    tft.fillRect(20, 60, 280, 120, COLOR_DARK_GRAY);
    tft.drawRect(20, 60, 280, 120, 0x07E0); // Bright green
    tft.setTextColor(0x07E0);
    tft.setTextSize(2);
    tft.setCursor(35, 75);
    tft.print("CONNECTED!");
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(1);
    tft.setCursor(35, 102);
    tft.print("IP: "); tft.print(WiFi.localIP());
    tft.setCursor(35, 122);
    tft.print("Web Dashboard Ready!");
    
    initWebServer();
    delay(1800);
  } else {
    tft.fillRect(20, 60, 280, 120, COLOR_DARK_GRAY);
    tft.drawRect(20, 60, 280, 120, COLOR_RED);
    tft.setTextColor(COLOR_RED);
    tft.setTextSize(2);
    tft.setCursor(35, 75);
    tft.print("CONNECTION FAILED");
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(1);
    tft.setCursor(35, 102);
    tft.print("Check password or router.");
    tft.setCursor(35, 122);
    tft.print("Tap screen to return...");
    delay(1800);
  }
  drawMenu();
}

void drawSlider() {
  int sliderX = 8, sliderY = 50, sliderW = 304, sliderH = 18;
  tft.fillRect(sliderX - 12, sliderY - 12, sliderW + 24, sliderH + 24, COLOR_BG);
  tft.fillRoundRect(sliderX, sliderY, sliderW, sliderH, 9, COLOR_DARK_GRAY);
  int fillW = map(brightnessLevel, 20, 255, 0, sliderW);
  tft.fillRoundRect(sliderX, sliderY, fillW, sliderH, 9, COLOR_ACCENT);
  tft.fillCircle(sliderX + fillW, sliderY + 9, 12, COLOR_WHITE);
}


void drawQRCode(String url, String title) {
    tft.fillScreen(COLOR_BG);
    tft.setTextColor(COLOR_HEADER);
    tft.setTextSize(2);
    tft.setCursor(10, 10);
    tft.print(title);
    
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(1);
    tft.setCursor(10, 35);
    char ssidStr[64];
    sprintf(ssidStr, "WiFi: HUB_%02X%02X  Pass: 12345678", myMAC[4], myMAC[5]);
    tft.print(ssidStr);
    
    QRCode qrcode;
    uint8_t qrcodeData[qrcode_getBufferSize(3)];
    qrcode_initText(&qrcode, qrcodeData, 3, 0, url.c_str());
    
    int scale = 4;
    int offsetX = (320 - (qrcode.size * scale)) / 2;
    int offsetY = 60;
    
    tft.fillRect(offsetX - 4, offsetY - 4, (qrcode.size * scale) + 8, (qrcode.size * scale) + 8, COLOR_WHITE);
    for (uint8_t y = 0; y < qrcode.size; y++) {
        for (uint8_t x = 0; x < qrcode.size; x++) {
            if (qrcode_getModule(&qrcode, x, y)) {
                tft.fillRect(offsetX + x * scale, offsetY + y * scale, scale, scale, TFT_BLACK);
            } else {
                tft.fillRect(offsetX + x * scale, offsetY + y * scale, scale, scale, COLOR_WHITE);
            }
        }
    }
    
    tft.fillRoundRect(80, 200, 160, 35, 6, COLOR_BLUE);
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(2);
    tft.setCursor(130, 210);
    tft.print("BACK");
}


void drawNodesList() {
  tft.fillScreen(COLOR_BG);
  tft.setTextColor(COLOR_WHITE);
  tft.setTextSize(3);
  tft.setCursor(10, 10);
  tft.print("NEARBY NODES");
  
  tft.setTextSize(2);
  int y = 60;
  int count = 0;
  for (int i=0; i<MAX_NODES; i++) {
    if (nodes[i].paired) {
      tft.setCursor(10, y);
      tft.setTextColor(COLOR_CYAN);
      tft.print("Node ");
      tft.print(i+1);
      tft.print(": ");
      
      char macStr[18];
      sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", nodes[i].mac[0], nodes[i].mac[1], nodes[i].mac[2], nodes[i].mac[3], nodes[i].mac[4], nodes[i].mac[5]);
      tft.setTextColor(COLOR_WHITE);
      tft.print(macStr);
      
      bool offline = (millis() - nodes[i].lastRecvTime > 10000);
      if (offline) {
         tft.setTextColor(COLOR_ORANGE);
         tft.print(" (OFF)");
      }
      y += 30;
      count++;
    }
  }
  
  if (count == 0) {
    tft.setTextColor(COLOR_DARK_GRAY);
    tft.setCursor(10, y);
    tft.print("No nodes nearby...");
  }
  
  // Back Button
  tft.fillRoundRect(40, 180, 240, 50, 8, COLOR_BLUE);
  tft.setTextColor(COLOR_WHITE);
  tft.setTextSize(3);
  tft.setCursor(120, 195);
  tft.print("BACK");
}



void drawMenu() {
  tft.fillScreen(COLOR_BG);
  tft.setTextColor(COLOR_HEADER);

  // ── Page 0: Main Settings ─────────────────────────────────────────────────
  if (currentMenuPage == 0) {
    // Title bar (uses full width, size-2 text = 12px tall)
    tft.fillRect(0, 0, 320, 24, COLOR_DARK_GRAY);
    tft.setTextColor(COLOR_HEADER);
    tft.setTextSize(2);
    tft.setCursor(6, 4);
    tft.print("SETTINGS");

    // BRIGHTNESS label + slider (y=26..56)
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(1);
    tft.setCursor(6, 28);
    tft.print("BRIGHTNESS");
    drawSlider(); // draws at y=50

    // Row of 3 square buttons (y=80..140)
    // [WiFi Setup]  [NODE CFG]  [TANK CAL]
    int bY = 82, bH = 56;
    bool isConnected = (WiFi.status() == WL_CONNECTED);
    tft.fillRoundRect(4,   bY, 97, bH, 5, isConnected ? 0x0280 : COLOR_DARK_GRAY);
    tft.fillRoundRect(111, bY, 97, bH, 5, COLOR_DARK_GRAY);
    tft.fillRoundRect(218, bY, 97, bH, 5, COLOR_DARK_GRAY);

    tft.setTextSize(1);
    tft.setTextColor(isConnected ? COLOR_WHITE : COLOR_CYAN);
    tft.setCursor(16,  bY + 12); tft.print("WiFi");
    tft.setCursor(16,  bY + 24);
    if (isConnected) {
      tft.print("ONLINE");
    } else if (hubSSID.length() > 0) {
      tft.print("Saved");
    } else {
      tft.print("Setup");
    }
    tft.setCursor(16,  bY + 38);
    tft.setTextColor(isConnected ? 0x07E0 : COLOR_WHITE);
    tft.print("CONFIG");

    tft.setTextColor(COLOR_WHITE);
    tft.setCursor(122, bY + 14); tft.print("NODE");
    tft.setCursor(122, bY + 28); tft.print("CONFIG");
    tft.setTextColor(COLOR_ACCENT);
    tft.setCursor(229, bY + 14); tft.print("TANK");
    tft.setCursor(229, bY + 28); tft.print("CAL");

    // BACK button (y=148..190)
    tft.fillRoundRect(8, 148, 304, 38, 6, COLOR_RED);
    tft.setTextColor(COLOR_WHITE, COLOR_RED);
    tft.setTextSize(2);
    tft.setCursor(134, 157);
    tft.print("BACK");
  }

  // ── Page 1: Node Config ───────────────────────────────────────────────────
  else if (currentMenuPage == 1) {
    tft.fillRect(0, 0, 320, 24, COLOR_DARK_GRAY);
    tft.setTextColor(COLOR_HEADER);
    tft.setTextSize(2);
    tft.setCursor(6, 4);
    tft.print("NODE CONFIG");

    // Paired count (read-only)
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(1);
    tft.setCursor(6, 34);
    tft.print("PAIRED NODES:");
    tft.setTextColor(COLOR_ACCENT);
    tft.setTextSize(2);
    tft.setCursor(120, 28);
    tft.print(activeNodeCount());
    tft.setTextSize(1);
    tft.setTextColor(0x4208);
    tft.setCursor(138, 34);
    tft.print("/ 4");

    // ADD NODE / PAIRING button (left half)
    if (isPairingMode) {
      tft.fillRoundRect(4, 68, 150, 46, 5, COLOR_ORANGE);
      tft.setTextColor(COLOR_BG);
      tft.setTextSize(1);
      tft.setCursor(18, 87); tft.print("PAIRING...");
    } else {
      tft.fillRoundRect(4, 68, 150, 46, 5, COLOR_BLUE);
      tft.setTextColor(COLOR_WHITE);
      tft.setTextSize(1);
      tft.setCursor(28, 87); tft.print("ADD NODE");
    }

    // CLEAR ALL button (right half)
    tft.fillRoundRect(162, 68, 150, 46, 5, COLOR_RED);
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(1);
    tft.setCursor(176, 87); tft.print("FORGET ALL");

    // BACK button
    tft.fillRoundRect(8, 128, 304, 38, 6, COLOR_DARK_GRAY);
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(2);
    tft.setCursor(134, 137);
    tft.print("BACK");
  }

  // ── Page 2: Nearby Nodes scan ─────────────────────────────────────────────
  else if (currentMenuPage == 2) {
    tft.fillRect(0, 0, 320, 24, COLOR_DARK_GRAY);
    tft.setTextColor(COLOR_HEADER);
    tft.setTextSize(2);
    tft.setCursor(6, 4);
    tft.print("NEARBY NODES");

    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(1);

    if (discoveredNodeCount == 0) {
      tft.setCursor(8, 40);
      tft.print("Scanning for nodes...");
    } else {
      for (int i = 0; i < discoveredNodeCount && i < 4; i++) {
        int rowY = 32 + (i * 46);
        tft.fillRoundRect(4, rowY, 314, 40, 4, COLOR_DARK_GRAY);
        tft.setTextColor(COLOR_WHITE);
        tft.setCursor(10, rowY + 10);
        tft.print("NODE ");
        char hx[4]; sprintf(hx, "%02X", discoveredNodes[i].deviceId);
        tft.print(hx);
        // MAC last 3 bytes for identification
        tft.setTextColor(COLOR_CYAN);
        tft.setCursor(10, rowY + 24);
        char mac[18];
        sprintf(mac, "%02X:%02X:%02X", discoveredNodes[i].mac[3], discoveredNodes[i].mac[4], discoveredNodes[i].mac[5]);
        tft.print(mac);

        tft.fillRoundRect(238, rowY + 5, 76, 30, 4, COLOR_BLUE);
        tft.setTextColor(COLOR_WHITE);
        tft.setTextSize(2);
        tft.setCursor(254, rowY + 12);
        tft.print("PAIR");
        tft.setTextSize(1);
      }
    }

    // CANCEL button (bottom strip)
    tft.fillRoundRect(4, 216, 312, 22, 4, COLOR_RED);
    tft.setTextColor(COLOR_WHITE);
    tft.setCursor(130, 220);
    tft.print("CANCEL");
  }

  // ── Page 3: Tank & Sensor Calibration ─────────────────────────────────────
  else if (currentMenuPage == 3) {
    tft.fillRect(0, 0, 320, 24, COLOR_DARK_GRAY);
    tft.setTextColor(COLOR_HEADER);
    tft.setTextSize(2);
    tft.setCursor(6, 4);
    tft.print("TANK & SENSOR CAL");

    char buf[12];
    int rH = 34;
    int rYs[4] = {28, 66, 104, 142};
    const char* labels[4] = {"EMPTY mm", "FULL  mm", "OFFSET mm", "ALERT %"};
    uint16_t cols[4] = {COLOR_ORANGE, COLOR_ACCENT, COLOR_CYAN, COLOR_RED};

    for (int r = 0; r < 4; r++) {
      int rY = rYs[r];
      tft.fillRoundRect(4, rY, 312, rH, 4, COLOR_DARK_GRAY);

      // Label
      tft.setTextColor(COLOR_WHITE);
      tft.setTextSize(1);
      tft.setCursor(10, rY + 12);
      tft.print(labels[r]);

      // Value
      tft.setTextColor(cols[r]);
      tft.setTextSize(2);
      if (r == 0) sprintf(buf, "%4d", tankEmptyMm);
      else if (r == 1) sprintf(buf, "%4d", tankFullMm);
      else if (r == 2) sprintf(buf, "%+4d", sensorOffsetMm);
      else sprintf(buf, "%3d%%", alertThreshold);
      tft.setCursor(110, rY + 9);
      tft.print(buf);

      // [+] button
      tft.fillRoundRect(224, rY + 3, 38, rH - 6, 4, 0x03E0);
      tft.setTextColor(COLOR_WHITE);
      tft.setTextSize(2);
      tft.setCursor(236, rY + 8);
      tft.print("+");

      // [-] button
      tft.fillRoundRect(268, rY + 3, 38, rH - 6, 4, 0xC000);
      tft.setCursor(280, rY + 8);
      tft.print("-");
    }

    // BACK button (all changes auto-save immediately to NVS)
    tft.fillRoundRect(8, 184, 304, 36, 6, COLOR_RED);
    tft.setTextColor(COLOR_WHITE, COLOR_RED);
    tft.setTextSize(2);
    tft.setCursor(134, 194);
    tft.print("BACK");
  }

  // ── Page 99: Secret Menu ──────────────────────────────────────────────────
  if (currentMenuPage == 99) {
    tft.fillRect(0, 0, 320, 24, COLOR_DARK_GRAY);
    tft.setTextColor(COLOR_CYAN);
    tft.setTextSize(2);
    tft.setCursor(6, 4);
    tft.print("SECRET MENU");

    // BUZZER TEST BUTTON
    tft.fillRoundRect(8, 50, 304, 50, 6, COLOR_ORANGE);
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(2);
    tft.setCursor(95, 66);
    tft.print("TEST BUZZER");

    // System Info
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(1);
    tft.setCursor(10, 115);
    tft.print("Hub MAC: "); 
    char macStr[20];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", myMAC[0], myMAC[1], myMAC[2], myMAC[3], myMAC[4], myMAC[5]);
    tft.print(macStr);
    tft.setCursor(10, 130);
    tft.print("Uptime (s): "); tft.print(millis()/1000);

    // BACK button
    tft.fillRoundRect(8, 160, 304, 38, 6, COLOR_RED);
    tft.setTextColor(COLOR_WHITE, COLOR_RED);
    tft.setTextSize(2);
    tft.setCursor(134, 172);
    tft.print("BACK");
  }
  else if (currentMenuPage == 4) {
    // WiFi Setup & Connection info page
    tft.fillRect(0, 0, 320, 24, COLOR_DARK_GRAY);
    tft.setTextColor(COLOR_HEADER);
    tft.setTextSize(2);
    tft.setCursor(6, 4);
    tft.print("WIFI SETUP & CONNECT");

    bool isConn = (WiFi.status() == WL_CONNECTED);

    // Status Banner Box (y=28..90)
    uint16_t boxBorder = isConn ? 0x07E0 : (hubSSID.length() > 0 ? COLOR_ORANGE : COLOR_DARK_GRAY);
    tft.fillRoundRect(8, 28, 304, 62, 5, isConn ? 0x0208 : 0x18C3);
    tft.drawRoundRect(8, 28, 304, 62, 5, boxBorder);

    tft.setTextSize(1);
    if (isConn) {
      tft.setTextColor(0x07E0);
      tft.setCursor(16, 34);
      tft.print("STATUS: ONLINE (CONNECTED)");
      tft.setTextColor(COLOR_WHITE);
      tft.setCursor(16, 48);
      tft.print("SSID: "); tft.print(hubSSID);
      tft.setTextColor(COLOR_CYAN);
      tft.setCursor(16, 62);
      tft.print("IP:   "); tft.print(WiFi.localIP().toString());
      tft.setCursor(16, 74);
      tft.setTextColor(0xFFE0); // Yellow
      tft.print("Web:  http://"); tft.print(WiFi.localIP().toString()); tft.print("/");
    } else {
      tft.setTextColor(COLOR_ORANGE);
      tft.setCursor(16, 34);
      tft.print("STATUS: DISCONNECTED");
      tft.setTextColor(COLOR_WHITE);
      tft.setCursor(16, 48);
      if (hubSSID.length() > 0) {
        tft.print("Saved SSID: "); tft.print(hubSSID);
        tft.setTextColor(COLOR_CYAN);
        tft.setCursor(16, 64);
        tft.print("Tap CONNECT below to join WiFi.");
      } else {
        tft.print("No WiFi network configured.");
        tft.setTextColor(COLOR_CYAN);
        tft.setCursor(16, 64);
        tft.print("Tap SETUP AP to configure via phone.");
      }
    }

    if (hubSSID.length() > 0) {
      // Button 1 (y=96..132, h=36): Connect or Reconnect
      uint16_t btnCol = isConn ? COLOR_BLUE : 0x03E0;
      tft.fillRoundRect(8, 96, 304, 36, 5, btnCol);
      tft.setTextColor(COLOR_WHITE);
      tft.setTextSize(2);
      tft.setCursor(isConn ? 32 : 36, 106);
      tft.print(isConn ? "RE-CHECK / RECONNECT" : "CONNECT TO SAVED WIFI");

      // Button 2 (y=138..174, h=36): Start Setup AP (New WiFi)
      tft.fillRoundRect(8, 138, 304, 36, 5, COLOR_CYAN);
      tft.setTextColor(COLOR_BG);
      tft.setTextSize(2);
      tft.setCursor(34, 148);
      tft.print("SETUP NEW WIFI (AP)");

      // Button 3 & 4 (y=182..218, h=36)
      // Left: Forget WiFi
      tft.fillRoundRect(8, 182, 146, 36, 5, COLOR_RED);
      tft.setTextColor(COLOR_WHITE);
      tft.setTextSize(1);
      tft.setCursor(32, 195);
      tft.print("FORGET WIFI");

      // Right: Back
      tft.fillRoundRect(166, 182, 146, 36, 5, COLOR_DARK_GRAY);
      tft.setTextColor(COLOR_WHITE);
      tft.setTextSize(2);
      tft.setCursor(212, 192);
      tft.print("BACK");
    } else {
      // No saved WiFi
      // Button 1 (y=100..152, h=52): Start Setup AP
      tft.fillRoundRect(8, 100, 304, 52, 6, COLOR_CYAN);
      tft.setTextColor(COLOR_BG);
      tft.setTextSize(2);
      tft.setCursor(38, 114);
      tft.print("START WIFI SETUP AP");
      tft.setTextSize(1);
      tft.setCursor(55, 136);
      tft.print("Scan QR code with your phone");

      // Button 2 (y=164..210, h=46): Back
      tft.fillRoundRect(8, 164, 304, 46, 6, COLOR_DARK_GRAY);
      tft.setTextColor(COLOR_WHITE);
      tft.setTextSize(2);
      tft.setCursor(134, 178);
      tft.print("BACK");
    }
  }
}

void handleTouch() {
  static bool isTouching = false;
  static uint16_t startX, startY, lastX, lastY;
  static unsigned long touchStartTime = 0;

  uint16_t x, y;
  bool touched = tft.getTouch(&x, &y);
  
  if (touched) {
    if (!isTouching) {
      startX = x; startY = y;
      isTouching = true;
      touchStartTime = millis();
    }
    lastX = x; lastY = y;
    
    if (qrMode > 0) return;

    if (inMenu && currentMenuPage == 0) {
      int sliderX = 8, sliderY = 50, sliderW = 304, sliderH = 18;
      if (x >= sliderX - 12 && x <= sliderX + sliderW + 12 && y >= sliderY - 12 && y <= sliderY + sliderH + 12) {
        int newBr = map(x, sliderX, sliderX + sliderW, 20, 255);
        newBr = constrain(newBr, 20, 255);
        if (abs(newBr - brightnessLevel) > 3) {
           setBrightness(newBr);
           drawSlider();
        }
      }
    }
  } else {
    if (isTouching) {
      isTouching = false;
      int dx = lastX - startX;
      int dy = lastY - startY;
      unsigned long duration = millis() - touchStartTime;
      
      if (abs(dx) < 20 && abs(dy) < 20 && duration < 500) {
        if (qrMode > 0) {
          qrMode = 0;
          drawMenu();
          return;
        }
        if (!inMenu) {
          // 1. SNOOZE / DISMISS BUZZER button in header (x=122..254, y=0..32)
          if (buzzerAlert && startX >= 122 && startX <= 254 && startY <= 32) {
            toggleSnooze();
            return;
          }
          // 2. MENU button (x=258..316, y=0..32)
          else if (startX > 258 && startY < 32) {
            inMenu = true;
            currentMenuPage = 0;
            drawMenu();
          }
          // 3. Secret menu (double tap on logo x=0..120, y=0..32)
          else if (startX < 120 && startY < 32) {
            static unsigned long lastTap = 0;
            if (millis() - lastTap < 1000 && lastTap > 0) {
              inMenu = true;
              currentMenuPage = 99; // Secret Menu
              drawMenu();
              lastTap = 0;
            } else {
              lastTap = millis();
            }
          }
          // 4. Tap on status bar / page dots (y >= 210) toggles page cleanly
          else if (startY >= 210) {
            currentPage = (currentPage == 0) ? 1 : 0;
            drawDisplay(true);
            return;
          }
        } else {
          if (currentMenuPage == 0) {
            // WiFi Setup & Connection — left third button row (x=4..101, y=82..138)
            if (startX > 4 && startX < 101 && startY > 82 && startY < 138) {
              currentMenuPage = 4;
              drawMenu();
            }
            // NODE CONFIG — middle button (x=111..208)
            else if (startX > 111 && startX < 208 && startY > 82 && startY < 138) {
              currentMenuPage = 1;
              drawMenu();
            }
            // TANK CAL — right button (x=218..315)
            else if (startX > 218 && startX < 315 && startY > 82 && startY < 138) {
              currentMenuPage = 3;
              drawMenu();
            }
            // BACK — exit menu, full clean redraw
            else if (startY > 148 && startY < 186) {
              inMenu = false;
              isPairingMode = false;
              tft.fillScreen(COLOR_BG);
              lastRenderedPage = -1;
              drawDisplay(true);
              forceRedraw = false;
            }
          }
          else if (currentMenuPage == 1) {
            // ADD NODE (x=4..154, y=68..114)
            if (startX > 4 && startX < 154 && startY > 68 && startY < 114) {
              isPairingMode = true;
              discoveredNodeCount = 0;
              pairingCode = random(1000, 9999);
              pairingStartTime = millis();
              currentMenuPage = 2;
              broadcastBeacon(); // Send immediately so nodes appear without delay
              lastBeaconTime = millis();
              drawMenu();
            }
            // FORGET ALL (x=162..312, y=68..114)
            else if (startX > 162 && startX < 312 && startY > 68 && startY < 114) {
              for (int i = 0; i < MAX_NODES; i++) {
                if (nodes[i].paired && esp_now_is_peer_exist(nodes[i].mac))
                  esp_now_del_peer(nodes[i].mac);
                nodes[i].paired = false;
                nodes[i].distance = -1;
              }
              // Clear only paired node keys in NVS — DO NOT wipe calibration or WiFi!
              hubPrefs.begin("hub", false);
              hubPrefs.putInt("count", 0);
              for (int k = 0; k < MAX_NODES; k++) {
                char kName[10]; sprintf(kName, "mac%d", k);
                hubPrefs.remove(kName);
              }
              hubPrefs.end();
              invalidateCache = true;
              isPairingMode = false;
              drawMenu();
            }
            // BACK (y=128..166)
            else if (startY > 128 && startY < 166) {
              currentMenuPage = 0;
              drawMenu();
            }
          }
          else if (currentMenuPage == 2) {
              // PAIR tap — new PAIR button at x=238..314, rowY+5..rowY+35, rows spaced by 46px from y=32
              if (startX > 238 && startX < 314) {
                  for (int i = 0; i < discoveredNodeCount && i < 4; i++) {
                      int rowY = 32 + (i * 46);
                      if (startY > rowY+5 && startY < rowY+35) {
                          int slot = -1;
                          for (int s = 0; s < MAX_NODES; s++) {
                              if (!nodes[s].paired) { slot = s; break; }
                          }
                          if (slot != -1) {
                              memcpy(nodes[slot].mac, discoveredNodes[i].mac, 6);
                              nodes[slot].paired = true;
                              nodes[slot].lastRecvTime = millis();
                              nodes[slot].distance = -1;
                              if (esp_now_is_peer_exist(nodes[slot].mac)) esp_now_del_peer(nodes[slot].mac);
                              esp_now_peer_info_t peer = {};
                              memcpy(peer.peer_addr, nodes[slot].mac, 6);
                              peer.channel = 0;
                              peer.ifidx = isAPMode ? WIFI_IF_AP : WIFI_IF_STA;
                              peer.encrypt = false;
                              esp_now_add_peer(&peer);
                              PairingConfirm conf = {};
                              strncpy(conf.magic, "WLMSCONF", 8);
                              memcpy(conf.hubMAC, myMAC, 6);
                              conf.deviceId = discoveredNodes[i].deviceId;
                              conf.accepted = true;
                              conf.auth = pairAuth((uint8_t*)&conf, sizeof(PairingConfirm) - sizeof(conf.auth));
                              Serial.println("[HUB] TX: Sending WLMSCONF (PairingConfirm)");
                              esp_now_send(nodes[slot].mac, (uint8_t *)&conf, sizeof(PairingConfirm));
                              hubSaveNodes(); // ← persist to NVS
                              Serial.printf("[HUB] Paired node in slot %d — saved to NVS\n", slot+1);
                          }
                          isPairingMode = false;
                          currentMenuPage = 1;
                          drawMenu();
                          break;
                      }
                  }
              }
              // CANCEL — bottom strip y=216..238
              if (startY > 216 && startY < 238) {
                  isPairingMode = false;
                  currentMenuPage = 1;
                  drawMenu();
              }
          }
          else if (currentMenuPage == 3) {
            int rYs[4] = {28, 66, 104, 142};
            for (int r = 0; r < 4; r++) {
              int rY = rYs[r];
              if (startY >= rY && startY <= rY + 34) {
                if (startX > 220 && startX < 264) { // [+]
                  if (r == 0) tankEmptyMm    = constrain(tankEmptyMm + 50, 100, 5000);
                  else if (r == 1) tankFullMm   = constrain(tankFullMm + 10, 10, tankEmptyMm - 50);
                  else if (r == 2) sensorOffsetMm = constrain(sensorOffsetMm + 10, -500, 500);
                  else alertThreshold          = constrain(alertThreshold + 5, 5, 80);
                  hubSaveCalibration();
                  invalidateCache = true;
                  forceRedraw = true;
                  drawMenu();
                } else if (startX > 264 && startX < 308) { // [-]
                  if (r == 0) tankEmptyMm    = constrain(tankEmptyMm - 50, 100, 5000);
                  else if (r == 1) tankFullMm   = constrain(tankFullMm - 10, 10, tankEmptyMm - 50);
                  else if (r == 2) sensorOffsetMm = constrain(sensorOffsetMm - 10, -500, 500);
                  else alertThreshold          = constrain(alertThreshold - 5, 5, 80);
                  hubSaveCalibration();
                  invalidateCache = true;
                  forceRedraw = true;
                  drawMenu();
                }
              }
            }
            // BACK button (y=180..230) — auto-saves to NVS and returns
            if (startY >= 180 && startY <= 230) {
              hubSaveCalibration();
              currentMenuPage = 0;
              drawMenu();
            }
          }
          else if (currentMenuPage == 4) {
            if (hubSSID.length() > 0) {
              // Button 1: Connect or Reconnect (y=96..134)
              if (startY >= 96 && startY <= 134) {
                connectToSavedWifi();
              }
              // Button 2: Start Setup AP (y=138..176)
              else if (startY >= 138 && startY <= 176) {
                startWifiAP();
              }
              // Button 3 & 4 (y=182..222)
              else if (startY >= 182 && startY <= 222) {
                if (startX <= 158) {
                  // Forget WiFi
                  Preferences pr;
                  pr.begin("hub", false);
                  pr.remove("ssid");
                  pr.remove("pass");
                  pr.end();
                  hubSSID = "";
                  hubPASS = "";
                  WiFi.disconnect(true);
                  delay(300);
                  drawMenu();
                } else {
                  // Back
                  currentMenuPage = 0;
                  drawMenu();
                }
              }
            } else {
              // No saved WiFi
              // Button 1: Start Setup AP (y=100..154)
              if (startY >= 100 && startY <= 154) {
                startWifiAP();
              }
              // Button 2: Back (y=164..212)
              else if (startY >= 164 && startY <= 212) {
                currentMenuPage = 0;
                drawMenu();
              }
            }
          }
          else if (currentMenuPage == 99) {
            // TEST BUZZER (y=50..100)
            if (startY > 50 && startY < 100) {
              // Visual feedback: button turns red
              tft.fillRoundRect(8, 50, 304, 50, 6, COLOR_RED);
              tft.setTextColor(COLOR_WHITE);
              tft.setTextSize(2);
              tft.setCursor(95, 66);
              tft.print("TEST BUZZER");
              
              triggerBuzzerTest();
              
              drawMenu(); // restore original button color
            }
            // BACK (y=160..198)
            else if (startY > 160 && startY < 198) {
              currentMenuPage = 0;
              drawMenu();
            }
          }
        }
      } else if (!inMenu && duration < 500) {
        if (dx > 40) {
          currentPage = (currentPage == 1) ? 0 : 1;
          drawDisplay(true);
        } else if (dx < -40) {
          currentPage = (currentPage == 0) ? 1 : 0;
          drawDisplay(true);
        }
      }
    }
  }
}


void broadcastBeacon() {
  PairingBeacon b = {};
  strncpy(b.magic, "WLMSHUB", 8);
  memcpy(b.hubMAC, myMAC, 6);
  b.channel = PAIRING_CHANNEL;  // always tell node we're on pairing channel
  b.pairingCode = pairingCode;
  b.auth = pairAuth((uint8_t*)&b, sizeof(PairingBeacon) - sizeof(b.auth));
  
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  esp_now_send(broadcast, (uint8_t *)&b, sizeof(PairingBeacon));
}

String getDashboardHTML() {
  String html = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>AQUAPULSE Dashboard</title><style>";
  html += "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; text-align: center; background: #0f172a; color: #fff; margin:0; padding:20px; }";
  html += ".grid { display: flex; flex-wrap: wrap; justify-content: center; gap: 15px; margin: 20px 0; }";
  html += ".tank { width: 130px; padding: 15px; background: #1e293b; border-radius: 12px; border: 1px solid #334155; }";
  html += ".card { max-width: 440px; margin: 20px auto; padding: 20px; background: #1e293b; border-radius: 12px; text-align: left; }";
  html += "label { font-size: 13px; color: #94a3b8; display: block; margin-top: 10px; }";
  html += "input { width: 100%; padding: 8px; margin: 4px 0 10px; background: #0f172a; border: 1px solid #475569; color: #fff; border-radius: 6px; box-sizing: border-box; }";
  html += "button { width: 100%; padding: 12px; background: #0284c7; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; margin-top: 10px; }";
  html += "</style></head><body><h1>AQUAPULSE Dashboard</h1><div class='grid'>";
  for (int i=0; i<4; i++) {
    if (nodes[i].paired) {
      bool offline = (millis() - nodes[i].lastRecvTime > 10000);
      html += "<div class='tank'><h3>Node " + String(i+1) + "</h3>";
      long rawD = nodes[i].distance;
      if (rawD == -1 || offline) {
         html += "<p style='color:#f87171'>" + String(offline ? "OFFLINE" : "-- m") + "</p>";
      } else {
         long d = constrain(rawD + sensorOffsetMm, 0, 5000);
         html += "<p style='font-size:16px;'>Dist: <b>" + String(d / 1000.0, 2) + " m</b> (" + String(d) + " mm)</p>";
         int pct = map(d, tankEmptyMm, tankFullMm, 0, 100);
         pct = constrain(pct, 0, 100);
         bool isAlert = (pct <= alertThreshold);
         String pctColor = isAlert ? "#ef4444" : (pct < 50 ? "#f59e0b" : "#22c55e");
         html += "<p style='font-size:24px;font-weight:bold;color:" + pctColor + "'>" + String(pct) + "%" + (isAlert ? " <span style='font-size:12px;background:#ef4444;color:#fff;padding:2px 6px;border-radius:4px;'>ALERT</span>" : "") + "</p>";
      }
      html += "</div>";
    }
  }
  html += "</div>";
  html += "<div class='card'><h3>Tank & Sensor Calibration</h3>";
  html += "<form action='/savecalib' method='GET'>";
  html += "<label>Tank Empty Distance (mm):</label><input type='number' name='empty' value='" + String(tankEmptyMm) + "'>";
  html += "<label>Tank Full Distance (mm):</label><input type='number' name='full' value='" + String(tankFullMm) + "'>";
  html += "<label>Sensor Distance Offset (mm):</label><input type='number' name='offset' value='" + String(sensorOffsetMm) + "'>";
  html += "<label>Alert Threshold (%):</label><input type='number' name='alert' value='" + String(alertThreshold) + "'>";
  html += "<button type='submit'>Save Calibration</button></form></div>";
  html += "<div class='card'><h3>Hardware Diagnostics & Alarm</h3>";
  html += "<button type='button' style='background:#f59e0b;padding:10px 16px;border:none;border-radius:5px;color:white;font-weight:bold;cursor:pointer;' onclick=\"fetch('/testbuzzer').then(()=>alert('Buzzer test triggered!'))\">🔊 Test Hub Buzzer</button>";
  if (buzzerAlert) {
    if (!snoozeActive && !buzzerDismissed) {
      html += "<button type='button' style='background:#ef4444;margin-left:12px;padding:10px 16px;border:none;border-radius:5px;color:white;font-weight:bold;cursor:pointer;' onclick=\"fetch('/dismissbuzzer').then(()=>location.reload())\">🔕 Snooze 30m (" + String(currentAlertPercent) + "%)</button>";
    } else {
      unsigned long elapsed = millis() - snoozeStartTime;
      int remMin = (elapsed < SNOOZE_DURATION_MS) ? (int)((SNOOZE_DURATION_MS - elapsed + 59999UL) / 60000UL) : 0;
      html += "<button type='button' style='background:#2563eb;margin-left:12px;padding:10px 16px;border-radius:5px;color:white;font-weight:bold;cursor:pointer;border:none;' onclick=\"fetch('/dismissbuzzer').then(()=>location.reload())\">⏰ Snoozed (" + String(remMin) + "m left) - Un-snooze</button>";
    }
  }
  html += "</div>";
  html += "<br><a href='/pairing' style='color:#38bdf8'>Pairing Mode</a>";
  html += "</body></html>";
  return html;
}

String getPairingHTML() {
  return "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>WiFi Setup</title><style>"
         "body { font-family: Arial; text-align: center; background: #222; color: #fff; margin-top: 50px;}"
         ".btn { display: inline-block; padding: 15px 30px; background: #4DA6FF; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; }"
         "</style></head><body><h2>Node Pairing</h2>"
         "<p>1. Ensure this Hub is powered on.</p>"
         "<p>2. Power on the Node.</p>"
         "<p>3. The Node will automatically connect to this Hub's MAC address.</p>"
         "<a href='/' class='btn'>Back to Dashboard</a></body></html>";
}

String getAPSetupHTML() {
  String pg = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>AquaPulse WiFi Setup</title><style>";
  pg += "body{background:#0f172a;color:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:20px;text-align:center}";
  pg += ".box{max-width:380px;margin:20px auto;background:#1e293b;padding:24px;border-radius:12px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.5);text-align:left}";
  pg += "h2{margin-top:0;color:#38bdf8;font-size:22px;text-align:center;}";
  pg += "label{font-size:13px;color:#94a3b8;display:block;margin-top:14px;font-weight:600}";
  pg += "input{width:100%;padding:12px;margin:6px 0;box-sizing:border-box;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#fff;font-size:16px;}";
  pg += "button{width:100%;padding:14px;background:#0284c7;color:#fff;border:none;border-radius:8px;font-weight:bold;font-size:16px;cursor:pointer;margin-top:18px;}";
  pg += "button:hover{background:#0369a1}";
  pg += ".tip{background:#1e3a5f;border-left:4px solid #38bdf8;padding:8px 12px;border-radius:4px;font-size:12px;color:#cbd5e1;margin-top:16px;line-height:1.4;}";
  pg += "</style></head><body><div class='box'>";
  pg += "<h2>AquaPulse WiFi Setup</h2>";
  pg += "<p style='color:#94a3b8;font-size:14px;margin-bottom:15px;text-align:center;'>Connect Hub to your 2.4GHz home Wi-Fi network.</p>";
  pg += "<form action='/save' method='POST'>";
  pg += "<label>NETWORK NAME (SSID):</label>";
  pg += "<input id='sInp' name='s' value='" + hubSSID + "' placeholder='Enter your Wi-Fi name' required autofocus>";
  pg += "<label>WI-FI PASSWORD:</label>";
  pg += "<input name='p' placeholder='Enter Wi-Fi password' type='password'>";
  pg += "<button type='submit' onclick=\"this.innerText='Saving & Connecting...';\">Save & Connect Hub</button>";
  pg += "</form>";
  pg += "<div class='tip'><b>Note:</b> Please ensure your router broadcasts on 2.4GHz. Once saved, the Hub screen will show its assigned IP address.</div>";
  pg += "</div></body></html>";
  return pg;
}

void setupServerRoutes() {
  static bool routesSetup = false;
  if (routesSetup) return;
  routesSetup = true;

  // Root endpoint: In AP mode serve setup portal, in STA mode serve dashboard
  server.on("/", HTTP_ANY, []() {
    if (inAPSetup) {
      Serial.printf("[HUB-AP] Serving Setup Portal to client: %s\n",
                    server.client().remoteIP().toString().c_str());
      server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      server.sendHeader("Pragma", "no-cache");
      server.sendHeader("Expires", "-1");
      server.sendHeader("Connection", "close");
      server.send(200, "text/html; charset=utf-8", getAPSetupHTML());
    } else {
      server.send(200, "text/html", getDashboardHTML());
    }
  });

  // Fast 204 handler for icons so browsers don't block sockets waiting for icons
  auto handleIcon204 = []() {
    server.send(204, "text/plain", "");
  };
  server.on("/favicon.ico", HTTP_ANY, handleIcon204);
  server.on("/apple-touch-icon.png", HTTP_ANY, handleIcon204);
  server.on("/apple-touch-icon-precomposed.png", HTTP_ANY, handleIcon204);

  // Apple Captive Network Assistant probes
  auto handleAppleProbe = []() {
    if (inAPSetup) {
      Serial.println("[HUB-AP] Apple CNA probe -> Serving Setup Portal");
      server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      server.sendHeader("Pragma", "no-cache");
      server.sendHeader("Expires", "-1");
      server.sendHeader("Connection", "close");
      server.send(200, "text/html; charset=utf-8", getAPSetupHTML());
    } else {
      server.send(200, "text/html", getDashboardHTML());
    }
  };
  server.on("/hotspot-detect.html", HTTP_ANY, handleAppleProbe);
  server.on("/canonical.html", HTTP_ANY, handleAppleProbe);

  // Android / Chrome Captive Portal probes: 302 Redirect to http://192.168.4.1/
  auto handleAndroidProbe = []() {
    if (inAPSetup) {
      Serial.println("[HUB-AP] Android captive probe -> 302 Redirect to 192.168.4.1");
      server.sendHeader("Location", "http://192.168.4.1/", true);
      server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      server.sendHeader("Connection", "close");
      server.send(302, "text/html", "<!DOCTYPE html><html><head><meta http-equiv='refresh' content='0;url=http://192.168.4.1/'></head><body><a href='http://192.168.4.1/'>AquaPulse WiFi Setup</a></body></html>");
    } else {
      server.send(204, "text/plain", "");
    }
  };
  server.on("/generate_204", HTTP_ANY, handleAndroidProbe);
  server.on("/gen_204", HTTP_ANY, handleAndroidProbe);

  // Windows probes
  server.on("/ncsi.txt", HTTP_ANY, []() {
    server.send(200, "text/plain", "Microsoft NCSI");
  });
  server.on("/connecttest.txt", HTTP_ANY, []() {
    if (inAPSetup) {
      server.sendHeader("Location", "http://192.168.4.1/", true);
      server.sendHeader("Connection", "close");
      server.send(302, "text/html", "<meta http-equiv='refresh' content='0;url=http://192.168.4.1/'>");
    } else {
      server.send(200, "text/plain", "Microsoft Connect Test");
    }
  });

  // Save WiFi credentials
  auto handleSaveWifi = []() {
    String s = server.hasArg("s") ? server.arg("s") : "";
    String p = server.hasArg("p") ? server.arg("p") : "";
    s.trim();
    p.trim();
    Serial.printf("[HUB-AP] Received WiFi credentials: SSID='%s'\n", s.c_str());
    String resp = "<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><style>body{background:#0f172a;color:#fff;font-family:sans-serif;text-align:center;padding:40px;}</style></head><body>";
    resp += "<h2 style='color:#22c55e'>Credentials Saved!</h2><p>Connecting Hub to <b>" + s + "</b>...</p><p style='color:#94a3b8'>Please look at the Hub screen.</p></body></html>";
    server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    server.sendHeader("Connection", "close");
    server.send(200, "text/html; charset=utf-8", resp);

    if (s.length() > 0) {
      Preferences pr;
      pr.begin("hub", false);
      pr.putString("ssid", s);
      pr.putString("pass", p);
      pr.end();
      hubSSID = s;
      hubPASS = p;
      newCredentialsSaved = true;
    }
    // Allow response packets to fully flush to client before closing AP!
    delay(1000);
    inAPSetup = false;
  };

  server.on("/save", HTTP_ANY, handleSaveWifi);
  server.on("/savewifi", HTTP_ANY, handleSaveWifi);

  server.on("/pairing", []() { server.send(200, "text/html", getPairingHTML()); });
  server.on("/testbuzzer", []() {
    triggerBuzzerTest();
    server.send(200, "text/plain", "Buzzer Test Executed!");
  });
  server.on("/dismissbuzzer", []() {
    toggleSnooze();
    server.send(200, "text/plain", snoozeActive ? "Buzzer Snoozed for 30m" : "Snooze Cancelled / Unmuted");
  });
  server.on("/savecalib", []() {
    if (server.hasArg("empty"))  tankEmptyMm    = constrain(server.arg("empty").toInt(), 100, 5000);
    if (server.hasArg("full"))   tankFullMm     = constrain(server.arg("full").toInt(), 10, tankEmptyMm - 10);
    if (server.hasArg("offset")) sensorOffsetMm = constrain(server.arg("offset").toInt(), -500, 500);
    if (server.hasArg("alert"))  alertThreshold = constrain(server.arg("alert").toInt(), 5, 80);
    hubSaveCalibration();
    invalidateCache = true;
    forceRedraw = true;
    server.send(200, "text/html", "<!DOCTYPE html><html><head><meta http-equiv='refresh' content='2;url=/'><style>body{background:#0f172a;color:#fff;font-family:sans-serif;text-align:center;padding:50px}</style></head><body><h2>Calibration Saved!</h2><p>Redirecting to dashboard...</p></body></html>");
  });

  server.onNotFound([]() {
    if (inAPSetup) {
      String uri = server.uri();
      Serial.printf("[HUB-AP] onNotFound: Host='%s', URI='%s', Client=%s\n",
                    server.hostHeader().c_str(), uri.c_str(),
                    server.client().remoteIP().toString().c_str());

      // If it's an image or static asset, return 204
      if (uri.endsWith(".ico") || uri.endsWith(".png") || uri.endsWith(".jpg") || uri.endsWith(".svg")) {
        server.send(204, "text/plain", "");
        return;
      }

      // If external domain request (captive portal redirect needed)
      String host = server.hostHeader();
      if (!host.startsWith("192.168.4.1")) {
        server.sendHeader("Location", "http://192.168.4.1/", true);
        server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        server.sendHeader("Connection", "close");
        server.send(302, "text/html", "<!DOCTYPE html><html><head><meta http-equiv='refresh' content='0;url=http://192.168.4.1/'></head><body><p>Redirecting to <a href='http://192.168.4.1/'>AquaPulse WiFi Setup</a>...</p></body></html>");
      } else {
        // Direct access to 192.168.4.1 with any path -> directly serve setup HTML!
        server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        server.sendHeader("Pragma", "no-cache");
        server.sendHeader("Expires", "-1");
        server.sendHeader("Connection", "close");
        server.send(200, "text/html; charset=utf-8", getAPSetupHTML());
      }
    } else {
      server.send(404, "text/plain", "Not Found");
    }
  });
}

void initWebServer() {
  setupServerRoutes();
  if (!serverInitialized) {
    server.begin();
    serverInitialized = true;
    Serial.printf("[HUB] WebServer online! IP: %s\n", WiFi.localIP().toString().c_str());
  }
}

uint16_t getDistColor(int percent) {
  if (percent <= alertThreshold) return COLOR_RED;
  if (percent < 50) return COLOR_ORANGE;
  return COLOR_ACCENT;
}

void updatePage0() {
  static bool lastPaired[4] = {false};
  static bool lastOffline[4] = {false};
  static int lastDist[4] = {-1, -1, -1, -1};
  static int lastPercent[4] = {-1, -1, -1, -1};

  if (invalidateCache) {
    for (int i=0; i<4; i++) { lastPaired[i] = !nodes[i].paired; }
  }

  int xs[] = {2, 162, 2, 162};
  int ys[] = {34, 34, 137, 137};
  
  for (int i=0; i<activeNodeCount(); i++) {
    int x = xs[i], y = ys[i];
    
    bool offline = (millis() - nodes[i].lastRecvTime > 10000);
    int rawDist = nodes[i].distance;
    int dist = rawDist != -1 ? constrain(rawDist + sensorOffsetMm, 0, 5000) : -1;
    int percent = 0;
    if (dist != -1) {
      percent = map(dist, tankEmptyMm, tankFullMm, 0, 100);
      percent = constrain(percent, 0, 100);
    }
    
    if (nodes[i].paired == lastPaired[i] && 
        offline == lastOffline[i] && 
        dist == lastDist[i] && 
        percent == lastPercent[i]) {
      continue;
    }
    
    lastPaired[i] = nodes[i].paired;
    lastOffline[i] = offline;
    lastDist[i] = dist;
    lastPercent[i] = percent;

    if (!nodes[i].paired) {
        tft.fillRect(x, y, 156, 78, COLOR_DARK_GRAY);
        tft.setTextSize(2);
        tft.setTextColor(COLOR_CYAN, COLOR_DARK_GRAY);
        tft.setCursor(x+4, y+4);
        tft.print("Node "); tft.print(i + 1);
        tft.setTextColor(COLOR_ORANGE, COLOR_DARK_GRAY);
        tft.setCursor(x+4, y+30);
        tft.print("Unpaired    ");
        tft.setCursor(x+4, y+50);
        tft.print("            ");
        continue;
    }
    
    if (offline) {
        tft.fillRect(x, y, 156, 78, COLOR_DARK_GRAY);
        tft.setTextSize(2);
        tft.setTextColor(COLOR_CYAN, COLOR_DARK_GRAY);
        tft.setCursor(x+4, y+4);
        tft.print("Node "); tft.print(i + 1);
        tft.setTextColor(COLOR_RED, COLOR_DARK_GRAY);
        tft.setCursor(x+4, y+30);
        tft.print("Offline     ");
        tft.setCursor(x+4, y+50);
        tft.print("            ");
        continue;
    }
    
    bool isAlerting = nodes[i].paired && !offline && (dist != -1) && (percent <= alertThreshold);

    uint16_t pctColor;
    if (dist == -1) {
      pctColor = COLOR_DARK_GRAY;
    } else if (isAlerting) {
      pctColor = COLOR_RED; // BRIGHT RED for the tank causing the alert!
    } else if (percent < 50) {
      pctColor = COLOR_ORANGE;
    } else {
      pctColor = COLOR_ACCENT; // Green
    }

    // Card background
    tft.fillRoundRect(x, y, 156, 80, 6, COLOR_DARK_GRAY);

    // If this tank is causing the alert, highlight with a BRIGHT RED double border!
    if (isAlerting) {
      tft.drawRoundRect(x, y, 156, 80, 6, COLOR_RED);
      tft.drawRoundRect(x+1, y+1, 154, 78, 5, COLOR_RED);
    }

    // Node header: RED if alerting, else CYAN
    tft.setTextSize(2);
    tft.setTextColor(isAlerting ? COLOR_RED : COLOR_CYAN, COLOR_DARK_GRAY);
    tft.setCursor(x+4, y+4);
    tft.print("Node "); tft.print(i + 1);

    // Distance
    tft.setTextSize(2);
    tft.setTextColor(dist == -1 ? COLOR_DARK_GRAY : (isAlerting ? COLOR_RED : COLOR_CYAN), COLOR_DARK_GRAY);
    tft.setCursor(x+4, y+28);
    char buf[16];
    if (dist == -1) sprintf(buf, "--    ");
    else sprintf(buf, "%.2f m  ", dist / 1000.0);
    tft.print(buf);

    // Percentage: BRIGHT RED for tank causing alert!
    tft.setTextSize(3);
    tft.setTextColor(pctColor, COLOR_DARK_GRAY);
    tft.setCursor(x+4, y+50);
    if (dist == -1) sprintf(buf, "--%%   ");
    else sprintf(buf, "%d%%   ", percent);
    tft.print(buf);
  }
}

void drawPage0(bool fullRedraw) {
  if (fullRedraw) {
    tft.fillRect(0, 32, 320, 188, COLOR_BG);
    int cellW = 156, cellH = 80;
    int xs[] = {2, 162, 2, 162};
    int ys[] = {34, 34, 137, 137};
    
    for (int i=0; i<activeNodeCount(); i++) {
      int x = xs[i], y = ys[i];
      tft.fillRoundRect(x, y, cellW, cellH, 6, COLOR_DARK_GRAY);
      tft.setTextSize(2);
      tft.setTextColor(COLOR_CYAN, COLOR_DARK_GRAY);
      tft.setCursor(x+4, y+4);
      tft.print("Node ");
      tft.print(i + 1);
    }
    invalidateCache = true;
  }
  updatePage0();
  invalidateCache = false;
}

// ── Helper: draw one tank cell cleanly ─────────────────────────────────────
void drawTankCell(int x, int y, int tankW, int tankH, int percent, bool paired, bool offline, int nodeIdx) {
  int rawDist = nodes[nodeIdx].distance;
  int dist = rawDist != -1 ? constrain(rawDist + sensorOffsetMm, 0, 5000) : -1;
  bool isAlerting = paired && !offline && (dist != -1) && (percent <= alertThreshold);

  uint16_t fillColor = (dist == -1) ? COLOR_DARK_GRAY : (isAlerting ? COLOR_RED : getDistColor(percent));

  // Outer border: BRIGHT RED for tank causing alert!
  uint16_t borderColor = offline ? COLOR_RED : (isAlerting ? COLOR_RED : (paired && dist != -1 ? fillColor : COLOR_DARK_GRAY));
  tft.drawRoundRect(x, y, tankW, tankH, 5, borderColor);
  tft.drawRoundRect(x+1, y+1, tankW-2, tankH-2, 4, borderColor); // double border for thickness

  int innerX = x+3, innerY = y+3, innerW = tankW-6, innerH = tankH-6;

  if (!paired) {
    tft.fillRect(innerX, innerY, innerW, innerH, COLOR_BG);
    tft.setTextSize(1);
    tft.setTextColor(COLOR_ORANGE, COLOR_BG);
    int tx = innerX + (innerW - 6*6)/2; // center "UNPAIR"
    tft.setCursor(tx, y + tankH/2 - 4);
    tft.print("UNPAIR");
    return;
  }

  if (offline) {
    tft.fillRect(innerX, innerY, innerW, innerH, COLOR_BG);
    // Draw X pattern for offline
    tft.setTextSize(1);
    tft.setTextColor(COLOR_RED, COLOR_BG);
    tft.setCursor(innerX + innerW/2 - 12, y + tankH/2 - 4);
    tft.print("OFFLIN");
    return;
  }

  // Air section (empty part) — draw above fill line
  int fillH = (innerH * percent) / 100;
  int airH  = innerH - fillH;
  tft.fillRect(innerX, innerY, innerW, airH, COLOR_BG);

  // Water fill
  if (fillH > 0) {
    tft.fillRoundRect(innerX, innerY + airH, innerW, fillH, 3, fillColor);
    // Highlight shimmer line (1px lighter stripe near top of fill)
    if (fillH > 4) {
      tft.drawFastHLine(innerX+2, innerY + airH + 2, innerW-4, 0xFFFF);
    }
  }

  // Tick marks on the border (25%, 50%, 75%)
  for (int tick = 25; tick <= 75; tick += 25) {
    int tickY = innerY + innerH - (innerH * tick) / 100;
    tft.drawFastHLine(x, tickY, 4, 0x4208); // dim grey ticks on left
  }
}

void updatePage1() {
  static bool lastPaired[4]  = {false};
  static bool lastOffline[4] = {false};
  static int  lastPercent[4] = {-1, -1, -1, -1};

  if (invalidateCache) {
    for (int i = 0; i < 4; i++) {
      lastPaired[i] = !nodes[i].paired;
      lastOffline[i] = false;
      lastPercent[i] = -999;
    }
  }

  // Layout: up to 4 tanks side by side
  // Responsive widths based on count:
  //  4: tankW=64  spacing=80  startX=0
  //  3: tankW=80  spacing=100 startX=10
  //  2: tankW=110 spacing=140 startX=20
  //  1: tankW=150            startX=85
  int tankW, spacing, startX;
  int tankH = 154; // header ends y=31, label 14px, tank, pct 14px, status at y=220
  int y = 50;      // labels draw at y-14=36, just below header line

  switch(activeNodeCount()) {
    case 4: tankW=64;  spacing=80;  startX=0;   break;
    case 3: tankW=80;  spacing=100; startX=10;  break;
    case 2: tankW=110; spacing=140; startX=20;  break;
    default: tankW=150; spacing=0;  startX=85;  break;
  }

  for (int i = 0; i < activeNodeCount(); i++) {
    int x = startX + i * spacing;

    bool offline = (millis() - nodes[i].lastRecvTime > 10000);
    int rawDist  = nodes[i].distance;
    int dist     = rawDist != -1 ? constrain(rawDist + sensorOffsetMm, 0, 5000) : -1;
    int percent  = 0;
    if (dist != -1 && nodes[i].paired) {
      percent = map(dist, tankEmptyMm, tankFullMm, 0, 100);
      percent = constrain(percent, 0, 100);
    }

    bool changed = (nodes[i].paired != lastPaired[i] ||
                    offline         != lastOffline[i] ||
                    percent         != lastPercent[i]);
    if (!changed) continue;

    lastPaired[i]  = nodes[i].paired;
    lastOffline[i] = offline;
    lastPercent[i] = percent;

    // Draw tank body
    drawTankCell(x, y, tankW, tankH, percent, nodes[i].paired, offline, i);

    // Label above tank
    tft.fillRect(x, y - 16, tankW, 14, COLOR_BG);
    tft.setTextSize(1);
    tft.setTextColor(COLOR_CYAN, COLOR_BG);
    tft.setCursor(x + tankW/2 - 18, y - 14);
    tft.print("NODE "); tft.print(i+1);

    // Percentage below tank — BRIGHT RED for the tank causing the alert!
    bool isAlerting = nodes[i].paired && !offline && (dist != -1) && (percent <= alertThreshold);
    tft.fillRect(x, y + tankH + 2, tankW, 16, COLOR_BG);
    tft.setTextSize(2); // Bold size 2 font for clear visibility
    uint16_t col;
    if (!nodes[i].paired || offline || dist == -1) {
      col = COLOR_DARK_GRAY;
    } else if (isAlerting) {
      col = COLOR_RED; // BRIGHT RED for tank causing alert!
    } else if (percent < 50) {
      col = COLOR_ORANGE;
    } else {
      col = COLOR_ACCENT; // Green
    }
    tft.setTextColor(col, COLOR_BG);
    char buf[10];
    if (!nodes[i].paired) strcpy(buf, "--");
    else if (offline)     strcpy(buf, "OFF");
    else if (dist == -1)  strcpy(buf, "--");
    else sprintf(buf, "%d%%", percent);
    int txtW = strlen(buf) * 12; // 12px per char in size 2
    tft.setCursor(x + (tankW - txtW)/2, y + tankH + 2);
    tft.print(buf);
  }
}

void drawPage1(bool fullRedraw) {
  if (fullRedraw) {
    tft.fillRect(0, 32, 320, 188, COLOR_BG);
    invalidateCache = true;
  }
  updatePage1();
  invalidateCache = false;
}


void drawStatusBar(bool fullRedraw) {
  if (fullRedraw) {
    tft.fillRect(0, 220, 320, 20, COLOR_DARK_GRAY);
    tft.setTextSize(2);
    tft.setTextColor(COLOR_WHITE, COLOR_DARK_GRAY);
    tft.setCursor(10, 222);
    if (currentPage == 0) tft.print("o .");
    else tft.print(". o");
    tft.setCursor(90, 222);
    tft.print("Nodes:");
  }

  // Node count
  int pCount = activeNodeCount();
  tft.setTextSize(2);
  tft.setTextColor(COLOR_ACCENT, COLOR_DARK_GRAY);
  tft.setCursor(175, 222);
  char nc[4]; sprintf(nc, "%d ", pCount);
  tft.print(nc);

  // WiFi indicator (x=202..260)
  tft.setCursor(202, 226);
  tft.setTextSize(1);
  if (WiFi.status() == WL_CONNECTED) {
    tft.setTextColor(0x07E0, COLOR_DARK_GRAY); // bright green
    tft.print("WiFi:OK");
  } else if (hubSSID.length() > 0) {
    tft.setTextColor(COLOR_ORANGE, COLOR_DARK_GRAY);
    tft.print("WiFi:--");
  } else {
    tft.setTextColor(COLOR_DARK_GRAY, COLOR_DARK_GRAY);
    tft.print("       ");
  }

  // Clock — textSize=1: each char=6px, "HH:MM:SS"=48px, x=268..316 (inside 320)
  unsigned long upSec = (millis() - startTime) / 1000;
  char buf[12];
  sprintf(buf, "%02lu:%02lu:%02lu", upSec/3600, (upSec%3600)/60, upSec%60);
  tft.setTextSize(1);
  tft.setTextColor(COLOR_CYAN, COLOR_DARK_GRAY);
  tft.setCursor(268, 226);
  tft.print(buf);
}

void drawDisplay(bool fullRedraw) {
  // If active page changed, enforce a complete canvas wipe and clean re-render
  if (currentPage != lastRenderedPage) {
    fullRedraw = true;
    lastRenderedPage = currentPage;
  }
  if (fullRedraw) {
    drawHeader();
    tft.fillRect(0, 32, 320, 188, COLOR_BG);
    invalidateCache = true;
  }
  if (currentPage == 0) drawPage0(fullRedraw);
  else drawPage1(fullRedraw);
  drawStatusBar(fullRedraw);
}

void setup() {
  Serial.begin(115200);
  startTime = millis();

  // Load tank calibration immediately from NVS at startup
  hubLoadCalibration();

  for (int i=0; i<MAX_NODES; i++) {
    nodes[i].paired = false;
    nodes[i].distance = -1;
    nodes[i].lastRecvTime = 0;
  }

  pinMode(TRANSISTOR_PIN, OUTPUT);
  digitalWrite(TRANSISTOR_PIN, LOW);

  pinMode(17, OUTPUT);
  digitalWrite(17, HIGH);
  setBrightness(255);

  tft.init();
  tft.setRotation(1);
  tft.invertDisplay(false);
  uint16_t calData[5] = { 275, 3620, 264, 3532, 1 };
  tft.setTouch(calData);
  
  tft.fillScreen(COLOR_BG);

  // Startup chirp (100ms) to confirm buzzer works without delaying boot
  digitalWrite(TRANSISTOR_PIN, HIGH);
  delay(100);
  digitalWrite(TRANSISTOR_PIN, LOW);

  // ── AQUAPULSE Splash Animation ───────────────────────────────────────────
  // 1. Fade-in water rising from bottom
  for (int h = 0; h <= 240; h += 8) {
    tft.fillRect(0, 240 - h, 320, 8, 0x0419); // deep blue
    delay(12);
  }
  // 2. Draw title with glow layers
  tft.setTextSize(4);
  // shadow
  tft.setTextColor(0x0212);
  tft.setCursor(17, 82); tft.print("AQUAPULSE");
  // glow
  tft.setTextColor(0x055F);
  tft.setCursor(15, 80); tft.print("AQUAPULSE");
  // main text
  tft.setTextColor(0x07FF); // bright cyan
  tft.setCursor(16, 80); tft.print("AQUAPULSE");

  // Subtitle
  tft.setTextSize(1);
  tft.setTextColor(COLOR_ACCENT, COLOR_BG);
  tft.setCursor(88, 120);
  tft.print("Water Level Monitor v3");

  // 3. Animated progress bar
  tft.drawRoundRect(20, 145, 280, 14, 7, COLOR_DARK_GRAY);
  for (int p = 0; p <= 280; p += 5) {
    uint16_t c = tft.color565(0, p/2, 200);
    tft.fillRoundRect(21, 146, p-1, 12, 6, c);
    delay(8);
  }
  tft.setTextColor(0xFFFF, COLOR_BG);
  tft.setCursor(110, 165); tft.print("Initialising...");
  delay(400);

  
  WiFi.macAddress(myMAC);
  pairingCode = (myMAC[4] << 8) | myMAC[5];

  hubPrefs.begin("hub", true);
  hubSSID = hubPrefs.getString("ssid", "");
  hubPASS = hubPrefs.getString("pass", "");
  hubPrefs.end();
  
  tft.fillScreen(COLOR_BG);
  tft.setCursor(10, 100);
  tft.setTextColor(COLOR_WHITE);
  
  bool connected = false;
  if (hubSSID.length() > 0) {
    tft.println("Connecting to WiFi:");
    tft.setTextColor(COLOR_ACCENT);
    tft.println(hubSSID);
    
    WiFi.mode(WIFI_STA);
    WiFi.begin(hubSSID.c_str(), hubPASS.c_str());
    unsigned long t = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t < 10000) {
      delay(300);
      tft.print(".");
    }
    connected = (WiFi.status() == WL_CONNECTED);
  }
  
  if (connected) {
    isAPMode = false;
    tft.println("\nConnected!");
    tft.print("IP: "); tft.println(WiFi.localIP());
    delay(800);
    initWebServer();
  } else {
    // No WiFi configured – start normally without blocking.
    // User can set up or connect to WiFi anytime from the menu.
    isAPMode = false;
    WiFi.mode(WIFI_STA); // Needed for ESP-NOW on channel
    esp_wifi_set_channel(PAIRING_CHANNEL, WIFI_SECOND_CHAN_NONE);
    tft.println("\nNo WiFi - ESP-NOW only");
    tft.println("(Connect anytime via Menu)");
    delay(600);
  }

  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    delay(3000);
    ESP.restart();
  } else {
    espNowOk = true;
    esp_now_register_recv_cb(OnDataRecv);
    
    // Broadcast peer for beacon/pairing
    esp_now_peer_info_t bcast = {};
    memset(bcast.peer_addr, 0xFF, 6);
    bcast.channel = 0;
    bcast.ifidx = isAPMode ? WIFI_IF_AP : WIFI_IF_STA;
    bcast.encrypt = false;
    esp_now_add_peer(&bcast);

    // Load saved nodes and calibration from NVS
    hubLoadNodes();
    hubLoadCalibration();
    for (int i = 0; i < MAX_NODES; i++) {
      if (nodes[i].paired) {
        esp_now_peer_info_t peer = {};
        memcpy(peer.peer_addr, nodes[i].mac, 6);
        peer.channel = 0; // Use current channel
        peer.ifidx = isAPMode ? WIFI_IF_AP : WIFI_IF_STA;
        peer.encrypt = false;
        esp_now_add_peer(&peer);
      }
    }
  }

  drawHeader();
  drawDisplay(forceRedraw);
}

void loop() {
  if (WiFi.status() == WL_CONNECTED && serverInitialized) {
    ArduinoOTA.handle();
    server.handleClient();
  }
  handleTouch();
  updateBuzzer(); // non-blocking buzzer driver

  // Refresh header minute countdown if snoozed
  static int lastSnoozeMin = -1;
  if (snoozeActive) {
    unsigned long elapsed = millis() - snoozeStartTime;
    int remMin = (elapsed < SNOOZE_DURATION_MS) ? (int)((SNOOZE_DURATION_MS - elapsed + 59999UL) / 60000UL) : 0;
    if (remMin != lastSnoozeMin) {
      lastSnoozeMin = remMin;
      if (!inMenu) drawHeader();
    }
  }

  // Serial commands for testing
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.equalsIgnoreCase("b") || cmd.equalsIgnoreCase("beep") || cmd.equalsIgnoreCase("test buzzer") || cmd.equalsIgnoreCase("buzzer") || cmd.equalsIgnoreCase("test")) {
      triggerBuzzerTest();
    } else if (cmd.equalsIgnoreCase("d") || cmd.equalsIgnoreCase("dismiss") || cmd.equalsIgnoreCase("mute") || cmd.equalsIgnoreCase("snooze") || cmd.equalsIgnoreCase("snz")) {
      toggleSnooze();
    } else if (cmd.equalsIgnoreCase("wifi") || cmd.equalsIgnoreCase("wifistatus")) {
      Serial.printf("[HUB] WiFi Status: %s, SSID: '%s', IP: %s, RSSI: %d dBm\n",
                    (WiFi.status() == WL_CONNECTED) ? "CONNECTED" : "DISCONNECTED",
                    hubSSID.c_str(), WiFi.localIP().toString().c_str(), WiFi.RSSI());
    } else if (cmd.equalsIgnoreCase("wifi connect") || cmd.equalsIgnoreCase("wificonnect")) {
      Serial.println("[HUB] Connecting to saved WiFi...");
      connectToSavedWifi();
    } else if (cmd.equalsIgnoreCase("wifi setup") || cmd.equalsIgnoreCase("wifisetup") || cmd.equalsIgnoreCase("ap")) {
      Serial.println("[HUB] Starting WiFi setup AP...");
      startWifiAP();
    } else if (cmd.startsWith("wifi set ") || cmd.startsWith("set wifi ")) {
      String rest = cmd.startsWith("set wifi ") ? cmd.substring(9) : cmd.substring(9);
      rest.trim();
      int sp = rest.indexOf(' ');
      String s = "", p = "";
      if (sp > 0) {
        s = rest.substring(0, sp);
        p = rest.substring(sp + 1);
      } else {
        s = rest;
        p = "";
      }
      s.trim();
      p.trim();
      if (s.length() > 0) {
        Preferences pr;
        pr.begin("hub", false);
        pr.putString("ssid", s);
        pr.putString("pass", p);
        pr.end();
        hubSSID = s;
        hubPASS = p;
        Serial.printf("[HUB] Saved WiFi to NVS: SSID='%s', connecting...\n", hubSSID.c_str());
        connectToSavedWifi();
      }
    } else if (cmd.equalsIgnoreCase("save") || cmd.equalsIgnoreCase("savecalib")) {
      hubSaveCalibration();
      Serial.println("[HUB] Tank config successfully saved into NVS!");
    } else if (cmd.equalsIgnoreCase("calib") || cmd.equalsIgnoreCase("config") || cmd.equalsIgnoreCase("tank")) {
      Serial.printf("[HUB] Tank Config in NVS: Empty=%d mm, Full=%d mm, Offset=%d mm, Alert=%d%%\n",
                    tankEmptyMm, tankFullMm, sensorOffsetMm, alertThreshold);
    } else if (cmd.startsWith("set empty ")) {
      tankEmptyMm = constrain(cmd.substring(10).toInt(), 100, 5000);
      hubSaveCalibration();
      invalidateCache = true; forceRedraw = true;
    } else if (cmd.startsWith("set full ")) {
      tankFullMm = constrain(cmd.substring(9).toInt(), 10, tankEmptyMm - 10);
      hubSaveCalibration();
      invalidateCache = true; forceRedraw = true;
    } else if (cmd.startsWith("set alert ")) {
      alertThreshold = constrain(cmd.substring(10).toInt(), 5, 80);
      hubSaveCalibration();
      invalidateCache = true; forceRedraw = true;
    } else if (cmd.startsWith("set offset ")) {
      sensorOffsetMm = constrain(cmd.substring(11).toInt(), -500, 500);
      hubSaveCalibration();
      invalidateCache = true; forceRedraw = true;
    }
  }

  // Startup beacons (10s window after boot) so pre-existing nodes can re-sync
  if (startupBeaconActive) {
    if (millis() - startupBeaconStart < 10000) {
      if (millis() - lastStartupBeacon > 500) {
        lastStartupBeacon = millis();
        broadcastBeacon();
      }
    } else {
      startupBeaconActive = false;
      Serial.println("[HUB] Startup beacon window closed");
    }
  }

  if (inMenu) {
    if (currentMenuPage == 2) {
      // Fast 300ms beacons during pairing mode
      if (millis() - lastBeaconTime > 300) {
        broadcastBeacon();
        lastBeaconTime = millis();
      }
      // Periodic redraw for dot animation (every 400ms) + when node found
      static unsigned long lastScanRedraw = 0;
      if (forceRedraw || millis() - lastScanRedraw > 400) {
        lastScanRedraw = millis();
        forceRedraw = false;
        drawMenu();
      }
    }
    return;
  }

  // Redraw display when data changed or page switched
  if (forceRedraw || currentPage != lastRenderedPage) {
    checkAlerts();        // Evaluate if any node is below alertThreshold
    drawDisplay(false);   // will automatically do fullRedraw if currentPage != lastRenderedPage
    forceRedraw = false;
  }

  // Clock ticks every second — textSize=1, x=268..316, safely inside 320px
  static unsigned long lastClockTick = 0;
  if (millis() - lastClockTick > 1000) {
    lastClockTick = millis();
    unsigned long upSec = (millis() - startTime) / 1000;
    char buf[12];
    sprintf(buf, "%02lu:%02lu:%02lu", upSec/3600, (upSec%3600)/60, upSec%60);
    tft.setTextSize(1);
    tft.setTextColor(COLOR_CYAN, COLOR_DARK_GRAY);
    tft.setCursor(268, 226);
    tft.print(buf);
    
    // Safety fallback: evaluate alerts on clock tick in case a node dropped offline
    checkAlerts();
  }
}
#endif // HUB_RS485_SENSOR

