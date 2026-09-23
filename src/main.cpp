#include <Arduino.h>
#include <WiFi.h>
#include <ArduinoOTA.h>

#define PAIRING_CHANNEL 1

typedef struct __attribute__((packed)) {
    uint8_t deviceId;
    int distance;
    unsigned long timestamp;
} SensorData;

typedef struct __attribute__((packed)) {
    char magic[8];
    uint8_t hubMAC[6];
    uint8_t channel;
    uint16_t pairingCode;
} PairingBeacon;

typedef struct __attribute__((packed)) {
    char magic[8];
    uint8_t sensorMAC[6];
    uint8_t deviceId;
    uint16_t pairingCode;
} PairingRequest;

typedef struct __attribute__((packed)) {
    char magic[8];
    uint8_t hubMAC[6];
    uint8_t deviceId;
    bool accepted;
} PairingConfirm;

#ifdef NODE_DYP_SENSOR

#include <esp_now.h>
#include <esp_wifi.h>
#include <HardwareSerial.h>
#include <Preferences.h>

#define DYP_RX D2
#define DYP_TX D1
HardwareSerial dypSerial(1);

uint8_t hubMAC[6];
bool paired = false;
uint16_t pairingCode = 0;
uint8_t myDeviceId = 1; 
uint8_t myMAC[6];

unsigned long lastSend = 0;
unsigned char dypData[4] = {};
int sendFailures = 0;          // consecutive send failures
Preferences nodePrefs;

void nodeLoadNVS() {
  nodePrefs.begin("node", true); // read-only
  paired = nodePrefs.getBool("paired", false);
  if (paired) {
    nodePrefs.getBytes("hubMAC", hubMAC, 6);
    pairingCode = nodePrefs.getUShort("code", 0);
  }
  nodePrefs.end();
}

void nodeSaveNVS() {
  nodePrefs.begin("node", false);
  nodePrefs.putBool("paired", paired);
  nodePrefs.putBytes("hubMAC", hubMAC, 6);
  nodePrefs.putUShort("code", pairingCode);
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

void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  Serial.print("[NODE] Send Status: ");
  Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Success" : "Fail");
}

void OnDataRecv(const uint8_t *mac, const uint8_t *incomingData, int len) {
  if (paired) return; // Ignore if already paired

  if (len == sizeof(PairingBeacon)) {
    PairingBeacon *beacon = (PairingBeacon *)incomingData;
    if (strncmp(beacon->magic, "WLMSHUB", 8) == 0) {
      Serial.println("[NODE] Found Hub Beacon — sending pairing request");
      memcpy(hubMAC, beacon->hubMAC, 6);
      pairingCode = beacon->pairingCode;
      
      if (!esp_now_is_peer_exist(hubMAC)) {
        esp_now_peer_info_t peerInfo = {};
        memcpy(peerInfo.peer_addr, hubMAC, 6);
        peerInfo.channel = PAIRING_CHANNEL;
        peerInfo.encrypt = false;
        esp_now_add_peer(&peerInfo);
      }

      PairingRequest req;
      strncpy(req.magic, "WLMSREQ", 8);
      memcpy(req.sensorMAC, myMAC, 6);
      req.deviceId = myDeviceId;
      req.pairingCode = pairingCode;
      esp_now_send(hubMAC, (uint8_t *)&req, sizeof(PairingRequest));
    }
  } else if (len == sizeof(PairingConfirm)) {
    PairingConfirm *conf = (PairingConfirm *)incomingData;
    if (strncmp(conf->magic, "WLMSCONF", 8) == 0 && conf->deviceId == myDeviceId) {
      if (conf->accepted) {
        paired = true;
        nodeSaveNVS(); // ← persist hub MAC so next boot skips scanning
        Serial.println("[NODE] Paired! Saved to NVS.");
      } else {
        Serial.println("[NODE] Pairing rejected.");
      }
    }
  }
}

bool readSensorDistance(uint16_t &distanceMm) {
  dypSerial.write(0x55);
  delay(50);
  
  if (dypSerial.available() >= 4) {
    dypData[0] = dypSerial.read();
    if (dypData[0] == 0xFF) {
      dypData[1] = dypSerial.read();
      dypData[2] = dypSerial.read();
      dypData[3] = dypSerial.read();
      
      uint8_t sum = (dypData[0] + dypData[1] + dypData[2]) & 0xFF;
      if (sum == dypData[3]) {
        distanceMm = (dypData[1] << 8) | dypData[2];
        return true;
      }
    }
  }
  return false;
}
// ── Calibration / Filtering ─────────────────────────────────────────────────
#define MEDIAN_SAMPLES   7      // 7 pings per cycle — better outlier rejection
#define EMA_ALPHA_NUM    15     // EMA weight = 15/100 = 0.15 — very slow to drift
#define EMA_ALPHA_DEN    100
#define DEADBAND_MM      10     // suppress transmit unless changed by >10mm
#define PLAUSIBLE_JUMP   200    // reject any reading >200mm from current EMA (spike guard)
#define SENSOR_MIN_MM    20     // DYP-A02YYTW min range
#define SENSOR_MAX_MM    4500   // DYP-A02YYTW max range

int16_t emaValue  = -1;
int16_t lastSentMm = -1;

// Take one raw reading from the DYP sensor (blocking ~60ms)
bool readRaw(uint16_t &out) {
  while (dypSerial.available()) dypSerial.read(); // flush stale bytes
  dypSerial.write(0x55);
  delay(60);
  if (dypSerial.available() >= 4) {
    uint8_t d[4];
    d[0] = dypSerial.read();
    if (d[0] == 0xFF) {
      d[1] = dypSerial.read();
      d[2] = dypSerial.read();
      d[3] = dypSerial.read();
      if (((d[0]+d[1]+d[2]) & 0xFF) == d[3]) {
        uint16_t v = (d[1] << 8) | d[2];
        // Hard clamp to sensor physical range
        if (v >= SENSOR_MIN_MM && v <= SENSOR_MAX_MM) {
          out = v;
          return true;
        }
      }
    }
  }
  return false;
}

// Insertion-sort helper for median
void sortArr(uint16_t *a, int n) {
  for (int i = 1; i < n; i++) {
    uint16_t key = a[i]; int j = i-1;
    while (j >= 0 && a[j] > key) { a[j+1] = a[j]; j--; }
    a[j+1] = key;
  }
}

// Take MEDIAN_SAMPLES readings, return median; false if < 4 valid
bool readMedian(uint16_t &out) {
  uint16_t buf[MEDIAN_SAMPLES];
  int valid = 0;
  for (int i = 0; i < MEDIAN_SAMPLES; i++) {
    uint16_t v;
    if (readRaw(v)) buf[valid++] = v;
  }
  if (valid < 4) return false;
  sortArr(buf, valid);
  out = buf[valid / 2];
  return true;
}


void setup() {
  Serial.begin(115200);
  delay(500); // brief settle — do NOT block on Serial (no USB = infinite hang)

  Serial.println("\n--- AQUAPULSE Node ---");
  dypSerial.begin(9600, SERIAL_8N1, DYP_RX, DYP_TX);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_channel(PAIRING_CHANNEL, WIFI_SECOND_CHAN_NONE);
  WiFi.macAddress(myMAC);
  Serial.print("[NODE] MAC: "); printMAC(myMAC); Serial.println();

  if (esp_now_init() != ESP_OK) {
    Serial.println("[NODE] ESP-NOW init failed — restarting");
    delay(1000); ESP.restart(); return;
  }
  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);

  // Add broadcast peer so hub beacons (sent to FF:FF:...) are receivable
  // and so we can reply from any address during pairing
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
    Serial.print("[NODE] Restored pairing — Hub: "); printMAC(hubMAC); Serial.println();
    if (!esp_now_is_peer_exist(hubMAC)) {
      esp_now_peer_info_t peerInfo = {};
      memcpy(peerInfo.peer_addr, hubMAC, 6);
      peerInfo.channel = PAIRING_CHANNEL;
      peerInfo.encrypt = false;
      esp_now_add_peer(&peerInfo);
    }
  } else {
    Serial.println("[NODE] No saved pairing — scanning for Hub beacon...");
  }
}

void loop() {
  if (paired) {
    uint16_t median;
    if (readMedian(median)) {
      // Seed EMA on first reading
      if (emaValue < 0) emaValue = (int16_t)median;

      // Plausibility check: if this median is >PLAUSIBLE_JUMP from our running EMA,
      // it's almost certainly a spurious echo — discard it entirely
      if (abs((int)median - (int)emaValue) > PLAUSIBLE_JUMP) {
        Serial.printf("[NODE] SPIKE rejected: median=%d  EMA=%d\n", median, emaValue);
      } else {
        // Apply EMA: new = alpha*median + (1-alpha)*old
        emaValue = (EMA_ALPHA_NUM * (int)median + (EMA_ALPHA_DEN - EMA_ALPHA_NUM) * (int)emaValue) / EMA_ALPHA_DEN;

        // Only transmit if changed by more than DEADBAND_MM
        if (lastSentMm < 0 || abs((int)emaValue - (int)lastSentMm) > DEADBAND_MM) {
          SensorData data;
          data.deviceId  = myDeviceId;
          data.distance  = emaValue;
          data.timestamp = millis();
          esp_err_t result = esp_now_send(hubMAC, (uint8_t *)&data, sizeof(SensorData));
          if (result == ESP_OK) {
            sendFailures = 0;
            lastSentMm = emaValue;
            Serial.printf("[NODE] Dist: %d mm  (raw median=%d mm)\n", emaValue, median);
          } else {
            sendFailures++;
            Serial.printf("[NODE] Send fail #%d\n", sendFailures);
          }
        } else {
          Serial.printf("[NODE] Stable (%d mm, no tx)\n", emaValue);
        }
      }
    } else {
      Serial.println("[NODE] Sensor read failed");
    }


    // After 10 consecutive failures, assume hub changed — clear NVS and re-scan
    if (sendFailures >= 10) {
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
#include "qrcode.h"
#include <WiFi.h>
#include <Preferences.h>
bool invalidateCache = false;
void drawDisplay(bool fullRedraw);
void drawPage0(bool fullRedraw);
void drawPage1(bool fullRedraw);
void drawStatusBar(bool fullRedraw);
void drawMenu();
void drawSlider();

#include <esp_now.h>
#include <esp_wifi.h>

// ─── TANK CALIBRATION ─────────────────────────────────────────────────────────
int tankEmptyMm = 2000;   // distance when tank is EMPTY (mm)
int tankFullMm  = 200;    // distance when tank is FULL  (mm)
int alertThreshold = 20;  // alert when fill % drops below this
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

bool isPairingMode = false;
unsigned long pairingStartTime = 0;

// ── Buzzer (pin 26, MMBT2222A NPN — HIGH = on) ───────────────────────────────
#define BUZZER_PIN 26
// Beep pattern state (non-blocking)
bool     buzzerAlert   = false;   // true when at least one node is below threshold
bool     buzzerOn      = false;   // current transistor state
unsigned long buzzerLast = 0;
int      buzzerPhase   = 0;       // cycles through ON/OFF timing

// Call this from loop() — drives the buzzer without delay()
void updateBuzzer() {
  if (!buzzerAlert) {
    if (buzzerOn) { digitalWrite(BUZZER_PIN, LOW); buzzerOn = false; }
    buzzerPhase = 0;
    return;
  }
  // Pattern: 100ms ON → 100ms OFF → 100ms ON → 700ms OFF (double-beep every ~1s)
  static const uint16_t pattern[] = {100, 100, 100, 700};
  unsigned long now = millis();
  if (now - buzzerLast >= pattern[buzzerPhase]) {
    buzzerLast = now;
    buzzerPhase = (buzzerPhase + 1) % 4;
    bool shouldBeOn = (buzzerPhase == 0 || buzzerPhase == 2); // phases 0,2 = ON
    buzzerOn = shouldBeOn;
    digitalWrite(BUZZER_PIN, buzzerOn ? HIGH : LOW);
  }
}

// Check all nodes — update buzzerAlert flag
void checkAlerts() {
  bool anyAlert = false;
  for (int i = 0; i < MAX_NODES; i++) {
    if (!nodes[i].paired) continue;
    if (millis() - nodes[i].lastRecvTime > 15000) continue; // skip offline
    if (nodes[i].distance == -1) continue;
    int pct = map(nodes[i].distance, tankEmptyMm, tankFullMm, 0, 100);
    pct = constrain(pct, 0, 100);
    if (pct < alertThreshold) { anyAlert = true; break; }
  }
  buzzerAlert = anyAlert;
}


// ── NVS (Preferences) for paired node MACs ───────────────────────────────────
Preferences hubPrefs;

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
    Serial.printf("[HUB] Loaded node %d from NVS\n", i+1);
  }
}

// Returns how many nodes are currently paired (used instead of activeNodeCount())
int activeNodeCount() {
  int c = 0;
  for (int i = 0; i < MAX_NODES; i++) if (nodes[i].paired) c++;
  return c;
}
int currentPage = 0; // 0 = Number Grid, 1 = Visual Tanks
bool forceRedraw = true;

void setBrightness(int level) {
  brightnessLevel = constrain(level, 20, 255);
  ledcSetup(0, 5000, 8);
  ledcAttachPin(BL_PIN, 0);
  ledcWrite(0, brightnessLevel);
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
    for (int i = 0; i < MAX_NODES; i++) {
      if (nodes[i].paired && memcmp(nodes[i].mac, mac, 6) == 0) {
        // ── Known paired node: update data ──
        if (nodes[i].distance != data->distance) forceRedraw = true;
        nodes[i].distance = data->distance;
        nodes[i].lastRecvTime = millis();
        return;
      }
    }
    // ── Unknown sender: check if it's a saved node that just rebooted ──
    // (Node has hub MAC in NVS and is sending directly without re-pairing)
    // We accept if the MAC is in our NVS-loaded list (paired=true at boot)
    // already handled above — if we get here it's a truly unknown node, ignore.
    return;
  }

  if (len == sizeof(PairingRequest)) {
    PairingRequest *req = (PairingRequest *)incomingData;
    if (strncmp(req->magic, "WLMSREQ", 8) != 0) return;
    if (req->pairingCode != pairingCode) return;
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

  // Menu Button — top-right
  tft.fillRoundRect(258, 4, 58, 24, 4, COLOR_DARK_GRAY);
  tft.setTextColor(COLOR_WHITE);
  tft.setTextSize(1);
  tft.setCursor(268, 11);
  tft.print("MENU");
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
    sprintf(ssidStr, "WiFi: AQP_%02X%02X%02X%02X%02X%02X (12345678)", myMAC[0], myMAC[1], myMAC[2], myMAC[3], myMAC[4], myMAC[5]);
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
    // [DASHBOARD]  [NODE CFG]  [TANK CAL]
    // Each ~96px wide, 8px gap
    int bY = 82, bH = 56;
    tft.fillRoundRect(4,   bY, 97, bH, 5, COLOR_DARK_GRAY);
    tft.fillRoundRect(111, bY, 97, bH, 5, COLOR_DARK_GRAY);
    tft.fillRoundRect(218, bY, 97, bH, 5, COLOR_DARK_GRAY);

    tft.setTextSize(1);
    tft.setTextColor(COLOR_WHITE);
    tft.setCursor(16,  bY + 20); tft.print("DASHBOARD");
    tft.setCursor(122, bY + 14); tft.print("NODE");
    tft.setCursor(122, bY + 28); tft.print("CONFIG");
    tft.setTextColor(COLOR_ACCENT);
    tft.setCursor(229, bY + 14); tft.print("TANK");
    tft.setCursor(229, bY + 28); tft.print("CAL");

    // BACK button (y=148..190)
    tft.fillRoundRect(8, 148, 304, 38, 6, COLOR_BLUE);
    tft.setTextColor(COLOR_WHITE);
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

  // ── Page 3: Tank Calibration ──────────────────────────────────────────────
  else if (currentMenuPage == 3) {
    tft.fillRect(0, 0, 320, 24, COLOR_DARK_GRAY);
    tft.setTextColor(COLOR_HEADER);
    tft.setTextSize(2);
    tft.setCursor(6, 4);
    tft.print("TANK CAL");

    // Each row: label | value | [+] [-]
    // rowY positions: 32, 84, 136  (52px per row, 42px buttons)
    char buf[12];
    int rH = 42;
    int rYs[3] = {30, 82, 134};
    const char* labels[3] = {"EMPTY mm", "FULL  mm", "ALERT %"};
    uint16_t cols[3] = {COLOR_ORANGE, COLOR_ACCENT, COLOR_RED};

    for (int r = 0; r < 3; r++) {
      int rY = rYs[r];
      tft.fillRoundRect(4, rY, 312, rH, 5, COLOR_DARK_GRAY);

      // Label
      tft.setTextColor(COLOR_WHITE);
      tft.setTextSize(1);
      tft.setCursor(10, rY + 6);
      tft.print(labels[r]);

      // Value
      tft.setTextColor(cols[r]);
      tft.setTextSize(2);
      if (r == 0) sprintf(buf, "%4d", tankEmptyMm);
      else if (r == 1) sprintf(buf, "%4d", tankFullMm);
      else sprintf(buf, "%3d%%", alertThreshold);
      tft.setCursor(105, rY + 12);
      tft.print(buf);

      // [+] button
      tft.fillRoundRect(224, rY + 4, 38, rH - 8, 4, 0x03E0);
      tft.setTextColor(COLOR_WHITE);
      tft.setTextSize(2);
      tft.setCursor(234, rY + 13);
      tft.print("+");

      // [-] button
      tft.fillRoundRect(268, rY + 4, 38, rH - 8, 4, 0xC000);
      tft.setCursor(278, rY + 13);
      tft.print("-");
    }

    // BACK button
    tft.fillRoundRect(8, 186, 304, 34, 6, COLOR_BLUE);
    tft.setTextColor(COLOR_WHITE);
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
    tft.fillRoundRect(8, 160, 304, 38, 6, COLOR_BLUE);
    tft.setTextColor(COLOR_WHITE);
    tft.setTextSize(2);
    tft.setCursor(134, 172);
    tft.print("BACK");
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
          // MENU button is now at x=258..316, y=4..28 (header)
          if (startX > 258 && startY < 32) {
            inMenu = true;
            currentMenuPage = 0;
            drawMenu();
          }
          // Secret menu (double tap on logo x=0..150, y=0..32)
          else if (startX < 150 && startY < 32) {
            static unsigned long lastTap = 0;
            if (millis() - lastTap < 500 && lastTap > 0) {
              inMenu = true;
              currentMenuPage = 99; // Secret Menu
              drawMenu();
              lastTap = 0;
            } else {
              lastTap = millis();
            }
          }
        } else {
          if (currentMenuPage == 0) {
            // DASHBOARD — left third button row (x=4..101, y=82..138)
            if (startX > 4 && startX < 101 && startY > 82 && startY < 138) {
              qrMode = 1;
              drawQRCode("http://192.168.4.1/", "DASHBOARD QR");
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
              drawHeader();
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
              hubPrefs.begin("hub", false); hubPrefs.clear(); hubPrefs.end(); // clear NVS
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
                              peer.channel = PAIRING_CHANNEL;
                              peer.encrypt = false;
                              esp_now_add_peer(&peer);
                              PairingConfirm conf;
                              strncpy(conf.magic, "WLMSCONF", 8);
                              memcpy(conf.hubMAC, myMAC, 6);
                              conf.deviceId = discoveredNodes[i].deviceId;
                              conf.accepted = true;
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
            // Rows: rYs = {30,82,134}, buttons at x=224..262(+) and x=268..306(-)
            int rYs[3] = {30, 82, 134};
            for (int r = 0; r < 3; r++) {
              int rY = rYs[r];
              if (startY > rY+4 && startY < rY+38) {
                if (startX > 224 && startX < 262) { // [+]
                  if (r == 0) tankEmptyMm  = constrain(tankEmptyMm  + 50, 100, 5000);
                  else if (r == 1) tankFullMm = constrain(tankFullMm + 10, 10, tankEmptyMm - 50);
                  else alertThreshold = constrain(alertThreshold + 5, 5, 80);
                  drawMenu();
                } else if (startX > 268 && startX < 306) { // [-]
                  if (r == 0) tankEmptyMm  = constrain(tankEmptyMm  - 50, 100, 5000);
                  else if (r == 1) tankFullMm = constrain(tankFullMm - 10, 10, tankEmptyMm - 50);
                  else alertThreshold = constrain(alertThreshold - 5, 5, 80);
                  drawMenu();
                }
              }
            }
            // BACK y=186..220
            if (startY > 186 && startY < 220) {
              currentMenuPage = 0;
              drawMenu();
            }
          }
          else if (currentMenuPage == 99) {
            // TEST BUZZER (y=50..100)
            if (startY > 50 && startY < 100) {
              digitalWrite(BUZZER_PIN, HIGH);
              delay(500); // Test beep
              digitalWrite(BUZZER_PIN, LOW);
            }
            // BACK (y=160..198)
            else if (startY > 160 && startY < 198) {
              currentMenuPage = 0;
              drawMenu();
            }
          }
        }
      } else if (!inMenu && duration < 500) {
        if (dx > 50) {
          currentPage = (currentPage == 1) ? 0 : 1;
          forceRedraw = true;
        } else if (dx < -50) {
          currentPage = (currentPage == 0) ? 1 : 0;
          forceRedraw = true;
        }
      }
    }
  }
}


void broadcastBeacon() {
  PairingBeacon b;
  strncpy(b.magic, "WLMSHUB", 8);
  memcpy(b.hubMAC, myMAC, 6);
  b.channel = PAIRING_CHANNEL;
  b.pairingCode = pairingCode;
  
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  esp_now_send(broadcast, (uint8_t *)&b, sizeof(PairingBeacon));
}

String getDashboardHTML() {
  String html = "<html><head><meta name='viewport' content='width=device-width, initial-scale=1'><style>";
  html += "body { font-family: Arial; text-align: center; background: #222; color: #fff; }";
  html += ".tank { display: inline-block; width: 100px; margin: 10px; padding: 10px; background: #333; border-radius: 8px; }";
  html += "</style></head><body><h1>WLMS Dashboard</h1>";
  for (int i=0; i<4; i++) {
    if (nodes[i].paired) {
      html += "<div class='tank'><h3>Node " + String(i+1) + "</h3>";
      long d = nodes[i].distance;
      if (d == -1) {
         html += "<p>Distance: -- mm</p>";
      } else {
         html += "<p>Distance: " + String(d) + " mm</p>";
         int pct = map(d, tankEmptyMm, tankFullMm, 0, 100);
         pct = constrain(pct, 0, 100);
         html += "<p>Level: " + String(pct) + "%</p>";
      }
      html += "</div>";
    }
  }
  html += "<br><a href='/pairing' style='color:#4DA6FF'>Pairing Mode</a>";
  html += "</body></html>";
  return html;
}

String getPairingHTML() {
  return "<html><head><meta name='viewport' content='width=device-width, initial-scale=1'><style>"
         "body { font-family: Arial; text-align: center; background: #222; color: #fff; margin-top: 50px;}"
         ".btn { display: inline-block; padding: 15px 30px; background: #4DA6FF; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; }"
         "</style></head><body><h2>Node Pairing</h2>"
         "<p>1. Ensure this Hub is powered on.</p>"
         "<p>2. Power on the Node.</p>"
         "<p>3. The Node will automatically connect to this Hub's MAC address.</p>"
         "<a href='/' class='btn'>Back to Dashboard</a></body></html>";
}

#include "qrcode.h"
void drawQRCode(const char *text, const char *title) {
  tft.fillScreen(COLOR_BG);
  tft.setTextColor(COLOR_CYAN);
  tft.setTextSize(2);
  tft.setCursor(20, 20);
  tft.print(title);
  
  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(3)];
  qrcode_initText(&qrcode, qrcodeData, 3, 0, text);
  
  int scale = 4;
  int startX = (320 - (qrcode.size * scale)) / 2;
  int startY = (240 - (qrcode.size * scale)) / 2 + 10;
  
  tft.fillRect(startX - 10, startY - 10, qrcode.size * scale + 20, qrcode.size * scale + 20, COLOR_WHITE);
  
  for (uint8_t y = 0; y < qrcode.size; y++) {
    for (uint8_t x = 0; x < qrcode.size; x++) {
      if (qrcode_getModule(&qrcode, x, y)) {
        tft.fillRect(startX + x * scale, startY + y * scale, scale, scale, 0x0000);
      }
    }
  }
}




uint16_t getDistColor(int percent) {
  if (percent < alertThreshold) return COLOR_RED;
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
    int dist = nodes[i].distance;
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
    
    uint16_t pColor = getDistColor(percent);

    tft.setTextSize(2);
    tft.setTextColor(pColor, COLOR_DARK_GRAY);
    tft.setCursor(x+4, y+28);
    char buf[16];
    if (dist == -1) sprintf(buf, "--    ");
    else sprintf(buf, "%d mm   ", dist);
    tft.print(buf);

    tft.setTextSize(3);
    tft.setTextColor(pColor, COLOR_DARK_GRAY);
    tft.setCursor(x+4, y+50);
    if (dist == -1) sprintf(buf, "--%%   ");
    else sprintf(buf, "%d%%   ", percent);
    tft.print(buf);
  }
}

void drawPage0(bool fullRedraw) {
  if (fullRedraw) {
    tft.fillRect(0, 32, 320, 208, COLOR_BG);
    int cellW = 156, cellH = 100;
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
  uint16_t fillColor = getDistColor(percent);

  // Outer border (rounded rect, always redrawn cleanly)
  uint16_t borderColor = offline ? COLOR_RED : (paired ? fillColor : COLOR_DARK_GRAY);
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
    for (int i = 0; i < 4; i++) { lastPaired[i] = -1; lastPercent[i] = -99; }
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
    int dist     = nodes[i].distance;
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

    // Percentage below tank
    tft.fillRect(x, y + tankH + 2, tankW, 14, COLOR_BG);
    tft.setTextSize(1);
    uint16_t col = nodes[i].paired && !offline ? getDistColor(percent) : COLOR_DARK_GRAY;
    tft.setTextColor(col, COLOR_BG);
    tft.setCursor(x + tankW/2 - 12, y + tankH + 3);
    char buf[8];
    if (!nodes[i].paired) strcpy(buf, "  --  ");
    else if (offline)     strcpy(buf, "OFFLN ");
    else sprintf(buf, " %3d%% ", percent);
    tft.print(buf);
  }
}

void drawPage1(bool fullRedraw) {
  if (fullRedraw) {
    tft.fillRect(0, 32, 320, 208, COLOR_BG);
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
  if (fullRedraw) drawHeader();
  if (currentPage == 0) drawPage0(fullRedraw);
  else drawPage1(fullRedraw);
  drawStatusBar(fullRedraw);
}

void setup() {
  Serial.begin(115200);
  startTime = millis();

  for (int i=0; i<MAX_NODES; i++) {
    nodes[i].paired = false;
    nodes[i].distance = -1;
    nodes[i].lastRecvTime = 0;
  }

  pinMode(BUZZER_PIN, OUTPUT);
  digitalWrite(BUZZER_PIN, LOW);

  pinMode(17, OUTPUT);
  digitalWrite(17, HIGH);
  setBrightness(255);

  tft.init();
  tft.setRotation(1);
  tft.invertDisplay(false);
  uint16_t calData[5] = { 275, 3620, 264, 3532, 1 };
  tft.setTouch(calData);
  
  tft.fillScreen(COLOR_BG);

  // Short startup beep to confirm buzzer works
  digitalWrite(BUZZER_PIN, HIGH);
  delay(100);
  digitalWrite(BUZZER_PIN, LOW);

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

  
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();
  WiFi.macAddress(myMAC);
  char ssid[32];
  sprintf(ssid, "AQP_%02X%02X%02X%02X%02X%02X", myMAC[0], myMAC[1], myMAC[2], myMAC[3], myMAC[4], myMAC[5]);
  WiFi.softAP(ssid, "12345678");
  pairingCode = (myMAC[4] << 8) | myMAC[5];
  esp_wifi_set_channel(PAIRING_CHANNEL, WIFI_SECOND_CHAN_NONE);

  server.on("/", []() { server.send(200, "text/html", getDashboardHTML()); });
  server.on("/pairing", []() { server.send(200, "text/html", getPairingHTML()); });
  server.begin();
  ArduinoOTA.begin();

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
    bcast.ifidx = WIFI_IF_STA;
    bcast.encrypt = false;
    esp_now_add_peer(&bcast);

    // Load saved nodes from NVS and re-register as peers
    hubLoadNodes();
    for (int i = 0; i < MAX_NODES; i++) {
      if (nodes[i].paired) {
        esp_now_peer_info_t peer = {};
        memcpy(peer.peer_addr, nodes[i].mac, 6);
        peer.channel = PAIRING_CHANNEL;
        peer.encrypt = false;
        esp_now_add_peer(&peer);
      }
    }
  }

  drawHeader();
  drawDisplay(forceRedraw);
}

void loop() {
  ArduinoOTA.handle();
  server.handleClient();
  handleTouch();
  updateBuzzer(); // non-blocking buzzer driver

  if (inMenu) {
    if (currentMenuPage == 2) {
      if (millis() - lastBeaconTime > 1000) {
        broadcastBeacon();
        lastBeaconTime = millis();
      }
      if (forceRedraw) {
        drawMenu();
        forceRedraw = false;
      }
    }
    return;
  }

  // Full page redraw only when data changed (ESP-NOW triggered forceRedraw)
  if (forceRedraw) {
    checkAlerts();        // Evaluate if any node is below alertThreshold
    drawDisplay(false);   // false = don't nuke whole screen, just update dirty cells
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
