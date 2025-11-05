\
/*
 * Secure IoT ESP32 Client (DHT11 + AES-256-CBC + HTTP POST)
 * - Reads DHT11 every 10 seconds
 * - Encrypts JSON {temp, hum, ts} with AES-256-CBC using mbedTLS
 * - Sends to Flask /ingest
 * - Blinks LED if server replies {blink:true}
 *
 * Dependencies:
 *  - ESP32 board package
 *  - DHT sensor library (Adafruit DHT)
 * 
 * Fill in: WIFI_SSID, WIFI_PASS, SERVER_HOST, SERVER_PORT
 * Set DHTPIN, LED_PIN, and AES key/IV generation (IV is random per message).
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "DHT.h"

#define WIFI_SSID     "Deep_Backward_Point"
#define WIFI_PASS     "SillyMidoff_18"
#define SERVER_HOST   "192.168.1.209"   //  Flask server IP
#define SERVER_PORT   8888
#define DEVICE_ID     "esp32-01"

#define DHTPIN 4
#define DHTTYPE DHT11
#define LED_PIN 2

DHT dht(DHTPIN, DHTTYPE);

// 32-byte AES-256 key (must match the server's AES256_KEY_B64)
uint8_t AES_KEY[32] = {
  /* paste 32 bytes here if you want hardcode; otherwise see setKeyFromBase64() */
};

// If you prefer to paste base64 key (from server .env), put it here:
const char* AES_KEY_B64 = "BFr5BHZ+N1AJjIy9114Pbirphqf0V1gETHz8xavRHfw=";

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

void setKeyFromBase64() {
  size_t out_len = 0;
  int rc = mbedtls_base64_decode(AES_KEY, sizeof(AES_KEY), &out_len, (const unsigned char*)AES_KEY_B64, strlen(AES_KEY_B64));
  if (rc != 0 || out_len != 32) {
    Serial.println("[AES] Failed to decode base64 key; using zeros");
    memset(AES_KEY, 0, 32);
  }
}

String b64(const uint8_t* data, size_t len) {
  size_t olen = 0;
  mbedtls_base64_encode(NULL, 0, &olen, data, len);
  std::unique_ptr<unsigned char[]> out(new unsigned char[olen+1]);
  mbedtls_base64_encode(out.get(), olen, &olen, data, len);
  out.get()[olen] = 0;
  return String((char*)out.get());
}

bool aes256_cbc_encrypt(const String& plaintext, String& out_ct_b64, String& out_iv_b64) {
  uint8_t iv[16];
  mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv));

  // PKCS7 padding
  size_t len = plaintext.length();
  uint8_t pad = 16 - (len % 16);
  size_t plen = len + pad;
  std::unique_ptr<uint8_t[]> padded(new uint8_t[plen]);
  memcpy(padded.get(), plaintext.c_str(), len);
  memset(padded.get()+len, pad, pad);

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  if (mbedtls_aes_setkey_enc(&ctx, AES_KEY, 256) != 0) {
    mbedtls_aes_free(&ctx);
    return false;
  }
  std::unique_ptr<uint8_t[]> out(new uint8_t[plen]);
  size_t offset = 0;
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);
  if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, plen, iv_copy, padded.get(), out.get()) != 0) {
    mbedtls_aes_free(&ctx);
    return false;
  }
  mbedtls_aes_free(&ctx);

  out_ct_b64 = b64(out.get(), plen);
  out_iv_b64 = b64(iv, 16);
  return true;
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  dht.begin();

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  const char* pers = "esp32_aes";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500); Serial.print(".");
  }
  Serial.println(" connected!");
  setKeyFromBase64();
}

void blinkLed() {
  for (int i=0;i<4;i++) {
    digitalWrite(LED_PIN, HIGH); delay(250);
    digitalWrite(LED_PIN, LOW); delay(250);
  }
}

void loop() {
  float h = dht.readHumidity();
  float t = dht.readTemperature(); // Celsius
  if (isnan(h) || isnan(t)) {
    Serial.println("DHT read failed"); delay(2000); return;
  }
  // JSON plaintext
  DynamicJsonDocument doc(256);
  doc["temp"] = t;
  doc["hum"] = h;
  doc["ts"] = (long)(millis()/1000 + 1700000000); // crude epoch if no RTC
  String pt;
  serializeJson(doc, pt);

  String ct_b64, iv_b64;
  if (!aes256_cbc_encrypt(pt, ct_b64, iv_b64)) {
    Serial.println("[AES] encrypt failed");
    delay(10000); return;
  }

  if (WiFi.status()==WL_CONNECTED) {
    HTTPClient http;
    String url = String("http://") + SERVER_HOST + ":" + SERVER_PORT + "/ingest";
    //http.setTimeout(8000);
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    DynamicJsonDocument body(512);
    body["device_id"] = DEVICE_ID;
    body["ciphertext"] = ct_b64;
    body["iv"] = iv_b64;
    String payload; serializeJson(body, payload);
    int code = http.POST(payload);
    Serial.printf("POST /ingest -> %d\n", code);
    if (code <= 0) {
      Serial.printf("HTTP error: %s\n", http.errorToString(code).c_str());
    } else {
      String resp = http.getString();
      Serial.println(resp);
      if (resp.indexOf("\"blink\":true") != -1) {
        blinkLed();
      }
    }
    http.end();
  }
  delay(10000);
}
