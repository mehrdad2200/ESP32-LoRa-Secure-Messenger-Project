#include <WiFi.h>
#include <WebServer.h>
#include <SPI.h>
#include <LoRa.h>
#include "lora_crypto.h"

// پین‌های ارتباطی ماژول LoRa SX1278
#define SCK_PIN   5
#define MISO_PIN  19
#define MOSI_PIN  27
#define SS_PIN    18
#define RST_PIN   14
#define DIO0_PIN  26

#define LORA_BAND 433E6 // فرکانس کاری (433MHz)

const char* ap_ssid = "ESP32-LoRa-Messenger";
const char* ap_password = ""; // شبکه باز

WebServer server(80);

struct Message {
  String sender;
  String text;
  String target;
  int rssi;
  float snr;
  bool isOutgoing;
};

#define MAX_MESSAGES 20
Message msgHistory[MAX_MESSAGES];
int msgCount = 0;

void addMessage(String sender, String text, String target, int rssi, float snr, bool isOutgoing) {
  if (msgCount >= MAX_MESSAGES) {
    for (int i = 0; i < MAX_MESSAGES - 1; i++) {
      msgHistory[i] = msgHistory[i + 1];
    }
    msgCount = MAX_MESSAGES - 1;
  }
  msgHistory[msgCount] = {sender, text, target, rssi, snr, isOutgoing};
  msgCount++;
}

// کد HTML/CSS/JS رابط کاربری پیام‌رسان و نقشه
const char INDEX_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>پیام‌رسان امن LoRa & نقشه آفلاین ESP32</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: Tahoma, sans-serif; }
    body { background: #121826; color: #fff; display: flex; flex-direction: column; height: 100vh; }
    header { background: #1f2937; padding: 15px; text-align: center; font-weight: bold; border-bottom: 1px solid #374151; }
    .status { font-size: 12px; color: #10b981; margin-top: 5px; }
    #chat { flex: 1; padding: 15px; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; }
    .msg { max-width: 80%; padding: 10px 14px; border-radius: 10px; font-size: 14px; line-height: 1.4; }
    .in { background: #374151; align-self: flex-start; border-bottom-right-radius: 0; }
    .out { background: #2563eb; align-self: flex-end; border-bottom-left-radius: 0; }
    .meta { font-size: 10px; opacity: 0.7; margin-top: 4px; text-align: left; }
    .input-box { padding: 10px; background: #1f2937; display: flex; gap: 10px; border-top: 1px solid #374151; }
    input { flex: 1; padding: 10px; border-radius: 6px; border: 1px solid #4b5563; background: #111827; color: #fff; }
    button { padding: 10px 20px; background: #2563eb; border: none; border-radius: 6px; color: #fff; cursor: pointer; font-weight: bold; }
    button:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <header>
    ESP32 LoRa Secure Messenger
    <div class="status">● متصل به ESP32 | رمزنگاری AES-128 فعال</div>
  </header>
  
  <div id="chat"></div>

  <div class="input-box">
    <input type="text" id="msgInput" placeholder="پیام خود را بنویسید..." />
    <button onclick="sendMsg()">ارسال</button>
  </div>

  <script>
    async function fetchMessages() {
      try {
        const res = await fetch('/api/messages');
        const data = await res.json();
        const chat = document.getElementById('chat');
        chat.innerHTML = '';
        data.forEach(m => {
          const div = document.createElement('div');
          div.className = `msg ${m.isOutgoing ? 'out' : 'in'}`;
          div.innerHTML = `<div>${m.text}</div><div class="meta">${m.sender} ${m.rssi ? '| RSSI: ' + m.rssi + ' dBm' : ''}</div>`;
          chat.appendChild(div);
        });
      } catch(e) {}
    }

    async function sendMsg() {
      const input = document.getElementById('msgInput');
      const text = input.value.trim();
      if (!text) return;
      
      await fetch('/api/send', {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: text
      });
      input.value = '';
      fetchMessages();
    }

    setInterval(fetchMessages, 2000);
    fetchMessages();
  </script>
</body>
</html>
)rawliteral";

void setup() {
  Serial.begin(115200);

  // راه‌اندازی وای‌فای AP
  WiFi.softAP(ap_ssid, ap_password);
  Serial.print("Access Point IP: ");
  Serial.println(WiFi.softAPIP());

  // راه‌اندازی LoRa
  SPI.begin(SCK_PIN, MISO_PIN, MOSI_PIN, SS_PIN);
  LoRa.setPins(SS_PIN, RST_PIN, DIO0_PIN);
  
  if (!LoRa.begin(LORA_BAND)) {
    Serial.println("خطا در راه‌اندازی ماژول LoRa!");
  } else {
    Serial.println("ماژول LoRa فعال شد.");
  }

  // تعریف Routes
  server.on("/", []() {
    server.send_P(200, "text/html; charset=UTF-8", INDEX_HTML);
  });

  server.on("/api/messages", []() {
    String json = "[";
    for (int i = 0; i < msgCount; i++) {
      json += "{";
      json += ""sender":"" + msgHistory[i].sender + "",";
      json += ""text":"" + msgHistory[i].text + "",";
      json += ""target":"" + msgHistory[i].target + "",";
      json += ""rssi":" + String(msgHistory[i].rssi) + ",";
      json += ""snr":" + String(msgHistory[i].snr) + ",";
      json += ""isOutgoing":" + String(msgHistory[i].isOutgoing ? "true" : "false");
      json += "}";
      if (i < msgCount - 1) json += ",";
    }
    json += "]";
    server.send(200, "application/json", json);
  });

  server.on("/api/send", HTTP_POST, []() {
    if (server.hasArg("plain")) {
      String plainText = server.arg("plain");
      
      // ۱. رمزنگاری پیام با AES-128
      String encryptedHex = encryptMessage(plainText);

      // ۲. ارسال پیام رمز شده با LoRa
      LoRa.beginPacket();
      LoRa.print(encryptedHex);
      LoRa.endPacket();

      // ذخیره در تاریخچه
      addMessage("Node-01", plainText, "Broadcast", 0, 0.0, true);
      server.send(200, "application/json", "{"status":"ok"}");
    } else {
      server.send(400, "text/plain", "Bad Request");
    }
  });

  server.begin();
  Serial.println("وب‌سرور فعال گردید.");
}

void loop() {
  server.handleClient();

  // بررسی دریافت بسته جدید از LoRa
  int packetSize = LoRa.parsePacket();
  if (packetSize) {
    String incomingHex = "";
    while (LoRa.available()) {
      incomingHex += (char)LoRa.read();
    }

    // رمزگشایی بسته دریافتی
    String decryptedText = decryptMessage(incomingHex);
    int rssi = LoRa.packetRssi();
    float snr = LoRa.packetSnr();

    if (decryptedText.length() > 0) {
      addMessage("Remote-Node", decryptedText, "Node-01", rssi, snr, false);
      Serial.println("پیام امن جدید دریافت شد: " + decryptedText);
    } else {
      Serial.println("خطا در رمزگشایی یا کلید نامعتبر!");
    }
  }
}
