#ifndef LORA_CRYPTO_H
#define LORA_CRYPTO_H

#include <Arduino.h>
#include "mbedtls/aes.h"

// کلید ۱۶ بایتی اختصاصی (باید در تمام دستگاه‌های هم‌شبکه یکسان باشد)
const uint8_t AES_KEY[16] = {
  0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
  0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

// تابع رمزنگاری متن قبل از ارسال LoRa
inline String encryptMessage(String plainText) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);

  uint8_t iv[16];
  for (int i = 0; i < 16; i++) {
    iv[i] = (uint8_t)esp_random();
  }

  uint8_t nonce_counter[16];
  memcpy(nonce_counter, iv, 16);

  size_t nc_off = 0;
  uint8_t stream_block[16] = {0};

  int len = plainText.length();
  uint8_t input[len];
  uint8_t output[len];
  memcpy(input, plainText.c_str(), len);

  mbedtls_aes_crypt_ctr(&aes, len, &nc_off, nonce_counter, stream_block, input, output);
  mbedtls_aes_free(&aes);

  uint8_t finalPacket[16 + len];
  memcpy(finalPacket, iv, 16);
  memcpy(finalPacket + 16, output, len);

  String hexResult = "";
  for (size_t i = 0; i < (16 + len); i++) {
    if (finalPacket[i] < 16) hexResult += "0";
    hexResult += String(finalPacket[i], HEX);
  }
  return hexResult;
}

// تابع رمزگشایی متن پس از دریافت از LoRa
inline String decryptMessage(String hexCipher) {
  int totalLen = hexCipher.length() / 2;
  if (totalLen <= 16) return ""; 

  uint8_t fullPacket[totalLen];
  for (int i = 0; i < totalLen; i++) {
    String byteString = hexCipher.substring(i * 2, i * 2 + 2);
    fullPacket[i] = (uint8_t) strtol(byteString.c_str(), NULL, 16);
  }

  uint8_t iv[16];
  memcpy(iv, fullPacket, 16);

  int cipherLen = totalLen - 16;
  uint8_t cipherText[cipherLen];
  uint8_t plainText[cipherLen + 1];
  memcpy(cipherText, fullPacket + 16, cipherLen);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);

  size_t nc_off = 0;
  uint8_t stream_block[16] = {0};

  mbedtls_aes_crypt_ctr(&aes, cipherLen, &nc_off, iv, stream_block, cipherText, plainText);
  mbedtls_aes_free(&aes);

  plainText[cipherLen] = '\0';
  return String((char*)plainText);
}

#endif
