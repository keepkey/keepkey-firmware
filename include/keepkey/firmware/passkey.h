#ifndef KEEPKEY_FIRMWARE_PASSKEY_H
#define KEEPKEY_FIRMWARE_PASSKEY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PASSKEY_CREDENTIAL_ID_SIZE 64
#define PASSKEY_USER_ID_MAX 64
#define PASSKEY_USER_NAME_MAX 48
#define PASSKEY_MAX_DISCOVERABLE_CREDENTIALS 4
#define PASSKEY_PIN_RETRIES 8
#define PASSKEY_STORAGE_VERSION 2
#define PASSKEY_CREDENTIAL_GENERATION_SIZE 32

typedef struct __attribute__((packed)) {
  uint8_t occupied;
  uint8_t user_id_length;
  uint8_t reserved[2];
  uint8_t rp_id_hash[32];
  uint8_t credential_id[PASSKEY_CREDENTIAL_ID_SIZE];
  uint8_t user_id[PASSKEY_USER_ID_MAX];
  char user_name[PASSKEY_USER_NAME_MAX];
} PasskeyCredential;

typedef struct __attribute__((packed)) {
  uint8_t version;
  uint8_t pin_set;
  uint8_t pin_retries;
  uint8_t reserved[5];
  uint8_t pin_salt[16];
  uint8_t pin_hash[16];
  PasskeyCredential credentials[PASSKEY_MAX_DISCOVERABLE_CREDENTIALS];
  /* HMAC domain for stateless U2F/CTAP credential IDs. Reset rotates this
   * value, invalidating every handle without retaining an enumerated copy. */
  uint8_t credential_generation[PASSKEY_CREDENTIAL_GENERATION_SIZE];
  uint8_t legacy_credentials_enabled;
} PasskeyStorage;

#endif
