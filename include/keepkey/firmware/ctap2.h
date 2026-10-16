#ifndef KEEPKEY_FIRMWARE_CTAP2_H
#define KEEPKEY_FIRMWARE_CTAP2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CTAP2_CMD_MAKE_CREDENTIAL 0x01
#define CTAP2_CMD_GET_ASSERTION 0x02
#define CTAP2_CMD_GET_INFO 0x04
#define CTAP2_CMD_CLIENT_PIN 0x06
#define CTAP2_CMD_RESET 0x07
#define CTAP2_CMD_GET_NEXT_ASSERTION 0x08
/* Status byte plus the largest response this firmware encodes
 * (makeCredential, 355 B; see the _Static_asserts in ctap2.c). The encoder
 * fails closed (CTAP2_ERR_OTHER) rather than overrun it. */
#define CTAP2_MAX_RESPONSE_SIZE 512

#define CTAP2_OK 0x00
#define CTAP2_ERR_INVALID_COMMAND 0x01
#define CTAP2_ERR_INVALID_PARAMETER 0x02
#define CTAP2_ERR_INVALID_LENGTH 0x03
#define CTAP2_ERR_INVALID_CBOR 0x12
#define CTAP2_ERR_MISSING_PARAMETER 0x14
#define CTAP2_ERR_CREDENTIAL_EXCLUDED 0x19
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26
#define CTAP2_ERR_OPERATION_DENIED 0x27
#define CTAP2_ERR_KEY_STORE_FULL 0x28
#define CTAP2_ERR_INVALID_OPTION 0x2c
#define CTAP2_ERR_KEEPALIVE_CANCEL 0x2d
#define CTAP2_ERR_NO_CREDENTIALS 0x2e
#define CTAP2_ERR_USER_ACTION_TIMEOUT 0x2f
#define CTAP2_ERR_NOT_ALLOWED 0x30
#define CTAP2_ERR_PIN_INVALID 0x31
#define CTAP2_ERR_PIN_BLOCKED 0x32
#define CTAP2_ERR_PIN_AUTH_INVALID 0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED 0x34
#define CTAP2_ERR_PIN_NOT_SET 0x35
#define CTAP2_ERR_PIN_REQUIRED 0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION 0x37
#define CTAP2_ERR_OTHER 0x7f

/* Includes the one-byte CTAP status in response_length. */
void ctap2_init(void);
/* Drop PIN tokens, key agreement and assertion state (wallet wipe/reset). */
void ctap2_clear_session(void);
void ctap2_set_transport_channel(uint32_t channel);
void ctap2_handle(const uint8_t* request, size_t request_length,
                  uint8_t* response, size_t response_capacity,
                  size_t* response_length);

bool ctap2_request_user_presence(const char* rp_id, bool registration);
bool ctap2_user_presence_was_cancelled(void);

#ifdef EMULATOR
/// Test-only visibility into the confidential ClientPIN ECDH lifecycle.
bool ctap2_key_agreement_is_clear(void);
bool ctap2_key_agreement_private_is_valid(const uint8_t private_key[32]);
#endif

#endif
