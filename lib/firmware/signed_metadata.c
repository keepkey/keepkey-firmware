#include "keepkey/firmware/signed_metadata.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "trezor/crypto/address.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"

#include <stdio.h>
#include <string.h>

#define _(X) (X)

static bool metadata_available = false;
static bool relied_on_metadata = false;
static SignedMetadata stored_metadata;

/*
 * Metadata verification public keys.
 * Slot 0: active production key
 * Slot 1: rotation target
 * Slots 2-3: reserved
 *
 * Keys are derived via KeepKey SignIdentity at keepkey.com/insight.
 * Only the public key is stored here — the signing mnemonic is held
 * offline and never appears in source code.
 *
 * To rotate: generate new key with pioneer-insight keygen,
 * replace the slot below, ship firmware update.
 */
static const uint8_t METADATA_PUBKEYS[METADATA_MAX_KEYS][33] = {
    /* Key 0: production */
    {0x02, 0x18, 0x62, 0x1d, 0x9c, 0x14, 0x47, 0x34, 0x58, 0x71, 0x3b,
     0xd3, 0xe6, 0x72, 0xe5, 0x34, 0x80, 0xaa, 0x70, 0x32, 0xca, 0x9b,
     0x67, 0x35, 0x63, 0x95, 0xe8, 0x87, 0x09, 0xbb, 0x45, 0x22, 0x6a},
    /* Key 1: rotation slot */
    {0x00},
    {0x00},
#if DEBUG_LINK
    /* Key 3: CI test key — only available in emulator/debug builds */
    {0x02, 0xe3, 0xb3, 0x01, 0x5c, 0x47, 0xdd, 0xca, 0xab, 0xe4, 0xf8,
     0xe8, 0x72, 0xf1, 0xed, 0x8f, 0x09, 0xca, 0x14, 0x5a, 0x8d, 0x81,
     0x77, 0x0d, 0x92, 0x21, 0x3d, 0x56, 0xda, 0x31, 0xab, 0x51, 0x07},
#else
    {0x00},
#endif
};

static bool read_u8(const uint8_t **cursor, const uint8_t *end, uint8_t *out) {
  if ((size_t)(end - *cursor) < 1) {
    return false;
  }

  *out = **cursor;
  *cursor += 1;
  return true;
}

static bool read_be_u16(const uint8_t **cursor, const uint8_t *end,
                        uint16_t *out) {
  if ((size_t)(end - *cursor) < 2) {
    return false;
  }

  *out = ((uint16_t)(*cursor)[0] << 8) | (*cursor)[1];
  *cursor += 2;
  return true;
}

static bool read_be_u32(const uint8_t **cursor, const uint8_t *end,
                        uint32_t *out) {
  if ((size_t)(end - *cursor) < 4) {
    return false;
  }

  *out = ((uint32_t)(*cursor)[0] << 24) | ((uint32_t)(*cursor)[1] << 16) |
         ((uint32_t)(*cursor)[2] << 8) | (*cursor)[3];
  *cursor += 4;
  return true;
}

static bool read_bytes(const uint8_t **cursor, const uint8_t *end, uint8_t *out,
                       size_t size) {
  if ((size_t)(end - *cursor) < size) {
    return false;
  }

  memcpy(out, *cursor, size);
  *cursor += size;
  return true;
}

static bool read_string(const uint8_t **cursor, const uint8_t *end, char *out,
                        size_t max_len) {
  uint16_t value_len = 0;
  if (!read_be_u16(cursor, end, &value_len) || value_len == 0 ||
      value_len > max_len || (size_t)(end - *cursor) < value_len) {
    return false;
  }

  memcpy(out, *cursor, value_len);
  out[value_len] = '\0';
  *cursor += value_len;
  return true;
}

static bool read_arg_name(const uint8_t **cursor, const uint8_t *end, char *out,
                          size_t max_len) {
  uint8_t value_len = 0;
  if (!read_u8(cursor, end, &value_len) || value_len == 0 ||
      value_len > max_len || (size_t)(end - *cursor) < value_len) {
    return false;
  }

  memcpy(out, *cursor, value_len);
  out[value_len] = '\0';
  *cursor += value_len;
  return true;
}

static bool parse_metadata_binary(const uint8_t *payload, size_t payload_len,
                                  SignedMetadata *out) {
  /* Minimum: version(1) + chain_id(4) + contract(20) + selector(4) +
   * tx_hash(32) + method_len(2) + method(1) + num_args(1) +
   * classification(1) + timestamp(4) + key_id(1) + sig(64) + recovery(1)
   * = 136 bytes */
  if (payload_len < 136) {
    return false;
  }

  const uint8_t *cursor = payload;
  const uint8_t *end = payload + payload_len;
  memset(out, 0, sizeof(*out));

  if (!read_u8(&cursor, end, &out->version) || out->version != 0x01 ||
      !read_be_u32(&cursor, end, &out->chain_id) ||
      !read_bytes(&cursor, end, out->contract_address,
                  sizeof(out->contract_address)) ||
      !read_bytes(&cursor, end, out->selector, sizeof(out->selector)) ||
      !read_bytes(&cursor, end, out->tx_hash, sizeof(out->tx_hash)) ||
      !read_string(&cursor, end, out->method_name, METADATA_MAX_METHOD_LEN) ||
      !read_u8(&cursor, end, &out->num_args) ||
      out->num_args > METADATA_MAX_ARGS) {
    return false;
  }

  for (uint8_t i = 0; i < out->num_args; i++) {
    uint8_t format = 0;
    uint16_t value_len = 0;
    MetadataArg *arg = &out->args[i];

    if (!read_arg_name(&cursor, end, arg->name, METADATA_MAX_ARG_NAME_LEN) ||
        !read_u8(&cursor, end, &format) || format > ARG_FORMAT_BYTES ||
        !read_be_u16(&cursor, end, &value_len) ||
        value_len > METADATA_MAX_ARG_VALUE_LEN ||
        !read_bytes(&cursor, end, arg->value, value_len)) {
      return false;
    }

    arg->format = (ArgFormat)format;
    arg->value_len = value_len;
  }

  uint8_t classification = 0;
  if (!read_u8(&cursor, end, &classification) || classification > 2 ||
      !read_be_u32(&cursor, end, &out->timestamp) ||
      !read_u8(&cursor, end, &out->key_id) ||
      !read_bytes(&cursor, end, out->signature, sizeof(out->signature)) ||
      !read_u8(&cursor, end, &out->recovery) || cursor != end) {
    return false;
  }

  out->classification = (MetadataClassification)classification;
  return true;
}

static void bn_from_metadata_bytes(const uint8_t *value, size_t value_len,
                                   bignum256 *out) {
  uint8_t padded[32] = {0};
  if (value_len > sizeof(padded)) {
    value_len = sizeof(padded);
  }
  memcpy(padded + (sizeof(padded) - value_len), value, value_len);
  bn_read_be(padded, out);
  memzero(padded, sizeof(padded));
}

bool signed_metadata_available(void) { return metadata_available; }

void signed_metadata_clear(void) {
  memzero(&stored_metadata, sizeof(stored_metadata));
  metadata_available = false;
  relied_on_metadata = false;
}

MetadataClassification signed_metadata_process(const uint8_t *payload,
                                               size_t payload_len,
                                               uint8_t key_id) {
  uint8_t digest[32];
  size_t signed_len;

  signed_metadata_clear();

  if (key_id >= METADATA_MAX_KEYS || METADATA_PUBKEYS[key_id][0] == 0x00 ||
      !payload || payload_len < 65) {
    return METADATA_MALFORMED;
  }

  if (!parse_metadata_binary(payload, payload_len, &stored_metadata) ||
      stored_metadata.key_id != key_id) {
    signed_metadata_clear();
    return METADATA_MALFORMED;
  }

  signed_len = payload_len - sizeof(stored_metadata.signature) - 1;
  sha256_Raw(payload, signed_len, digest);

  if (ecdsa_verify_digest(&secp256k1, METADATA_PUBKEYS[key_id],
                          stored_metadata.signature, digest) != 0) {
    signed_metadata_clear();
    return METADATA_MALFORMED;
  }

  metadata_available = true;
  return stored_metadata.classification;
}

bool signed_metadata_matches_tx(const EthereumSignTx *msg) {
  if (!metadata_available || !msg ||
      stored_metadata.classification != METADATA_VERIFIED ||
      msg->to.size != sizeof(stored_metadata.contract_address) ||
      msg->data_initial_chunk.size < sizeof(stored_metadata.selector)) {
    return false;
  }

  /* Contract address binding */
  if (memcmp(stored_metadata.contract_address, msg->to.bytes,
             sizeof(stored_metadata.contract_address)) != 0) {
    return false;
  }

  /* Function selector binding */
  if (memcmp(stored_metadata.selector, msg->data_initial_chunk.bytes,
             sizeof(stored_metadata.selector)) != 0) {
    return false;
  }

  /* Chain ID binding */
  if ((msg->has_chain_id ? msg->chain_id : 0) != stored_metadata.chain_id) {
    return false;
  }

  /* This only gates what we DISPLAY (so a benign-looking method screen can't
   * be shown for the wrong call). The metadata commits to the full tx hash;
   * that is enforced against the real signed digest in
   * signed_metadata_enforce() because the digest does not exist until
   * send_signature() finalizes it. */
  return true;
}

bool signed_metadata_confirm(void) {
  char body[128];

  if (!metadata_available ||
      stored_metadata.classification != METADATA_VERIFIED) {
    return false;
  }

  /* Screen 1: Verified method — use review_with_icon for trust indicator */
  memset(body, 0, sizeof(body));
  snprintf(body, sizeof(body), "Verified call:\n%s",
           stored_metadata.method_name);
  if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         VERIFIED_ICON, "Insight Verified", "%s", body)) {
    return false;
  }

  /* Screen 2: Contract address — ALWAYS show full address, never truncate.
   * Truncation is a spoofing vector (attacker crafts matching prefix+suffix).
   */
  char contract_addr[43] = "0x";
  ethereum_address_checksum(stored_metadata.contract_address, contract_addr + 2,
                            false, stored_metadata.chain_id);
  memset(body, 0, sizeof(body));
  snprintf(body, sizeof(body), "Contract:\n%s", contract_addr);
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               stored_metadata.method_name, "%s", body)) {
    return false;
  }

  /* Screen 3..N: Each decoded argument */
  for (uint8_t i = 0; i < stored_metadata.num_args; i++) {
    MetadataArg *arg = &stored_metadata.args[i];
    memset(body, 0, sizeof(body));

    switch (arg->format) {
      case ARG_FORMAT_ADDRESS: {
        char addr_full[43] = "0x";
        if (arg->value_len != 20) {
          return false;
        }
        ethereum_address_checksum(arg->value, addr_full + 2, false,
                                  stored_metadata.chain_id);
        snprintf(body, sizeof(body), "%s:\n%s", arg->name, addr_full);
        break;
      }
      case ARG_FORMAT_AMOUNT: {
        bignum256 amount;
        bn_from_metadata_bytes(arg->value, arg->value_len, &amount);
        /* Check for MAX_UINT256 (unlimited approval) */
        bool is_max = true;
        for (uint16_t j = 0; j < arg->value_len; j++) {
          if (arg->value[j] != 0xFF) {
            is_max = false;
            break;
          }
        }
        if (is_max && arg->value_len == 32) {
          snprintf(body, sizeof(body), "%s:\nUNLIMITED", arg->name);
        } else {
          char formatted[48];
          bn_format(&amount, NULL, " wei", 0, 0, false, formatted,
                    sizeof(formatted));
          snprintf(body, sizeof(body), "%s:\n%s", arg->name, formatted);
        }
        break;
      }
      case ARG_FORMAT_BYTES:
      case ARG_FORMAT_RAW:
      default: {
        char hex[(METADATA_MAX_ARG_VALUE_LEN * 2) + 1];
        size_t display_len = arg->value_len > 16 ? 16 : (size_t)arg->value_len;
        data2hex(arg->value, display_len, hex);
        snprintf(body, sizeof(body), "%s:\n%s%s", arg->name, hex,
                 arg->value_len > 16 ? "..." : "");
        break;
      }
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 stored_metadata.method_name, "%s", body)) {
      return false;
    }
  }

  /* User approved the decoded who/what/why. From here the raw-data confirm is
   * suppressed, so the signature MUST be bound to this metadata's tx hash. */
  relied_on_metadata = true;
  return true;
}

bool signed_metadata_relied(void) { return relied_on_metadata; }

bool signed_metadata_enforce_decision(bool relied, bool available,
                                      int classification,
                                      const uint8_t *stored_hash,
                                      const uint8_t *hash) {
  if (!relied) {
    return true; /* signature was not gated by metadata */
  }
  /* Fail closed: relied on metadata but it's gone, not verified, or the signed
   * digest differs from what was displayed → refuse to emit a signature.
   * tx_hash is 32 bytes (see SignedMetadata). */
  return hash != NULL && stored_hash != NULL && available &&
         classification == METADATA_VERIFIED &&
         memcmp(stored_hash, hash, 32) == 0;
}

bool signed_metadata_enforce(const uint8_t hash[32]) {
  return signed_metadata_enforce_decision(
      relied_on_metadata, metadata_available, stored_metadata.classification,
      stored_metadata.tx_hash, hash);
}

const SignedMetadata *signed_metadata_get(void) {
  return metadata_available ? &stored_metadata : NULL;
}
