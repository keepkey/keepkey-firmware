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
static bool metadata_signer_loaded = false;
/* v2 only: set true once decode_v2_args() has decoded this metadata's args from
 * the tx calldata. The v2 enforce path REQUIRES it — v2 has no committed
 * tx_hash, so this is the explicit proof (not an implicit call-order
 * assumption) that the displayed values came from the calldata being signed. */
static bool metadata_schema_decoded = false;
static SignedMetadata stored_metadata;

/*
 * Built-in metadata verification public keys.
 *
 * Phase 1 ships with NO built-in keys: every clearsign signer must be
 * loaded at runtime via LoadClearsignSigner (user-confirmed on device,
 * RAM-only, gone on reboot), and every transaction it vouches for is
 * preceded by a warning screen naming the signer's alias. There is no
 * hardcoded "KeepKey says this is safe" path in this phase.
 *
 * Phase 2 (once the offline signing infrastructure is hardened) puts the
 * KeepKey production key back in slot 0. A slot holding a built-in key can
 * never be shadowed by a loaded signer (see signed_metadata_signer_valid)
 * and is the only path that clearsigns without the warning screen.
 */
static const uint8_t METADATA_PUBKEYS[METADATA_MAX_KEYS][33] = {
    /* Key 0: production (returns in phase 2) */
    {0x00},
    /* Key 1: rotation slot */
    {0x00},
    {0x00},
    /* Key 3: was the DEBUG_LINK-only CI test key; CI now loads it through
     * LoadClearsignSigner so tests exercise the same warning flow users see. */
    {0x00},
};

/* Runtime-loaded signers. RAM only — cleared on reboot by construction. */
static uint8_t loaded_pubkeys[METADATA_MAX_KEYS][33];
static char loaded_aliases[METADATA_MAX_KEYS][METADATA_ALIAS_MAX_LEN + 1];

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

/* Per-format value validation, fail-closed at parse time. STRING and
 * TOKEN_AMOUNT carry display semantics, so their byte layout is enforced
 * before anything is stored; legacy formats keep their original 32-byte cap
 * (METADATA_MAX_ARG_VALUE_LEN grew only to fit TOKEN_AMOUNT). */
static bool arg_value_ok(uint8_t format, const uint8_t *value, uint16_t len) {
  switch (format) {
    case ARG_FORMAT_STRING: {
      /* Attested printable label ("protocol: Uniswap V2"). Rendered through
       * confirm() bodies: printable ASCII only, '%' excluded. */
      if (len == 0 || len > 32) {
        return false;
      }
      for (uint16_t i = 0; i < len; i++) {
        if (value[i] < 0x20 || value[i] > 0x7e || value[i] == '%') {
          return false;
        }
      }
      return true;
    }
    case ARG_FORMAT_TOKEN_AMOUNT: {
      /* decimals(1) + symbol_len(1) + symbol + amount(1..32 BE) */
      if (len < 4) {
        return false;
      }
      uint8_t decimals = value[0];
      uint8_t symlen = value[1];
      if (decimals > 36 || symlen == 0 ||
          symlen > METADATA_MAX_TOKEN_SYMBOL_LEN ||
          (uint16_t)(2 + symlen) >= len || len - 2 - symlen > 32) {
        return false;
      }
      for (uint8_t i = 0; i < symlen; i++) {
        char c = (char)value[2 + i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9');
        if (!ok) {
          return false;
        }
      }
      return true;
    }
    default:
      return len <= 32;
  }
}

/* chain_id(4) + contract(20) + selector(4) — shared by both blob versions. */
static bool parse_common_head(const uint8_t **cursor, const uint8_t *end,
                              SignedMetadata *out) {
  return read_be_u32(cursor, end, &out->chain_id) &&
         read_bytes(cursor, end, out->contract_address,
                    sizeof(out->contract_address)) &&
         read_bytes(cursor, end, out->selector, sizeof(out->selector));
}

/* classification(1) + timestamp(4) + key_id(1) + sig(64) + recovery(1), then
 * the cursor must land exactly on `end` — identical for v1 and v2. */
static bool parse_trailer(const uint8_t **cursor, const uint8_t *end,
                          SignedMetadata *out) {
  uint8_t classification = 0;
  if (!read_u8(cursor, end, &classification) || classification > 2 ||
      !read_be_u32(cursor, end, &out->timestamp) ||
      !read_u8(cursor, end, &out->key_id) ||
      !read_bytes(cursor, end, out->signature, sizeof(out->signature)) ||
      !read_u8(cursor, end, &out->recovery) || *cursor != end) {
    return false;
  }
  out->classification = (MetadataClassification)classification;
  return true;
}

/* v1 args: name + format + explicit (host-decoded) value. */
static bool parse_v1_args(const uint8_t **cursor, const uint8_t *end,
                          SignedMetadata *out) {
  for (uint8_t i = 0; i < out->num_args; i++) {
    uint8_t format = 0;
    uint16_t value_len = 0;
    MetadataArg *arg = &out->args[i];

    if (!read_arg_name(cursor, end, arg->name, METADATA_MAX_ARG_NAME_LEN) ||
        !read_u8(cursor, end, &format) || format > ARG_FORMAT_TOKEN_AMOUNT ||
        !read_be_u16(cursor, end, &value_len) ||
        value_len > METADATA_MAX_ARG_VALUE_LEN ||
        !read_bytes(cursor, end, arg->value, value_len) ||
        !arg_value_ok(format, arg->value, value_len)) {
      return false;
    }
    arg->format = (ArgFormat)format;
    arg->value_len = value_len;
  }
  return true;
}

/* v2 args: name + display format only (NO value — decoded from calldata later).
 * TOKEN_AMOUNT additionally carries its static decimals + symbol, pre-stored as
 * the value prefix [decimals, symlen, symbol...] so decode_v2_args() only has
 * to append the 32-byte amount word. v2 supports the fixed single-word ABI
 * types ADDRESS / AMOUNT / TOKEN_AMOUNT; anything else is out of scope -> blind
 * sign. */
static bool parse_v2_args(const uint8_t **cursor, const uint8_t *end,
                          SignedMetadata *out) {
  for (uint8_t i = 0; i < out->num_args; i++) {
    uint8_t format = 0;
    MetadataArg *arg = &out->args[i];

    if (!read_arg_name(cursor, end, arg->name, METADATA_MAX_ARG_NAME_LEN) ||
        !read_u8(cursor, end, &format)) {
      return false;
    }
    switch (format) {
      case ARG_FORMAT_ADDRESS:
      case ARG_FORMAT_AMOUNT:
        arg->value_len = 0; /* filled from the tx calldata at decode time */
        break;
      case ARG_FORMAT_TOKEN_AMOUNT: {
        uint8_t decimals = 0, symlen = 0;
        if (!read_u8(cursor, end, &decimals) ||
            !read_u8(cursor, end, &symlen) || decimals > 36 || symlen == 0 ||
            symlen > METADATA_MAX_TOKEN_SYMBOL_LEN ||
            (size_t)(end - *cursor) < symlen) {
          return false;
        }
        arg->value[0] = decimals;
        arg->value[1] = symlen;
        for (uint8_t j = 0; j < symlen; j++) {
          char c = (char)(*cursor)[j];
          bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9');
          if (!ok) {
            return false;
          }
          arg->value[2 + j] = (uint8_t)c;
        }
        *cursor += symlen;
        arg->value_len = (uint16_t)(2 + symlen);
        break;
      }
      default:
        return false;
    }
    arg->format = (ArgFormat)format;
  }
  return true;
}

static bool parse_metadata_binary(const uint8_t *payload, size_t payload_len,
                                  SignedMetadata *out) {
  const uint8_t *cursor = payload;
  const uint8_t *end = payload + payload_len;
  memset(out, 0, sizeof(*out));

  if (!read_u8(&cursor, end, &out->version)) {
    return false;
  }

  if (out->version == METADATA_VERSION_LEGACY) {
    /* Min: version(1)+chain_id(4)+contract(20)+selector(4)+tx_hash(32)+
     * method_len(2)+method(1)+num_args(1)+trailer(71) = 136 */
    if (payload_len < 136 || !parse_common_head(&cursor, end, out) ||
        !read_bytes(&cursor, end, out->tx_hash, sizeof(out->tx_hash)) ||
        !read_string(&cursor, end, out->method_name, METADATA_MAX_METHOD_LEN) ||
        !read_u8(&cursor, end, &out->num_args) ||
        out->num_args > METADATA_MAX_ARGS ||
        !parse_v1_args(&cursor, end, out)) {
      return false;
    }
  } else if (out->version == METADATA_VERSION_SCHEMA) {
    /* Min (0 args): version(1)+chain_id(4)+contract(20)+selector(4)+
     * method_len(2)+method(1)+num_args(1)+trailer(71) = 104 (no tx_hash) */
    if (payload_len < 104 || !parse_common_head(&cursor, end, out) ||
        !read_string(&cursor, end, out->method_name, METADATA_MAX_METHOD_LEN) ||
        !read_u8(&cursor, end, &out->num_args) ||
        out->num_args > METADATA_MAX_ARGS ||
        !parse_v2_args(&cursor, end, out)) {
      return false;
    }
  } else {
    return false;
  }

  return parse_trailer(&cursor, end, out);
}

/*
 * v2 decode: fill each schema arg's value from the transaction calldata.
 *
 * All v2 args are fixed single 32-byte ABI head words, laid out sequentially
 * from offset 4 (right after the selector). We require the ENTIRE calldata to
 * be exactly selector + num_args words, wholly present in the initial chunk —
 * so the device decodes, displays, AND signs the same bytes with nothing hidden
 * in a later chunk or trailing the words. That structural completeness is what
 * binds the displayed decode to the signature; v2 has no tx_hash.
 */
static bool decode_v2_args(SignedMetadata *md, const EthereumSignTx *msg) {
  uint32_t expected = 4u + 32u * (uint32_t)md->num_args;
  uint32_t initsz = msg->data_initial_chunk.size;
  uint32_t total = msg->has_data_length ? msg->data_length : initsz;
  if (total != expected || initsz != expected) {
    return false;
  }

  for (uint8_t i = 0; i < md->num_args; i++) {
    const uint8_t *word = msg->data_initial_chunk.bytes + 4 + 32u * i;
    MetadataArg *arg = &md->args[i];

    switch (arg->format) {
      case ARG_FORMAT_ADDRESS:
        /* ABI address is a left-zero-padded 20-byte value; reject dirty high
         * bytes rather than silently truncate (they could hide meaning). */
        for (int j = 0; j < 12; j++) {
          if (word[j] != 0) {
            return false;
          }
        }
        memcpy(arg->value, word + 12, 20);
        arg->value_len = 20;
        break;
      case ARG_FORMAT_AMOUNT:
        memcpy(arg->value, word, 32);
        arg->value_len = 32;
        break;
      case ARG_FORMAT_TOKEN_AMOUNT: {
        /* value holds [decimals, symlen, symbol] from parse; append the amount.
         * Derive the prefix from symlen (value[1]), NOT the current value_len,
         * so a repeated decode of the same arg is idempotent (value_len already
         * includes a previously-appended amount; value[1] does not change). */
        uint16_t prefix = (uint16_t)(2 + arg->value[1]);
        if ((size_t)prefix + 32 > METADATA_MAX_ARG_VALUE_LEN) {
          return false;
        }
        memcpy(arg->value + prefix, word, 32);
        arg->value_len = (uint16_t)(prefix + 32);
        break;
      }
      default:
        return false;
    }
  }
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

bool signed_metadata_schema_decoded(void) { return metadata_schema_decoded; }

void signed_metadata_clear(void) {
  memzero(&stored_metadata, sizeof(stored_metadata));
  metadata_available = false;
  relied_on_metadata = false;
  metadata_signer_loaded = false;
  metadata_schema_decoded = false;
}

void signed_metadata_clear_signers(void) {
  memzero(loaded_pubkeys, sizeof(loaded_pubkeys));
  memzero(loaded_aliases, sizeof(loaded_aliases));
  /* Metadata verified by a now-dropped signer must not outlive it. */
  signed_metadata_clear();
}

bool signed_metadata_signer_valid(uint8_t key_id, const uint8_t *pubkey,
                                  size_t pubkey_len, const char *alias) {
  curve_point point;
  size_t alias_len;

  if (key_id >= METADATA_MAX_KEYS || METADATA_PUBKEYS[key_id][0] != 0x00 ||
      !pubkey || pubkey_len != 33 || !alias) {
    return false;
  }

  /* Alias is rendered INSIDE quotes on the load screen and the per-tx warning
   * ("Trust signer '%s' ..."). Restrict to a strict allowlist — letters,
   * digits, space, '-' and '_' — so a host-chosen alias cannot break out of
   * its quoted region or inject a semantic trust claim (e.g. a quote to close
   * the quotes, or "." / "(" to append "verified by KeepKey."). '%' is also
   * excluded so it can never reach the format string as a specifier. */
  alias_len = strlen(alias);
  if (alias_len == 0 || alias_len > METADATA_ALIAS_MAX_LEN) {
    return false;
  }
  for (size_t i = 0; i < alias_len; i++) {
    char c = alias[i];
    bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == ' ' || c == '-' || c == '_';
    if (!ok) {
      return false;
    }
  }

  /* Compressed form only — ecdsa_read_pubkey would read 65 bytes for an
   * uncompressed 0x04 prefix, past our 33-byte buffer. Requiring 0x02/0x03
   * also excludes the all-zero "empty slot" sentinel. */
  if (pubkey[0] != 0x02 && pubkey[0] != 0x03) {
    return false;
  }
  return ecdsa_read_pubkey(&secp256k1, pubkey, &point) == 1;
}

void signed_metadata_store_signer(uint8_t key_id, const uint8_t *pubkey,
                                  const char *alias) {
  if (key_id >= METADATA_MAX_KEYS) {
    return;
  }
  memcpy(loaded_pubkeys[key_id], pubkey, sizeof(loaded_pubkeys[key_id]));
  strlcpy(loaded_aliases[key_id], alias, sizeof(loaded_aliases[key_id]));
  /* Replacing a signer invalidates anything the old one verified. */
  signed_metadata_clear();
}

void signed_metadata_pubkey_fingerprint(const uint8_t pubkey[33],
                                        char out[METADATA_FINGERPRINT_LEN]) {
  uint8_t digest[32];
  sha256_Raw(pubkey, 33, digest);
  data2hex(digest, 4, out);
  memzero(digest, sizeof(digest));
}

bool signed_metadata_from_loaded_signer(void) {
  return metadata_available && metadata_signer_loaded;
}

/* Resolve the verification key for a slot. Built-in keys win; a runtime-
 * loaded signer can only occupy an empty built-in slot. */
static const uint8_t *metadata_pubkey_for(uint8_t key_id, bool *is_loaded) {
  *is_loaded = false;
  if (key_id >= METADATA_MAX_KEYS) {
    return NULL;
  }
  if (METADATA_PUBKEYS[key_id][0] != 0x00) {
    return METADATA_PUBKEYS[key_id];
  }
  if (loaded_pubkeys[key_id][0] != 0x00) {
    *is_loaded = true;
    return loaded_pubkeys[key_id];
  }
  return NULL;
}

MetadataClassification signed_metadata_process(const uint8_t *payload,
                                               size_t payload_len,
                                               uint8_t key_id) {
  uint8_t digest[32];
  size_t signed_len;
  bool is_loaded = false;
  const uint8_t *pubkey;

  signed_metadata_clear();

  pubkey = metadata_pubkey_for(key_id, &is_loaded);
  if (!pubkey || !payload || payload_len < 65) {
    return METADATA_MALFORMED;
  }

  if (!parse_metadata_binary(payload, payload_len, &stored_metadata) ||
      stored_metadata.key_id != key_id) {
    signed_metadata_clear();
    return METADATA_MALFORMED;
  }

  signed_len = payload_len - sizeof(stored_metadata.signature) - 1;
  sha256_Raw(payload, signed_len, digest);

  if (ecdsa_verify_digest(&secp256k1, pubkey, stored_metadata.signature,
                          digest) != 0) {
    signed_metadata_clear();
    return METADATA_MALFORMED;
  }

  metadata_available = true;
  metadata_signer_loaded = is_loaded;
  return stored_metadata.classification;
}

bool signed_metadata_matches_tx(const EthereumSignTx *msg) {
  /* Reset the v2 decode proof up front: it must reflect ONLY the current call.
   * Any early return below (unavailable, wrong contract/selector/chain) leaves
   * it false, so a stale `true` from a prior successful match can never let
   * signed_metadata_enforce() pass for a v2 blob that did not decode this tx.
   */
  metadata_schema_decoded = false;

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

  if (stored_metadata.version == METADATA_VERSION_SCHEMA) {
    /* v2 has no committed values or tx_hash: decode the args straight from the
     * calldata this tx will sign. Success here means the schema fully accounts
     * for the calldata (decode_v2_args enforces exact length + presence), so
     * the display is bound to the signature structurally — nothing is enforced
     * later against a digest (there is no tx_hash). A decode failure falls
     * through to the normal blind-sign path. Record the decode explicitly:
     * signed_metadata_enforce() requires it for v2, so a signature can never be
     * emitted for a v2 blob whose args were not decoded from this tx. */
    metadata_schema_decoded = decode_v2_args(&stored_metadata, msg);
    return metadata_schema_decoded;
  }

  /* v1 only gates what we DISPLAY (so a benign-looking method screen can't be
   * shown for the wrong call). The metadata commits to the full tx hash; that
   * is enforced against the real signed digest in signed_metadata_enforce()
   * because the digest does not exist until send_signature() finalizes it. */
  return true;
}

bool signed_metadata_confirm(void) {
  char body[128];

  if (!metadata_available ||
      stored_metadata.classification != METADATA_VERIFIED) {
    return false;
  }

  if (metadata_signer_loaded) {
    /* Warning screen FIRST, before any clearsign page: the decode below is
     * vouched for by a signer the user loaded, not by KeepKey. */
    char fingerprint[METADATA_FINGERPRINT_LEN];
    signed_metadata_pubkey_fingerprint(loaded_pubkeys[stored_metadata.key_id],
                                       fingerprint);
    memset(body, 0, sizeof(body));
    snprintf(body, sizeof(body),
             "Signer '%s' (%s) you loaded describes this tx. NOT verified by "
             "KeepKey.",
             loaded_aliases[stored_metadata.key_id], fingerprint);
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Clearsign Warning", "%s", body)) {
      return false;
    }

    /* Method screen without the "Insight Verified" branding/icon — that
     * presentation is reserved for the built-in (phase 2) keys. */
    memset(body, 0, sizeof(body));
    snprintf(body, sizeof(body), "Call:\n%s", stored_metadata.method_name);
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Clearsign",
                 "%s", body)) {
      return false;
    }
  } else {
    /* Screen 1: Verified method — use review_with_icon for trust indicator */
    memset(body, 0, sizeof(body));
    snprintf(body, sizeof(body), "Verified call:\n%s",
             stored_metadata.method_name);
    if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           VERIFIED_ICON, "Insight Verified", "%s", body)) {
      return false;
    }
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
      case ARG_FORMAT_STRING: {
        /* Attested printable label, validated at parse (arg_value_ok). */
        char text[33];
        memcpy(text, arg->value, arg->value_len);
        text[arg->value_len] = '\0';
        snprintf(body, sizeof(body), "%s:\n%s", arg->name, text);
        break;
      }
      case ARG_FORMAT_TOKEN_AMOUNT: {
        /* decimals + symbol + big-endian amount, validated at parse.
         * This is the "Amount: 1,000 USDC" the clear-signing plan calls for
         * instead of a raw wei integer. */
        uint8_t decimals = arg->value[0];
        uint8_t symlen = arg->value[1];
        char suffix[METADATA_MAX_TOKEN_SYMBOL_LEN + 2];
        suffix[0] = ' ';
        memcpy(suffix + 1, arg->value + 2, symlen);
        suffix[1 + symlen] = '\0';

        const uint8_t *amt = arg->value + 2 + symlen;
        uint16_t amt_len = arg->value_len - 2 - symlen;
        bool is_max = amt_len == 32;
        for (uint16_t j = 0; j < amt_len && is_max; j++) {
          if (amt[j] != 0xFF) {
            is_max = false;
          }
        }
        if (is_max) {
          snprintf(body, sizeof(body), "%s:\nUNLIMITED%s", arg->name, suffix);
        } else {
          bignum256 amount;
          bn_from_metadata_bytes(amt, amt_len, &amount);
          char formatted[48];
          bn_format(&amount, NULL, suffix, decimals, 0, false, formatted,
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

bool signed_metadata_enforce_schema_decision(bool relied, bool available,
                                             bool decoded, int classification) {
  /* v2 (static schema) has no committed tx_hash. Its binding is structural: the
   * args were decoded from the exact calldata being signed, and that calldata
   * cannot change between decode and sign within one signing operation. So if
   * we relied on a verified v2 decode, signing may proceed; there is no digest
   * to compare. `decoded` is the explicit proof that decode_v2_args() ran and
   * succeeded for this signing operation — required rather than inferred from
   * call order, since v2 has no digest fallback. If we did not rely on the
   * metadata, signing was never gated by it. */
  return !relied ||
         (available && decoded && classification == METADATA_VERIFIED);
}

bool signed_metadata_enforce(const uint8_t hash[32]) {
  if (metadata_available &&
      stored_metadata.version == METADATA_VERSION_SCHEMA) {
    return signed_metadata_enforce_schema_decision(
        relied_on_metadata, metadata_available, metadata_schema_decoded,
        stored_metadata.classification);
  }
  return signed_metadata_enforce_decision(
      relied_on_metadata, metadata_available, stored_metadata.classification,
      stored_metadata.tx_hash, hash);
}

const SignedMetadata *signed_metadata_get(void) {
  return metadata_available ? &stored_metadata : NULL;
}
