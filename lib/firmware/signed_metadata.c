#include "keepkey/firmware/signed_metadata.h"

#include "keepkey/firmware/clearsign_root.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/draw.h"     // draw_bitmap_mono_rle_valid
#include "keepkey/board/layout.h"   // RUNTIME_ICON + layout_set_runtime_icon
#include "keepkey/board/variant.h"  // Image / AnimationFrame
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/storage.h"
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
static uint8_t metadata_tier = METADATA_TIER_NONE;

/* Set ONLY on the certified path, cleared with everything else. A delegation
 * never outlives the message that carried it. */
static char delegate_alias[CLEARSIGN_ALIAS_LEN + 1];
static char delegate_fp[METADATA_FINGERPRINT_LEN];
static uint32_t delegate_chain_id;
static bool delegate_may_suppress;
/* v2 only: set true once decode_v2_args() has decoded this metadata's args from
 * the tx calldata. The v2 enforce path REQUIRES it — v2 has no committed
 * tx_hash, so this is the explicit proof (not an implicit call-order
 * assumption) that the displayed values came from the calldata being signed. */
/* Set during matching: this tx carries native value, so the amount screen
 * must NOT be suppressed even though the schema matched. */
static bool metadata_schema_moves_value = false;
static bool metadata_schema_decoded = false;
static SignedMetadata stored_metadata;

/* Runtime signer slots remain a development/self-service lane. Production v3
 * metadata carries a root-certified delegate in the message and never writes
 * that delegate into this ring. */

/* Runtime-loaded signers. RAM only — cleared on reboot by construction. RC18
 * deliberately rejects persistent trust anchors: the public storage section
 * has no authenticated integrity against physical flash modification. */
static uint8_t loaded_pubkeys[METADATA_MAX_KEYS][33];
static char loaded_aliases[METADATA_MAX_KEYS][METADATA_ALIAS_MAX_LEN + 1];
/* Per-slot session icon (1bpp mono RLE). icon_len==0 => text-only identity. */
#if !ZCASH_PRIVACY
static uint8_t loaded_icons[METADATA_MAX_KEYS][METADATA_ICON_MAX];
static uint8_t loaded_icon_w[METADATA_MAX_KEYS];
static uint8_t loaded_icon_h[METADATA_MAX_KEYS];
static uint16_t loaded_icon_len[METADATA_MAX_KEYS];
#endif

static bool read_u8(const uint8_t** cursor, const uint8_t* end, uint8_t* out) {
  if ((size_t)(end - *cursor) < 1) {
    return false;
  }

  *out = **cursor;
  *cursor += 1;
  return true;
}

static bool read_be_u16(const uint8_t** cursor, const uint8_t* end,
                        uint16_t* out) {
  if ((size_t)(end - *cursor) < 2) {
    return false;
  }

  *out = ((uint16_t)(*cursor)[0] << 8) | (*cursor)[1];
  *cursor += 2;
  return true;
}

static bool read_be_u32(const uint8_t** cursor, const uint8_t* end,
                        uint32_t* out) {
  if ((size_t)(end - *cursor) < 4) {
    return false;
  }

  *out = ((uint32_t)(*cursor)[0] << 24) | ((uint32_t)(*cursor)[1] << 16) |
         ((uint32_t)(*cursor)[2] << 8) | (*cursor)[3];
  *cursor += 4;
  return true;
}

static bool read_bytes(const uint8_t** cursor, const uint8_t* end, uint8_t* out,
                       size_t size) {
  if ((size_t)(end - *cursor) < size) {
    return false;
  }

  memcpy(out, *cursor, size);
  *cursor += size;
  return true;
}

/* method_name and arg names render through confirm() bodies exactly like
 * STRING values and signer aliases do — hold them to the same allowlist
 * (printable ASCII, '%' excluded) so no metadata-carried text can embed
 * control bytes or format specifiers. Only a trusted signer could author
 * such a blob, but the charset rule should not depend on who signs. */
static bool display_text_ok(const uint8_t* text, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (text[i] < 0x20 || text[i] > 0x7e || text[i] == '%') {
      return false;
    }
  }
  return true;
}

static bool read_string(const uint8_t** cursor, const uint8_t* end, char* out,
                        size_t max_len) {
  uint16_t value_len = 0;
  if (!read_be_u16(cursor, end, &value_len) || value_len == 0 ||
      value_len > max_len || (size_t)(end - *cursor) < value_len) {
    return false;
  }
  if (!display_text_ok(*cursor, value_len)) {
    return false;
  }

  memcpy(out, *cursor, value_len);
  out[value_len] = '\0';
  *cursor += value_len;
  return true;
}

static bool read_arg_name(const uint8_t** cursor, const uint8_t* end, char* out,
                          size_t max_len) {
  uint8_t value_len = 0;
  if (!read_u8(cursor, end, &value_len) || value_len == 0 ||
      value_len > max_len || (size_t)(end - *cursor) < value_len) {
    return false;
  }
  if (!display_text_ok(*cursor, value_len)) {
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
static bool arg_value_ok(uint8_t format, const uint8_t* value, uint16_t len) {
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
static bool parse_common_head(const uint8_t** cursor, const uint8_t* end,
                              SignedMetadata* out) {
  return read_be_u32(cursor, end, &out->chain_id) &&
         read_bytes(cursor, end, out->contract_address,
                    sizeof(out->contract_address)) &&
         read_bytes(cursor, end, out->selector, sizeof(out->selector));
}

/* classification(1) + timestamp(4) + key_id(1) + sig(64) + recovery(1), then
 * the cursor must land exactly on `end` — identical for v1 and v2. */
static bool parse_trailer(const uint8_t** cursor, const uint8_t* end,
                          SignedMetadata* out) {
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
static bool parse_v1_args(const uint8_t** cursor, const uint8_t* end,
                          SignedMetadata* out) {
  for (uint8_t i = 0; i < out->num_args; i++) {
    uint8_t format = 0;
    uint16_t value_len = 0;
    MetadataArg* arg = &out->args[i];

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
static bool parse_v2_args(const uint8_t** cursor, const uint8_t* end,
                          SignedMetadata* out) {
  for (uint8_t i = 0; i < out->num_args; i++) {
    uint8_t format = 0;
    MetadataArg* arg = &out->args[i];

    if (!read_arg_name(cursor, end, arg->name, METADATA_MAX_ARG_NAME_LEN) ||
        !read_u8(cursor, end, &format)) {
      return false;
    }
    switch (format) {
      case ARG_FORMAT_ADDRESS:
      case ARG_FORMAT_AMOUNT:
      /* BYTES covers an opaque fixed word — an order/request id, say — which
       * a router genuinely cannot render as an address or an amount. It still
       * consumes exactly one 32-byte ABI word, so structural completeness is
       * unaffected; only the rendering differs (hex, first 16 bytes). */
      case ARG_FORMAT_BYTES:
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

static bool parse_metadata_binary(const uint8_t* payload, size_t payload_len,
                                  SignedMetadata* out) {
  const uint8_t* cursor = payload;
  const uint8_t* end = payload + payload_len;
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
  } else if (out->version == METADATA_VERSION_DYNAMIC_SCHEMA) {
    /* Min: version(1)+chain_id(4)+contract(20)+selector(4)+method_len(2)+
     * method(1)+decoder_id(1)+trailer(71) = 104.  The decoder owns the
     * argument labels and formats so a delegate cannot change what the device
     * claims to have parsed. */
    if (payload_len < 104 || !parse_common_head(&cursor, end, out) ||
        !read_string(&cursor, end, out->method_name, METADATA_MAX_METHOD_LEN) ||
        !read_u8(&cursor, end, &out->decoder_id) ||
        out->decoder_id != METADATA_DECODER_PORTALS_NATIVE_ORDER_V1) {
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
static bool decode_v2_args(SignedMetadata* md, const EthereumSignTx* msg) {
  uint32_t expected = 4u + 32u * (uint32_t)md->num_args;
  uint32_t initsz = msg->data_initial_chunk.size;
  uint32_t total = msg->has_data_length ? msg->data_length : initsz;
  if (total != expected || initsz != expected) {
    return false;
  }

  for (uint8_t i = 0; i < md->num_args; i++) {
    const uint8_t* word = msg->data_initial_chunk.bytes + 4 + 32u * i;
    MetadataArg* arg = &md->args[i];

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
      case ARG_FORMAT_BYTES:
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

static bool word_is_zero(const uint8_t* word) {
  for (size_t i = 0; i < 32; i++) {
    if (word[i] != 0) return false;
  }
  return true;
}

static bool word_u32(const uint8_t* word, uint32_t* out) {
  for (size_t i = 0; i < 28; i++) {
    if (word[i] != 0) return false;
  }
  *out = ((uint32_t)word[28] << 24) | ((uint32_t)word[29] << 16) |
         ((uint32_t)word[30] << 8) | word[31];
  return true;
}

static bool word_address(const uint8_t* word, uint8_t out[20]) {
  for (size_t i = 0; i < 12; i++) {
    if (word[i] != 0) return false;
  }
  memcpy(out, word + 12, 20);
  return true;
}

static bool bytes_nonzero(const uint8_t* bytes, size_t size) {
  for (size_t i = 0; i < size; i++) {
    if (bytes[i] != 0) return true;
  }
  return false;
}

static bool word_matches_value(const uint8_t word[32],
                               const EthereumSignTx* msg) {
  size_t value_len = msg->has_value ? msg->value.size : 0;
  if (value_len > 32) return false;
  size_t pad = 32 - value_len;
  for (size_t i = 0; i < pad; i++) {
    if (word[i] != 0) return false;
  }
  return value_len == 0 || memcmp(word + pad, msg->value.bytes, value_len) == 0;
}

static void set_dynamic_arg(MetadataArg* arg, const char* name,
                            ArgFormat format, const uint8_t* value,
                            uint16_t value_len) {
  strlcpy(arg->name, name, sizeof(arg->name));
  arg->format = format;
  memcpy(arg->value, value, value_len);
  arg->value_len = value_len;
}

/* PortalsRouter.portal((Order,Call[]),partner), selector 0xa2e42c65.
 *
 * The exact contract and selector are independently bound by matches_tx().
 * PortalsRouter's verified implementation snapshots recipient's output-token
 * balance, runs the dynamic calls, and reverts unless the received delta is at
 * least minOutputAmount.  Consequently the safety-defining fields are the
 * outer Order, all of which are in the first 260 bytes.  The calls may extend
 * past the 1024-byte initial chunk; they can choose HOW the immutable router
 * obtains the output, but cannot change WHAT token/recipient/minimum the router
 * enforces or spend more native value than this transaction supplies.
 *
 * We still validate canonical outer offsets and the complete Call[] offset
 * table.  Any ambiguity, dirty address word, non-native input, value mismatch,
 * empty call set, or malformed boundary fails back to blind signing. */
static bool decode_portals_native_order(SignedMetadata* md,
                                        const EthereumSignTx* msg) {
  enum {
    PORTALS_MIN_INITIAL = 292,
    PORTALS_MIN_TOTAL = 452,
    PORTALS_MAX_TOTAL = 16388,
    PORTALS_MAX_CALLS = 16,
  };
  static const uint8_t portals_router[20] = {
      0xbf, 0x5a, 0x7f, 0x36, 0x29, 0xfb, 0x32, 0x5e, 0x2a, 0x84,
      0x53, 0xd5, 0x95, 0xab, 0x10, 0x34, 0x65, 0xf7, 0x5e, 0x62};
  static const uint8_t portals_selector[4] = {0xa2, 0xe4, 0x2c, 0x65};

  /* This decoder relies on this immutable router's verified postcondition, so
   * the hot delegate must not be able to assign it to an arbitrary contract
   * with the same ABI. Pin all three identity dimensions in firmware in
   * addition to the signed schema/transaction match performed by the caller. */
  if (md->chain_id != 1 ||
      memcmp(md->contract_address, portals_router, sizeof(portals_router)) !=
          0 ||
      memcmp(md->selector, portals_selector, sizeof(portals_selector)) != 0) {
    return false;
  }
  uint32_t initsz = msg->data_initial_chunk.size;
  uint32_t total = msg->has_data_length ? msg->data_length : initsz;
  if (initsz < PORTALS_MIN_INITIAL || total < PORTALS_MIN_TOTAL ||
      total > PORTALS_MAX_TOTAL || total < initsz || (total - 4u) % 32u != 0) {
    return false;
  }

  const uint8_t* data = msg->data_initial_chunk.bytes;
  uint32_t order_offset = 0, calls_offset = 0, call_count = 0;
  if (!word_u32(data + 4, &order_offset) || order_offset != 0x40 ||
      !word_u32(data + 228, &calls_offset) || calls_offset != 0xc0 ||
      !word_u32(data + 260, &call_count) || call_count == 0 ||
      call_count > PORTALS_MAX_CALLS) {
    return false;
  }

  /* The complete element-offset table must be in the authenticated initial
   * chunk.  Offsets are relative to the byte immediately after array length. */
  uint32_t offset_table_end = 292u + call_count * 32u;
  if (offset_table_end > initsz) return false;
  uint32_t previous = 0;
  for (uint32_t i = 0; i < call_count; i++) {
    uint32_t offset = 0;
    if (!word_u32(data + 292u + i * 32u, &offset) || offset % 32u != 0 ||
        offset < call_count * 32u || (i == 0 && offset != call_count * 32u) ||
        (i > 0 && offset <= previous) || offset > total - 292u - 128u) {
      return false;
    }
    previous = offset;
  }

  const uint8_t* input_token = data + 68;
  const uint8_t* input_amount = data + 100;
  const uint8_t* output_token_word = data + 132;
  const uint8_t* minimum_output = data + 164;
  const uint8_t* recipient_word = data + 196;
  const uint8_t* partner_word = data + 36;
  uint8_t output_token[20], recipient[20], partner[20];
  if (!word_is_zero(input_token) || !bytes_nonzero(input_amount, 32) ||
      !word_matches_value(input_amount, msg) ||
      !word_address(output_token_word, output_token) ||
      !bytes_nonzero(output_token, sizeof(output_token)) ||
      !bytes_nonzero(minimum_output, 32) ||
      !word_address(recipient_word, recipient) ||
      !bytes_nonzero(recipient, sizeof(recipient)) ||
      !word_address(partner_word, partner)) {
    return false;
  }

  md->num_args = 3;
  strlcpy(md->method_name, "Portals swap", sizeof(md->method_name));
  set_dynamic_arg(&md->args[0], "Output token", ARG_FORMAT_ADDRESS,
                  output_token, sizeof(output_token));

  /* TOKEN_AMOUNT with zero decimals and the literal unit label gives an
   * honest decimal integer without incorrectly calling arbitrary ERC-20 base
   * units "wei".  Token decimals are not part of this router calldata. */
  uint8_t units_value[2 + 5 + 32] = {0, 5, 'u', 'n', 'i', 't', 's'};
  memcpy(units_value + 7, minimum_output, 32);
  set_dynamic_arg(&md->args[1], "Minimum output", ARG_FORMAT_TOKEN_AMOUNT,
                  units_value, sizeof(units_value));
  set_dynamic_arg(&md->args[2], "Recipient", ARG_FORMAT_ADDRESS, recipient,
                  sizeof(recipient));
  return true;
}

static void bn_from_metadata_bytes(const uint8_t* value, size_t value_len,
                                   bignum256* out) {
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

bool signed_metadata_schema_moves_value(void) {
  return metadata_schema_moves_value;
}

void signed_metadata_clear(void) {
  memzero(&stored_metadata, sizeof(stored_metadata));
  metadata_available = false;
  relied_on_metadata = false;
  metadata_tier = METADATA_TIER_NONE;
  memzero(delegate_alias, sizeof(delegate_alias));
  memzero(delegate_fp, sizeof(delegate_fp));
  delegate_chain_id = 0;
  delegate_may_suppress = false;
  metadata_schema_decoded = false;
}

void signed_metadata_clear_signers(void) {
  memzero(loaded_pubkeys, sizeof(loaded_pubkeys));
  memzero(loaded_aliases, sizeof(loaded_aliases));
#if !ZCASH_PRIVACY
  memzero(loaded_icons, sizeof(loaded_icons));
  memzero(loaded_icon_w, sizeof(loaded_icon_w));
  memzero(loaded_icon_h, sizeof(loaded_icon_h));
  memzero(loaded_icon_len, sizeof(loaded_icon_len));
#endif
  /* Metadata verified by a now-dropped signer must not outlive it. */
  signed_metadata_clear();
}

bool signed_metadata_signer_valid(uint8_t key_id, const uint8_t* pubkey,
                                  size_t pubkey_len, const char* alias) {
  curve_point point;
  size_t alias_len;

  if (key_id >= METADATA_MAX_KEYS || !pubkey || pubkey_len != 33 || !alias) {
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

bool signed_metadata_store_signer(uint8_t key_id, const uint8_t* pubkey,
                                  const char* alias, const uint8_t* icon,
                                  uint8_t icon_w, uint8_t icon_h,
                                  uint16_t icon_len, bool persist) {
  /* Fail before changing the RAM slot. A caller asking for persistence must
   * never receive a session-only downgrade it could mistake for durable trust.
   * Persistence can return only after authenticated storage binding exists. */
  if (persist || key_id >= METADATA_MAX_KEYS) {
    return false;
  }
  memcpy(loaded_pubkeys[key_id], pubkey, sizeof(loaded_pubkeys[key_id]));
  strlcpy(loaded_aliases[key_id], alias, sizeof(loaded_aliases[key_id]));

  /* A load without an icon clears any prior one for the slot (icon_len
   * already validated <= max by the caller — belt-and-braces here). */
  bool has_icon = icon && icon_len > 0 && icon_len <= METADATA_ICON_MAX;

  /* Session icon into the RAM working slot. The Orchard build omits this
   * cosmetic cache to preserve its tight SRAM margin; signers remain usable
   * and render text-only after the mandatory load confirmation. */
#if !ZCASH_PRIVACY
  memzero(loaded_icons[key_id], sizeof(loaded_icons[key_id]));
  if (has_icon) {
    memcpy(loaded_icons[key_id], icon, icon_len);
    loaded_icon_w[key_id] = icon_w;
    loaded_icon_h[key_id] = icon_h;
    loaded_icon_len[key_id] = icon_len;
  } else {
    loaded_icon_w[key_id] = 0;
    loaded_icon_h[key_id] = 0;
    loaded_icon_len[key_id] = 0;
  }
#else
  (void)has_icon;
  (void)icon_w;
  (void)icon_h;
#endif

  /* Replacing a signer invalidates anything the old one verified. */
  signed_metadata_clear();
  return true;
}

/* Resolve the alias for a session slot. */
const char* signed_metadata_signer_alias(uint8_t key_id) {
  if (key_id >= METADATA_MAX_KEYS) return NULL;
  if (loaded_pubkeys[key_id][0] != 0x00) return loaded_aliases[key_id];
  return NULL;
}

/* Resolve the icon for a session slot. Returns false for a text-only slot. */
/* An icon is renderable only if its geometry fits the confirm's icon column
 * AND its RLE stream decodes exactly to that geometry. This is the single
 * choke point for session icons: signed_metadata_signer_icon() is what both the
 * load-confirm and the per-tx identity screen call, and the per-tx screen
 * stages the frame itself (it never goes through stage_runtime_icon). Fail
 * closed to a text-only identity: a missing logo is cosmetic, an over-wide one
 * erases the alias, fingerprint and the "NOT verified by KeepKey" warning. */
#if !ZCASH_PRIVACY
static bool icon_renderable(const uint8_t* icon, uint16_t icon_len,
                            uint8_t icon_w, uint8_t icon_h) {
  if (!icon || icon_len == 0) return false;
  if (icon_w == 0 || icon_w > LEFT_MARGIN_WITH_ICON) return false;
  if (icon_h == 0 || icon_h > 64) return false;
  return draw_bitmap_mono_rle_valid(icon, (uint32_t)icon_len, icon_w, icon_h);
}
#endif

bool signed_metadata_signer_icon(uint8_t key_id, const uint8_t** icon_out,
                                 uint8_t* w_out, uint8_t* h_out,
                                 uint16_t* len_out) {
  if (key_id >= METADATA_MAX_KEYS) return false;
  if (loaded_pubkeys[key_id][0] != 0x00) {
#if ZCASH_PRIVACY
    (void)icon_out;
    (void)w_out;
    (void)h_out;
    (void)len_out;
    return false;
#else
    if (loaded_icon_len[key_id] == 0) return false;
    if (!icon_renderable(loaded_icons[key_id], loaded_icon_len[key_id],
                         loaded_icon_w[key_id], loaded_icon_h[key_id])) {
      return false;
    }
    if (icon_out) *icon_out = loaded_icons[key_id];
    if (w_out) *w_out = loaded_icon_w[key_id];
    if (h_out) *h_out = loaded_icon_h[key_id];
    if (len_out) *len_out = loaded_icon_len[key_id];
    return true;
#endif
  }
  return false;
}

/* Render an AnimationFrame from a stored icon into the confirm's left column.
 * Image + frame are the CALLER's (must outlive the synchronous confirm); this
 * only wires them up. Returns RUNTIME_ICON when an icon was set, else NO_ICON.
 * Positioning tuned on device — icon column is ~40px, height 64px. */
static IconType stage_runtime_icon(Image* img, AnimationFrame* frame,
                                   const uint8_t* icon, uint8_t icon_w,
                                   uint8_t icon_h, uint16_t icon_len) {
  if (!icon || icon_len == 0) return NO_ICON;
  /* Fail closed on an over-wide icon rather than drawing it at x=0: text begins
   * at x=40 and the icon is drawn AFTER the text, so a wider icon would paint
   * over the alias, fingerprint and the "NOT verified by KeepKey" warning.
   * The load handler already checks this, but enforce it again at the point of
   * use. Dropping the logo degrades to a text-only identity; letting it erase
   * the warning does not. */
  if (icon_w == 0 || icon_w > LEFT_MARGIN_WITH_ICON || icon_h == 0 ||
      icon_h > 64) {
    return NO_ICON;
  }
  img->w = icon_w;
  img->h = icon_h;
  img->length = icon_len;
  img->data = icon;
  /* Center inside the confirm's left icon column (LEFT_MARGIN_WITH_ICON=40px).
   * Vertically center in the 64px height. */
  frame->x = (uint16_t)((LEFT_MARGIN_WITH_ICON - icon_w) / 2);
  frame->y = (icon_h < 64) ? (uint16_t)((64 - icon_h) / 2) : 0;
  frame->duration = 0;
  /* Decoder does value*color/100; color=100 => data bytes are direct 0-255. */
  frame->color = 100;
  frame->image = img;
  layout_set_runtime_icon(frame);
  return RUNTIME_ICON;
}

bool signed_metadata_confirm_load(const char* alias, const char* fingerprint,
                                  const uint8_t* icon, uint8_t icon_w,
                                  uint8_t icon_h, uint16_t icon_len) {
  /* Draw the logo only in a build that also keeps the session icon cache. In a
   * build without it, signed_metadata_signer_icon() returns false for the rest
   * of the session, so no per-tx screen can repeat the logo -- and a logo shown
   * once here would train the user to expect one, making its later absence
   * carry no signal. Show the same text-only identity the per-tx screens will
   * show. */
#if !ZCASH_PRIVACY
  Image icon_img;
  AnimationFrame icon_frame;
  IconType id_icon = stage_runtime_icon(&icon_img, &icon_frame, icon, icon_w,
                                        icon_h, icon_len);
#else
  IconType id_icon = NO_ICON;
  (void)icon;
  (void)icon_w;
  (void)icon_h;
  (void)icon_len;
#endif

  char body[160];
  memset(body, 0, sizeof(body));
  /* Lead with the identity (its logo + alias + fingerprint). The trust model
   * hangs on this consent; the fingerprint reappears on every per-tx screen. */
  snprintf(body, sizeof(body),
           "Trust '%s' (%s) for this session to describe transactions? NOT "
           "verified by KeepKey.",
           alias, fingerprint);
  bool ok = confirm_with_icon(ButtonRequestType_ButtonRequest_Other, id_icon,
                              _("Load Clearsigner"), "%s", body);
  layout_set_runtime_icon(NULL);
  return ok;
}

void signed_metadata_pubkey_fingerprint(const uint8_t pubkey[33],
                                        char out[METADATA_FINGERPRINT_LEN]) {
  uint8_t digest[32];
  sha256_Raw(pubkey, 33, digest);
  data2hex(digest, 4, out);
  memzero(digest, sizeof(digest));
}

bool signed_metadata_from_loaded_signer(void) {
  return metadata_available && metadata_tier == METADATA_TIER_RUNTIME;
}

/* Resolve the verification key for a slot. */
static const uint8_t* metadata_pubkey_for(uint8_t key_id, bool* is_loaded) {
  *is_loaded = false;
  if (key_id >= METADATA_MAX_KEYS) {
    return NULL;
  }
  if (loaded_pubkeys[key_id][0] != 0x00) {
    *is_loaded = true;
    return loaded_pubkeys[key_id];
  }
  return NULL;
}

bool signed_metadata_signer_is_runtime(uint8_t key_id) {
  bool is_loaded = false;
  return metadata_pubkey_for(key_id, &is_loaded) != NULL && is_loaded;
}

bool signed_metadata_signer_fingerprint(uint8_t key_id,
                                        char out[METADATA_FINGERPRINT_LEN]) {
  bool is_loaded = false;
  const uint8_t* pubkey = metadata_pubkey_for(key_id, &is_loaded);
  if (!pubkey || (is_loaded && !storage_isPolicyEnabled("AdvancedMode"))) {
    return false;
  }
  signed_metadata_pubkey_fingerprint(pubkey, out);
  return true;
}

bool signed_metadata_verify_attestation(uint8_t key_id, const uint8_t* data,
                                        size_t data_len, const uint8_t* sig,
                                        size_t sig_len) {
  if (!data || data_len == 0 || !sig || sig_len != 64) {
    return false;
  }
  bool is_loaded = false;
  const uint8_t* pubkey = metadata_pubkey_for(key_id, &is_loaded);
  if (!pubkey || (is_loaded && !storage_isPolicyEnabled("AdvancedMode"))) {
    return false;
  }
  uint8_t digest[32];
  sha256_Raw(data, data_len, digest);
  bool ok = ecdsa_verify_digest(&secp256k1, pubkey, sig, digest) == 0;
  memzero(digest, sizeof(digest));
  return ok;
}

/* Defined below, next to the suppression predicate it feeds. */
static MetadataClassification process_certified(const uint8_t* payload,
                                                size_t payload_len);

bool signed_metadata_is_certified_envelope(const uint8_t* payload,
                                           size_t payload_len,
                                           uint32_t key_id) {
  return payload != NULL && payload_len > 1 + CLEARSIGN_CERT_LEN &&
         payload[0] == METADATA_VERSION_CERTIFIED &&
         key_id == METADATA_KEYID_DELEGATE;
}

MetadataClassification signed_metadata_process(const uint8_t* payload,
                                               size_t payload_len,
                                               uint8_t key_id) {
  uint8_t digest[32];
  size_t signed_len;
  bool is_loaded = false;
  const uint8_t* pubkey;

  signed_metadata_clear();

  /* A certified envelope carries its own verification key inside a
   * KeepKey-signed certificate, so it is dispatched BEFORE the runtime key ring
   * is consulted -- the delegate is not in that ring and must never be put
   * there. key_id is required to be the reserved sentinel so a certified
   * envelope can never be confused with a runtime slot. */
  if (signed_metadata_is_certified_envelope(payload, payload_len, key_id)) {
    MetadataClassification c = process_certified(payload, payload_len);
    if (c == METADATA_MALFORMED) signed_metadata_clear();
    return c;
  }

  pubkey = metadata_pubkey_for(key_id, &is_loaded);
  if (!pubkey || (is_loaded && !storage_isPolicyEnabled("AdvancedMode")) ||
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

  if (ecdsa_verify_digest(&secp256k1, pubkey, stored_metadata.signature,
                          digest) != 0) {
    signed_metadata_clear();
    return METADATA_MALFORMED;
  }

  metadata_available = true;
  metadata_tier = is_loaded ? METADATA_TIER_RUNTIME : METADATA_TIER_NONE;
  return stored_metadata.classification;
}

/* ── The KeepKey tier ────────────────────────────────────────────────
 *
 * A certified envelope is [0x03][cert 139][device-decoded schema]. The
 * certificate is verified against the compiled-in root, its fields are copied
 * out for the screen, and the certificate itself is DISCARDED -- the inner
 * payload is then processed exactly as a v2 payload would be, against the
 * delegate's key.
 *
 * Nothing about a delegation survives the message. There is no slot to
 * promote, nothing to revoke at runtime, and no state a later transaction can
 * inherit.
 */
static MetadataClassification process_certified(const uint8_t* payload,
                                                size_t payload_len) {
  if (payload_len <= 1 + CLEARSIGN_CERT_LEN) return METADATA_MALFORMED;

  const uint8_t* cert = payload + 1;
  if (!clearsign_root_verify_cert(cert, CLEARSIGN_CERT_LEN)) {
    /* Unverifiable, expired, wrong chain shape, or no root compiled in. The
     * CALLER degrades to the additive path -- this is not a refusal. */
    return METADATA_MALFORMED;
  }

  /* The inner payload is verified against the DELEGATE's key, which the
   * certificate carries. The root vouches for the delegate; the delegate signs
   * the description. Two signatures, two distinct keys, one message. */
  const uint8_t* delegate_pub = cert + CLEARSIGN_CERT_OFF_PUBKEY;
  const uint8_t* inner = payload + 1 + CLEARSIGN_CERT_LEN;
  size_t inner_len = payload_len - 1 - CLEARSIGN_CERT_LEN;

  if (!parse_metadata_binary(inner, inner_len, &stored_metadata))
    return METADATA_MALFORMED;

  /* The inner payload MUST be a device-decoded schema. This is the load-bearing
   * check of the whole
   * tier, not a format nicety.
   *
   * The reason a KeepKey-certified describer is allowed to suppress the raw
   * review is structural: under v2 the DEVICE decodes the argument values out
   * of the exact calldata it is about to sign, so what the screen says is
   * bound to the signature by construction and the signer cannot lie about it.
   *
   * A v1 blob has no such property -- it carries argument values supplied
   * WHOLESALE BY THE SIGNER, and v1 exists precisely because 7.15 tolerates a
   * hot per-transaction key: mislabelling is survivable there only because the
   * raw review always follows. Grant that same blob the suppression tier and
   * the one thing that made it safe is gone. The delegate could then show
   * "Amount: 0.1 ETH" over calldata doing something else entirely, with
   * nothing behind it.
   *
   * Rejecting degrades to the additive 7.15 path, which is exactly where a v1
   * describer belongs. */
  if (stored_metadata.version != METADATA_VERSION_SCHEMA &&
      stored_metadata.version != METADATA_VERSION_DYNAMIC_SCHEMA) {
    signed_metadata_clear();
    return METADATA_MALFORMED;
  }

  size_t signed_len = inner_len - sizeof(stored_metadata.signature) - 1;
  uint8_t digest[32];
  sha256_Raw(inner, signed_len, digest);
  if (ecdsa_verify_digest(&secp256k1, delegate_pub, stored_metadata.signature,
                          digest) != 0) {
    return METADATA_MALFORMED;
  }

  memcpy(delegate_alias, cert + CLEARSIGN_CERT_OFF_ALIAS, CLEARSIGN_ALIAS_LEN);
  delegate_alias[CLEARSIGN_ALIAS_LEN] = '\0';
  signed_metadata_pubkey_fingerprint(delegate_pub, delegate_fp);
  delegate_chain_id = ((uint32_t)cert[CLEARSIGN_CERT_OFF_SCOPE] << 24) |
                      ((uint32_t)cert[CLEARSIGN_CERT_OFF_SCOPE + 1] << 16) |
                      ((uint32_t)cert[CLEARSIGN_CERT_OFF_SCOPE + 2] << 8) |
                      ((uint32_t)cert[CLEARSIGN_CERT_OFF_SCOPE + 3]);
  delegate_may_suppress =
      (cert[CLEARSIGN_CERT_OFF_FLAGS] & CLEARSIGN_USAGE_MAY_SUPPRESS_RAW) != 0;

  metadata_available = true;
  metadata_tier = METADATA_TIER_KEEPKEY;
  return stored_metadata.classification;
}

/* The ONE place suppression is decided.
 *
 * Positive and conjunctive on purpose. An else-arm answers "not a runtime
 * signer", which quietly becomes true for any tier added later -- including
 * one nobody has reviewed against this question. Every clause here has to be
 * satisfied deliberately.
 */
bool signed_metadata_may_suppress(uint32_t tx_chain_id) {
  if (!metadata_available) return false;
  if (metadata_tier != METADATA_TIER_KEEPKEY) return false;
  if (!delegate_may_suppress) return false;
  if (delegate_chain_id == 0) return false;
  /* Bound to ONE network. A certificate for mainnet must not describe a
   * transaction on another chain, where the same address means something
   * entirely different. */
  if (delegate_chain_id != tx_chain_id) return false;
  if (!clearsign_root_is_present()) return false;
  return true;
}

const char* signed_metadata_delegate_alias(void) {
  return (metadata_tier == METADATA_TIER_KEEPKEY) ? delegate_alias : "";
}

bool signed_metadata_delegate_fingerprint(char out[METADATA_FINGERPRINT_LEN]) {
  if (metadata_tier != METADATA_TIER_KEEPKEY) return false;
  memcpy(out, delegate_fp, METADATA_FINGERPRINT_LEN);
  return true;
}

bool signed_metadata_matches_tx(const EthereumSignTx* msg) {
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

  if (stored_metadata.version == METADATA_VERSION_SCHEMA ||
      stored_metadata.version == METADATA_VERSION_DYNAMIC_SCHEMA) {
    /* v2 commits to calldata only — never to msg->value. A v2 match otherwise
     * suppresses the native-value confirm screen in ethereum.c, which would
     * let a payable method clear-sign an ETH transfer whose amount is never
     * shown. Rather than refuse every payable call (which forced blind-signing
     * on exactly the routes that most need review), record that this tx moves
     * value; ethereum.c keeps the amount/recipient screen when it does. The
     * device reads that amount from the transaction it is signing, so nothing
     * unattested is displayed and the schema stays transaction-independent. */
    metadata_schema_moves_value = false;
    for (uint32_t i = 0; i < msg->value.size; i++) {
      if (msg->value.bytes[i] != 0) {
        metadata_schema_moves_value = true;
        break;
      }
    }
    /* v2 has no committed values or tx_hash: decode the args straight from the
     * calldata this tx will sign. Success here means the schema fully accounts
     * for the calldata (decode_v2_args enforces exact length + presence), so
     * the display is bound to the signature structurally — nothing is enforced
     * later against a digest (there is no tx_hash). A decode failure falls
     * through to the normal blind-sign path. Record the decode explicitly:
     * signed_metadata_enforce() requires it for v2, so a signature can never be
     * emitted for a v2 blob whose args were not decoded from this tx. */
    metadata_schema_decoded =
        stored_metadata.version == METADATA_VERSION_SCHEMA
            ? decode_v2_args(&stored_metadata, msg)
            : decode_portals_native_order(&stored_metadata, msg);
    return metadata_schema_decoded;
  }

  /* v1 only gates what we DISPLAY (so a benign-looking method screen can't be
   * shown for the wrong call). The metadata commits to the full tx hash; that
   * is enforced against the real signed digest in signed_metadata_enforce()
   * because the digest does not exist until send_signature() finalizes it. */
  return true;
}

/* Renders the clearsign screens in sequence. When a signer with an icon is
 * loaded, its logo (the compass) is set as RUNTIME_ICON and STAYS set for the
 * whole flow, so every screen — identity, method, contract, each arg — carries
 * it. The caller (signed_metadata_confirm) clears the runtime icon once on
 * return, covering every early-exit path. */
static bool signed_metadata_confirm_screens(void) {
  /* Sized so the widest argument cannot be silently truncated by snprintf:
   * name + ":\n" + every value byte as hex + NUL. A truncating snprintf here
   * would reintroduce exactly the concealment this renderer was fixed for. */
  char body[METADATA_MAX_ARG_NAME_LEN + 2 + (METADATA_MAX_ARG_VALUE_LEN * 2) +
            1];
  /* Compass shown on every screen once a signer with an icon is loaded. */
  IconType screen_icon = NO_ICON;
  Image icon_img;
  AnimationFrame icon_frame;

  /* ── State 3: KeepKey vouched for this describer ───────────────────
   *
   * A POSITIVE marker, not the absence of a warning.
   *
   * That distinction is the whole reason this screen exists. An absence
   * signals nothing to a user who has never seen the thing that is missing --
   * and on EVM there is nothing to miss anyway: the "NOT verified by KeepKey"
   * wording appears only on the load-time consent screen, never per
   * transaction. So a KeepKey-delegated describer that merely dropped a
   * warning would be indistinguishable from a stranger, on the one screen
   * where the difference decides whether the raw review is about to be
   * skipped.
   *
   * The alias and fingerprint stay because they are the only forensic handle
   * if a delegate key ever leaks. No expiry date: the device has no clock, so
   * showing one would imply a freshness check it did not perform. */
  if (metadata_tier == METADATA_TIER_KEEPKEY) {
    char fp[METADATA_FINGERPRINT_LEN];
    if (!signed_metadata_delegate_fingerprint(fp)) {
      strlcpy(fp, "????????", sizeof(fp));
    }
    const char* alias = signed_metadata_delegate_alias();
    if (!alias || alias[0] == '\0') alias = "unknown";
    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 _("Verified by KeepKey"),
                 "%s (%s)\ndescribes this transaction.", alias, fp)) {
      return false;
    }
  }

  if (metadata_tier == METADATA_TIER_RUNTIME) {
    /* Lead with the loaded IDENTITY (logo, if any, + alias + fingerprint)
     * BEFORE any clearsign page. The user approved this identity as their
     * trust anchor, so showing it — not a scary "NOT verified by KeepKey"
     * banner — is the honest framing. The fingerprint stays reachable so a
     * swapped provider is still detectable. */
    uint8_t key_id = stored_metadata.key_id;
    bool is_loaded = false;
    const uint8_t* pk = metadata_pubkey_for(key_id, &is_loaded);
    const char* alias = signed_metadata_signer_alias(key_id);
    char fingerprint[METADATA_FINGERPRINT_LEN];
    if (pk) {
      signed_metadata_pubkey_fingerprint(pk, fingerprint);
    } else {
      strlcpy(fingerprint, "????????", sizeof(fingerprint));
    }
    if (!alias) alias = "unknown";

    /* Draw the identity logo in the confirm's left icon column if one was
     * loaded. Image + frame are local — valid for the synchronous confirm
     * call, then the runtime icon is cleared. (Positioning tuned on device.) */
    const uint8_t* icon_data;
    uint8_t icon_w, icon_h;
    uint16_t icon_len;
    if (signed_metadata_signer_icon(key_id, &icon_data, &icon_w, &icon_h,
                                    &icon_len)) {
      /* Use the same full-height, centered placement as load confirmation. */
      screen_icon = stage_runtime_icon(&icon_img, &icon_frame, icon_data,
                                       icon_w, icon_h, icon_len);
    }

    memset(body, 0, sizeof(body));
    snprintf(body, sizeof(body), "%s (%s)\ndescribes this tx.", alias,
             fingerprint);
    /* Runtime icon stays set from here on — every subsequent screen shows the
     * compass. Cleared once by the caller. */
    if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           screen_icon, "Identity", "%s", body)) {
      return false;
    }

    /* Method screen — same identity compass, no "Insight Verified" branding
     * (that presentation is reserved for the built-in phase-2 keys). */
    memset(body, 0, sizeof(body));
    snprintf(body, sizeof(body), "Call:\n%s", stored_metadata.method_name);
    if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           screen_icon, "Clearsign", "%s", body)) {
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
  if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         screen_icon, stored_metadata.method_name, "%s",
                         body)) {
    return false;
  }

  /* Screen 3..N: Each decoded argument */
  for (uint8_t i = 0; i < stored_metadata.num_args; i++) {
    MetadataArg* arg = &stored_metadata.args[i];
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
          /* bn_format() BLANKS its output buffer and returns 0 when the value
           * does not fit, so 48 bytes rendered a 256-bit amount as an EMPTY
           * string: the clear-sign screen showed the argument name and no
           * value, which is the one rendering a user cannot read as wrong.
           * Size it beyond the 78-digit worst case and refuse to render a
           * blank if it ever overflows anyway. */
          char formatted[96];
          if (bn_format(&amount, NULL, " wei", 0, 0, false, formatted,
                        sizeof(formatted)) == 0) {
            strlcpy(formatted, "AMOUNT TOO LARGE TO DISPLAY",
                    sizeof(formatted));
          }
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

        const uint8_t* amt = arg->value + 2 + symlen;
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
          /* bn_format() BLANKS its output buffer and returns 0 when the value
           * does not fit, so 48 bytes rendered a 256-bit amount as an EMPTY
           * string: the clear-sign screen showed the argument name and no
           * value, which is the one rendering a user cannot read as wrong.
           * Size it beyond the 78-digit worst case and refuse to render a
           * blank if it ever overflows anyway. */
          char formatted[96];
          if (bn_format(&amount, NULL, suffix, decimals, 0, false, formatted,
                        sizeof(formatted)) == 0) {
            strlcpy(formatted, "AMOUNT TOO LARGE TO DISPLAY",
                    sizeof(formatted));
          }
          snprintf(body, sizeof(body), "%s:\n%s", arg->name, formatted);
        }
        break;
      }
      case ARG_FORMAT_BYTES:
      case ARG_FORMAT_RAW:
      default: {
        /* The WHOLE value, never an ellipsis.
         *
         * This used to show the first 16 bytes and trail a "...". Under 7.15
         * that was merely terse, because the raw-calldata review followed and
         * the hidden half was visible there. Under a suppressing KeepKey
         * delegate there is no such review, and the remaining bytes are
         * displayed NOWHERE while still being covered by the signature.
         *
         * That is a redirection primitive, not a cosmetic limit: a bytes32
         * recipient (a bridge mintRecipient, say) differing only in its low 16
         * bytes produced a screen sequence byte-for-byte identical to the
         * honest one. ADDRESS is already documented as "never truncated" for
         * exactly this reason; a signed word is no different.
         *
         * confirm_helper paginates, so a long body costs screens, not
         * information. */
        char hex[(METADATA_MAX_ARG_VALUE_LEN * 2) + 1];
        data2hex(arg->value, arg->value_len, hex);
        snprintf(body, sizeof(body), "%s:\n%s", arg->name, hex);
        break;
      }
    }

    if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           screen_icon, stored_metadata.method_name, "%s",
                           body)) {
      return false;
    }
  }

  /* User approved the decoded who/what/why. From here the raw-data confirm is
   * suppressed, so the signature MUST be bound to this metadata's tx hash. */
  relied_on_metadata = true;
  return true;
}

bool signed_metadata_confirm(void) {
  if (!metadata_available ||
      stored_metadata.classification != METADATA_VERIFIED) {
    return false;
  }
  bool ok = signed_metadata_confirm_screens();
  /* Single cleanup for every screen-flow exit — the runtime icon frame lives on
   * the helper's stack, so it must not outlive this call. */
  layout_set_runtime_icon(NULL);
  return ok;
}

bool signed_metadata_relied(void) { return relied_on_metadata; }

bool signed_metadata_enforce_decision(bool relied, bool available,
                                      int classification,
                                      const uint8_t* stored_hash,
                                      const uint8_t* hash) {
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
      (stored_metadata.version == METADATA_VERSION_SCHEMA ||
       stored_metadata.version == METADATA_VERSION_DYNAMIC_SCHEMA)) {
    return signed_metadata_enforce_schema_decision(
        relied_on_metadata, metadata_available, metadata_schema_decoded,
        stored_metadata.classification);
  }
  return signed_metadata_enforce_decision(
      relied_on_metadata, metadata_available, stored_metadata.classification,
      stored_metadata.tx_hash, hash);
}

const SignedMetadata* signed_metadata_get(void) {
  return metadata_available ? &stored_metadata : NULL;
}
