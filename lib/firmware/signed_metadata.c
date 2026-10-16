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
/* Certified path only; cleared with everything else. */
static char delegate_alias[CLEARSIGN_ALIAS_LEN + 1];
static char delegate_fp[METADATA_FINGERPRINT_LEN];
/* A certified envelope arrived this message, whether or not it verified. */
static bool certified_claimed;
/* moves_value: tx carries native value; the amount screen must NOT be
 * suppressed. decoded: v2 args came from this tx's calldata; enforce REQUIRES
 * it (v2 has no tx_hash). */
static bool metadata_schema_moves_value = false;
static bool metadata_schema_decoded = false;
static SignedMetadata stored_metadata;
/* A v0x07 call, decoded as its chunks arrive and matched at its last byte
 * (signed_metadata_ur_pending). Only the decoder's state is held, never the
 * call; the plan it builds is stored_metadata.ur_plan. */
static UrStream ur_stream;
static uint32_t ur_len, ur_total;

/* No built-in verification keys: runtime signers come only from
 * LoadClearsignSigner. A v3 delegate is never written into the ring below. */

/* Runtime signers: RAM only. Never persist: public storage has no
 * authenticated integrity against physical flash modification. */
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

/* Displayed metadata text: printable ASCII, '%' excluded (no control bytes
 * or format specifiers), regardless of who signed it. */
static bool display_text_ok(const uint8_t* text, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (text[i] < 0x20 || text[i] > 0x7e || text[i] == '%') {
      return false;
    }
  }
  return true;
}

/* u8 length + printable text (no '%'), 1..max_len. */
static bool read_short_text(const uint8_t** cursor, const uint8_t* end,
                            char* out, size_t max_len) {
  uint8_t len = 0;
  if (!read_u8(cursor, end, &len) || len == 0 || len > max_len ||
      (size_t)(end - *cursor) < len || !display_text_ok(*cursor, len)) {
    return false;
  }
  memcpy(out, *cursor, len);
  out[len] = '\0';
  *cursor += len;
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

static bool is_address_format(ArgFormat f) {
  return f == ARG_FORMAT_ADDRESS || f == ARG_FORMAT_ADDRESS_PINNED;
}

/* Fail-closed per-format validation at parse time. Legacy formats keep the
 * 32-byte cap; the larger max exists only for TOKEN_AMOUNT. */
static bool arg_value_ok(uint8_t format, const uint8_t* value, uint16_t len) {
  switch (format) {
    case ARG_FORMAT_STRING: {
      /* Printable ASCII, '%' excluded. */
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
    case ARG_FORMAT_ADDRESS:
      /* Shown whole as an address: nothing but 20 bytes can be. */
      return len == 20;
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

/* v2 args: name + format, NO value (decoded from calldata). TOKEN_AMOUNT
 * pre-stores [decimals, symlen, symbol]. Single-word ABI types only; anything
 * else blind-signs. */
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
      /* BYTES: one opaque 32-byte word, shown as full hex. */
      case ARG_FORMAT_BYTES:
        arg->value_len = 0; /* filled from the tx calldata at decode time */
        break;
      case ARG_FORMAT_ADDRESS_PINNED:
        /* The schema carries the address; decode only checks equality. */
        if (!read_bytes(cursor, end, arg->value, 20)) {
          return false;
        }
        arg->value_len = 20;
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
    if (out->version == METADATA_VERSION_SCHEMA_INTENT) {
      const bool amount =
          format == ARG_FORMAT_AMOUNT || format == ARG_FORMAT_TOKEN_AMOUNT;
      if (!read_u8(cursor, end, &arg->role) ||
          (amount ? (arg->role < METADATA_ROLE_SPEND_MAX ||
                     arg->role > METADATA_ROLE_ALLOWANCE)
                  : arg->role != METADATA_ROLE_NONE)) {
        return false;
      }
    }
  }
  return true;
}

static bool signed_metadata_intent_valid(const SignedMetadata* md);

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
  } else if (out->version == METADATA_VERSION_NAME) {
    if (!read_be_u32(&cursor, end, &out->chain_id) ||
        !read_bytes(&cursor, end, out->contract_address,
                    sizeof(out->contract_address)) ||
        !read_short_text(&cursor, end, out->vouched_name, METADATA_NAME_MAX)) {
      return false;
    }
  } else if (out->version == METADATA_VERSION_SCHEMA_INTENT) {
    if (!parse_common_head(&cursor, end, out) ||
        !read_string(&cursor, end, out->method_name, METADATA_MAX_METHOD_LEN) ||
        !read_u8(&cursor, end, &out->num_args) ||
        out->num_args > METADATA_MAX_ARGS ||
        !parse_v2_args(&cursor, end, out) ||
        !read_u8(&cursor, end, &out->value_role) ||
        (out->value_role != METADATA_ROLE_NONE &&
         out->value_role != METADATA_ROLE_SPEND_MAX &&
         out->value_role != METADATA_ROLE_SPEND_EXACT) ||
        !read_short_text(&cursor, end, out->title, METADATA_TITLE_MAX) ||
        !read_short_text(&cursor, end, out->intent, METADATA_INTENT_MAX) ||
        !signed_metadata_intent_valid(out)) {
      return false;
    }
  } else if (out->version == METADATA_VERSION_DECODER) {
    if (!parse_common_head(&cursor, end, out) ||
        !read_string(&cursor, end, out->method_name, METADATA_MAX_METHOD_LEN) ||
        !read_u8(&cursor, end, &out->decoder) ||
        out->decoder != METADATA_DECODER_UNISWAP_UR ||
        !read_short_text(&cursor, end, out->title, METADATA_TITLE_MAX) ||
        !read_u8(&cursor, end, &out->num_tokens) || out->num_tokens == 0 ||
        out->num_tokens > METADATA_MAX_TOKENS) {
      return false;
    }
    for (uint8_t i = 0; i < out->num_tokens; i++) {
      MetadataToken* t = &out->tokens[i];
      uint8_t symlen = 0;
      if (!read_bytes(&cursor, end, t->address, sizeof(t->address)) ||
          !read_u8(&cursor, end, &t->decimals) || t->decimals > 36 ||
          !read_u8(&cursor, end, &symlen) || symlen == 0 ||
          symlen > METADATA_MAX_TOKEN_SYMBOL_LEN ||
          !read_bytes(&cursor, end, (uint8_t*)t->symbol, symlen)) {
        return false;
      }
      t->symbol[symlen] = '\0';
      for (uint8_t j = 0; j < symlen; j++) {
        char ch = t->symbol[j];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
              (ch >= '0' && ch <= '9'))) {
          return false;
        }
      }
    }
  } else {
    return false;
  }

  return parse_trailer(&cursor, end, out);
}

/* v2 decode. Calldata must be EXACTLY selector + num_args 32-byte words, all
 * in the initial chunk: nothing undisplayed can be signed. This structural
 * completeness is v2's only display-to-signature binding (no tx_hash). */
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
        /* Reject dirty high bytes rather than truncate. */
        for (int j = 0; j < 12; j++) {
          if (word[j] != 0) {
            return false;
          }
        }
        memcpy(arg->value, word + 12, 20);
        arg->value_len = 20;
        break;
      case ARG_FORMAT_ADDRESS_PINNED:
        /* Clean word holding exactly the pinned address, or no match. */
        for (int j = 0; j < 12; j++) {
          if (word[j] != 0) {
            return false;
          }
        }
        if (arg->value_len != 20 || memcmp(arg->value, word + 12, 20) != 0) {
          return false;
        }
        break;
      case ARG_FORMAT_AMOUNT:
      case ARG_FORMAT_BYTES:
        memcpy(arg->value, word, 32);
        arg->value_len = 32;
        break;
      case ARG_FORMAT_TOKEN_AMOUNT: {
        /* Prefix from symlen, NOT value_len, so re-decoding is idempotent. */
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
  certified_claimed = false;
  metadata_schema_decoded = false;
  metadata_schema_moves_value = false;
  ur_len = ur_total = 0;
  memzero(&ur_stream, sizeof(ur_stream));
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

  /* Alias renders inside quotes: strict allowlist so it cannot close the
   * quotes, append a fake trust claim, or inject a '%' specifier. */
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

  /* Compressed only: 0x04 would read 65 bytes past the 33-byte buffer, and
   * this also rejects the all-zero empty-slot sentinel. */
  if (pubkey[0] != 0x02 && pubkey[0] != 0x03) {
    return false;
  }
  return ecdsa_read_pubkey(&secp256k1, pubkey, &point) == 1;
}

bool signed_metadata_store_signer(uint8_t key_id, const uint8_t* pubkey,
                                  const char* alias, const uint8_t* icon,
                                  uint8_t icon_w, uint8_t icon_h,
                                  uint16_t icon_len, bool persist) {
  /* Refuse persist before touching the slot: never silently downgrade a
   * persistence request to session-only trust. */
  if (persist || key_id >= METADATA_MAX_KEYS) {
    return false;
  }
  memcpy(loaded_pubkeys[key_id], pubkey, sizeof(loaded_pubkeys[key_id]));
  strlcpy(loaded_aliases[key_id], alias, sizeof(loaded_aliases[key_id]));

  /* A load without an icon clears any prior one. */
  bool has_icon = icon && icon_len > 0 && icon_len <= METADATA_ICON_MAX;

  /* Orchard build omits icons (SRAM); signers render text-only. */
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

const char* signed_metadata_signer_alias(uint8_t key_id) {
  if (key_id >= METADATA_MAX_KEYS) return NULL;
  if (loaded_pubkeys[key_id][0] != 0x00) return loaded_aliases[key_id];
  return NULL;
}

/* Single choke point for session icons: geometry must fit the icon column
 * and the RLE must decode exactly to it. Fail closed to text-only; an
 * over-wide icon would erase the alias, fingerprint and warning. */
#if !ZCASH_PRIVACY
static bool icon_renderable(const uint8_t* icon, uint16_t icon_len,
                            uint8_t icon_w, uint8_t icon_h) {
  if (!icon || icon_len == 0) return false;
  if (icon_w == 0 || icon_w > LEFT_MARGIN_WITH_ICON) return false;
  if (icon_h == 0 || icon_h > 64) return false;
  return draw_bitmap_mono_rle_valid(icon, (uint32_t)icon_len, icon_w, icon_h);
}
#endif

static bool signed_metadata_signer_icon(uint8_t key_id,
                                        const uint8_t** icon_out,
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

/* img/frame are the caller's and must outlive the synchronous confirm. */
static IconType stage_runtime_icon(Image* img, AnimationFrame* frame,
                                   const uint8_t* icon, uint8_t icon_w,
                                   uint8_t icon_h, uint16_t icon_len) {
  if (!icon || icon_len == 0) return NO_ICON;
  /* Re-checked at point of use: icon is drawn after text at x=40, so an
   * over-wide one would paint over the warning. */
  if (icon_w == 0 || icon_w > LEFT_MARGIN_WITH_ICON || icon_h == 0 ||
      icon_h > 64) {
    return NO_ICON;
  }
  img->w = icon_w;
  img->h = icon_h;
  img->length = icon_len;
  img->data = icon;
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
#if ZCASH_PRIVACY
  /* This build keeps no session icons (SRAM), so every per-transaction
   * identity screen is text-only. The consent screen shows the identity
   * exactly as it will reappear, so it is text-only too. */
  icon_len = 0;
#endif
  Image icon_img;
  AnimationFrame icon_frame;
  IconType id_icon = stage_runtime_icon(&icon_img, &icon_frame, icon, icon_w,
                                        icon_h, icon_len);

  char body[160];
  memset(body, 0, sizeof(body));
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
  data2hex(digest, (METADATA_FINGERPRINT_LEN - 1u) / 2u, out);
  memzero(digest, sizeof(digest));
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

bool signed_metadata_verify_runtime_attestation_for_pubkey(
    const uint8_t pubkey[33], const uint8_t* data, size_t data_len,
    const uint8_t* sig, size_t sig_len,
    char out_alias[METADATA_ALIAS_MAX_LEN + 1]) {
  if (!pubkey || !data || data_len == 0 || !sig || sig_len != 64 ||
      !out_alias || !storage_isPolicyEnabled("AdvancedMode")) {
    return false;
  }
  for (uint8_t key_id = 0; key_id < METADATA_MAX_KEYS; key_id++) {
    if (loaded_pubkeys[key_id][0] == 0x00 ||
        memcmp(loaded_pubkeys[key_id], pubkey, 33) != 0) {
      continue;
    }
    uint8_t digest[32];
    sha256_Raw(data, data_len, digest);
    const bool ok = ecdsa_verify_digest(&secp256k1, loaded_pubkeys[key_id], sig,
                                        digest) == 0;
    memzero(digest, sizeof(digest));
    if (!ok) return false;
    strlcpy(out_alias, loaded_aliases[key_id], METADATA_ALIAS_MAX_LEN + 1);
    return true;
  }
  return false;
}

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

  /* Dispatched BEFORE the runtime ring: the delegate must never enter it. */
  if (signed_metadata_is_certified_envelope(payload, payload_len, key_id)) {
    MetadataClassification c = process_certified(payload, payload_len);
    if (c == METADATA_MALFORMED) signed_metadata_clear();
    /* After any clear: a failed claim is refused, not downgraded (R-1.4). A
     * verified name record claims no transaction, so SignTx ignores it. */
    certified_claimed = !(c == METADATA_VERIFIED &&
                          stored_metadata.version == METADATA_VERSION_NAME);
    return c;
  }

  pubkey = metadata_pubkey_for(key_id, &is_loaded);
  if (!pubkey || (is_loaded && !storage_isPolicyEnabled("AdvancedMode")) ||
      !payload || payload_len < 65) {
    return METADATA_MALFORMED;
  }

  if (!parse_metadata_binary(payload, payload_len, &stored_metadata) ||
      stored_metadata.key_id != key_id ||
      /* A decoder entry is KeepKey-certified or nothing. */
      stored_metadata.version == METADATA_VERSION_DECODER) {
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

/* KeepKey tier: verify the cert, keep only alias/fingerprint (signing-flow
 * state, cleared by signed_metadata_clear()), then verify the inner v2 payload
 * against the delegate key. No slot to promote, nothing to revoke at runtime.
 */
static MetadataClassification process_certified(const uint8_t* payload,
                                                size_t payload_len) {
  if (payload_len <= 1 + CLEARSIGN_CERT_LEN) return METADATA_MALFORMED;

  const uint8_t* cert = payload + 1;
  const uint8_t* inner = payload + 1 + CLEARSIGN_CERT_LEN;
  size_t inner_len = payload_len - 1 - CLEARSIGN_CERT_LEN;

  if (!parse_metadata_binary(inner, inner_len, &stored_metadata))
    return METADATA_MALFORMED;

  /* LOAD-BEARING: inner MUST be a device-decoded schema (v2 or the 0x05
   * intent schema), whose values the device decodes from the calldata it
   * signs. v1 values are signer-supplied and could show any amount over
   * calldata doing something else. */
  if (stored_metadata.version != METADATA_VERSION_SCHEMA &&
      stored_metadata.version != METADATA_VERSION_SCHEMA_INTENT &&
      stored_metadata.version != METADATA_VERSION_NAME &&
      stored_metadata.version != METADATA_VERSION_DECODER) {
    signed_metadata_clear();
    return METADATA_MALFORMED;
  }

  /* SRS R-1.2: root-signed, unexpired, MAY_SUPPRESS_RAW, scope == chain. */
  uint8_t delegate_pub[CLEARSIGN_PUBKEY_LEN];
  if (stored_metadata.chain_id == CLEARSIGN_SCOPE_SOLANA ||
      !clearsign_root_cert_delegate(cert, CLEARSIGN_CERT_LEN,
                                    stored_metadata.chain_id, delegate_pub,
                                    delegate_alias)) {
    signed_metadata_clear();
    return METADATA_MALFORMED;
  }

  /* Root vouches for the delegate; the delegate signs the description. */
  size_t signed_len = inner_len - sizeof(stored_metadata.signature) - 1;
  uint8_t digest[32];
  sha256_Raw(inner, signed_len, digest);
  if (ecdsa_verify_digest(&secp256k1, delegate_pub, stored_metadata.signature,
                          digest) != 0) {
    signed_metadata_clear();
    return METADATA_MALFORMED;
  }

  signed_metadata_pubkey_fingerprint(delegate_pub, delegate_fp);

  metadata_available = true;
  metadata_tier = METADATA_TIER_KEEPKEY;
  return stored_metadata.classification;
}

/* The ONE place suppression is decided. Conjunctive on purpose: an else-arm
 * ("not runtime") would silently admit any tier added later. */
bool signed_metadata_may_suppress(uint32_t tx_chain_id) {
  if (!metadata_available) return false;
  if (metadata_tier != METADATA_TIER_KEEPKEY) return false;
  /* Bound to ONE network (cert scope == description chain at accept). */
  if (stored_metadata.chain_id != tx_chain_id) return false;
  if (!clearsign_root_is_present()) return false;
  return true;
}

bool signed_metadata_certified_claimed(void) { return certified_claimed; }

/* R-7.2 coverage puts every token amount in the summary sentence. */
bool signed_metadata_certified_states_allowance(const EthereumSignTx* msg,
                                                uint32_t tx_chain_id) {
  return signed_metadata_may_suppress(tx_chain_id) &&
         stored_metadata.version == METADATA_VERSION_SCHEMA_INTENT &&
         signed_metadata_matches_tx(msg) && stored_metadata.num_args == 2 &&
         stored_metadata.args[1].format == ARG_FORMAT_TOKEN_AMOUNT;
}

const char* signed_metadata_delegate_alias(void) {
  return (metadata_tier == METADATA_TIER_KEEPKEY) ? delegate_alias : "";
}

static const MetadataToken* metadata_token(const SignedMetadata* md,
                                           const uint8_t address[20]) {
  for (uint8_t i = 0; i < md->num_tokens; i++) {
    if (memcmp(md->tokens[i].address, address, 20) == 0) return &md->tokens[i];
  }
  return NULL;
}

/* msg->value into md->tx_value, big-endian. */
static bool store_tx_value(SignedMetadata* md, const EthereumSignTx* msg) {
  memset(md->tx_value, 0, sizeof(md->tx_value));
  if (msg->value.size > sizeof(md->tx_value)) return false;
  memcpy(md->tx_value + 32 - msg->value.size, msg->value.bytes,
         msg->value.size);
  return true;
}

/* Completes the streamed decode once every byte is in; md->tx_value must
 * already hold msg.value, and the router is the entry's contract (equal to
 * `to` once matched). */
static bool decoder_matches(SignedMetadata* md) {
  UrPlan* plan = &md->ur_plan; /* shares RAM with the unused schema args */
  bool ok = false;
  memset(&md->ur, 0, sizeof(md->ur));
  if (ur_stream_finish(&ur_stream) &&
      md->decoder == METADATA_DECODER_UNISWAP_UR &&
      ur_summarize(plan, md->contract_address, md->tx_value, &md->ur)) {
    /* Every token the review names must carry a certified identity. */
    ok = (md->ur.in_is_eth || metadata_token(md, md->ur.token_in)) &&
         (md->ur.out_is_eth || metadata_token(md, md->ur.token_out)) &&
         (!md->ur.has_permit || metadata_token(md, md->ur.permit_token));
  }
  memzero(plan, sizeof(*plan));
  memzero(&ur_stream, sizeof(ur_stream));
  if (!ok) memset(&md->ur, 0, sizeof(md->ur));
  /* ETH in is stated on the Limits screen; any other value was refused. */
  return ok;
}

/* The stored entry is a verified description of this contract, selector and
 * chain. Says nothing yet about the arguments. */
static bool entry_is_for(const EthereumSignTx* msg) {
  if (!metadata_available || !msg ||
      stored_metadata.version == METADATA_VERSION_NAME ||
      stored_metadata.classification != METADATA_VERIFIED ||
      msg->to.size != sizeof(stored_metadata.contract_address) ||
      msg->data_initial_chunk.size < sizeof(stored_metadata.selector)) {
    return false;
  }

  /* Metadata describes an Ethereum call. A Wanchain transaction (tx_type)
   * with the same chain id, contract and selector is not one. */
  if (msg->has_tx_type) {
    return false;
  }

  if (memcmp(stored_metadata.contract_address, msg->to.bytes,
             sizeof(stored_metadata.contract_address)) != 0) {
    return false;
  }

  if (memcmp(stored_metadata.selector, msg->data_initial_chunk.bytes,
             sizeof(stored_metadata.selector)) != 0) {
    return false;
  }

  return (msg->has_chain_id ? msg->chain_id : 0) == stored_metadata.chain_id;
}

bool signed_metadata_matches_tx(const EthereumSignTx* msg) {
  /* Reset first: a stale `true` from a prior match must never let enforce
   * pass for a v2 blob that did not decode this tx. */
  metadata_schema_decoded = false;
  metadata_schema_moves_value = false;
  ur_len = ur_total = 0;
  memzero(&ur_stream, sizeof(ur_stream));

  if (!entry_is_for(msg)) return false;

  if (stored_metadata.version == METADATA_VERSION_SCHEMA ||
      stored_metadata.version == METADATA_VERSION_SCHEMA_INTENT) {
    /* v2 never commits to msg->value: flag nonzero value so ethereum.c keeps
     * the amount screen and a payable call cannot move unseen ETH. A v0x05
     * schema that gives the value a role states it on its Limits screen. */
    metadata_schema_moves_value = false;
    for (uint32_t i = 0; i < msg->value.size; i++) {
      if (msg->value.bytes[i] != 0) {
        metadata_schema_moves_value = true;
        break;
      }
    }
    if (!store_tx_value(&stored_metadata, msg)) return false;
    if (stored_metadata.version == METADATA_VERSION_SCHEMA_INTENT &&
        stored_metadata.value_role != METADATA_ROLE_NONE) {
      metadata_schema_moves_value = false;
    }
    /* Decode from the calldata being signed; failure falls back to
     * blind-sign. enforce requires this flag for v2. */
    metadata_schema_decoded = decode_v2_args(&stored_metadata, msg);
    return metadata_schema_decoded;
  }

  if (stored_metadata.version == METADATA_VERSION_DECODER) {
    /* Certified only. The decoder reads every byte that will be signed: a
     * call past the first chunk stays pending until its last byte. */
    const uint32_t initsz = msg->data_initial_chunk.size;
    const uint32_t total = msg->has_data_length ? msg->data_length : initsz;
    if (metadata_tier != METADATA_TIER_KEEPKEY ||
        !store_tx_value(&stored_metadata, msg)) {
      return false;
    }
    ur_stream_begin(&ur_stream, &stored_metadata.ur_plan, total);
    ur_total = total;
    return signed_metadata_ur_feed(msg->data_initial_chunk.bytes, initsz) &&
           metadata_schema_decoded;
  }

  /* v1 gates display only; the committed tx_hash is checked against the
   * final digest in signed_metadata_enforce(). */
  return true;
}

bool signed_metadata_ur_pending(void) { return ur_len < ur_total; }

bool signed_metadata_ur_feed(const uint8_t* bytes, uint32_t len) {
  if (len > ur_total - ur_len) {
    ur_len = ur_total = 0;
    memzero(&ur_stream, sizeof(ur_stream));
    return false;
  }
  /* A refusal is latched in the stream and reported at the last byte, as
   * when the call was held whole: the caller's flow does not change. */
  ur_stream_feed(&ur_stream, bytes, len);
  ur_len += len;
  if (ur_len < ur_total) return true;
  metadata_schema_decoded = decoder_matches(&stored_metadata);
  ur_len = ur_total = 0;
  return metadata_schema_decoded;
}

/* One decoded argument as text, without its name. BYTES/RAW return false:
 * the caller pages them. shorten: "0xabcd...1234" for a sentence; the full
 * address is always shown on another screen. */
static bool metadata_arg_text(const MetadataArg* arg, uint32_t chain_id,
                              bool shorten, char* out, size_t len) {
  switch (arg->format) {
    case ARG_FORMAT_ADDRESS:
    case ARG_FORMAT_ADDRESS_PINNED: {
      char full[43] = "0x";
      if (arg->value_len != 20) return false;
      ethereum_address_checksum(arg->value, full + 2, false, chain_id);
      if (shorten) {
        snprintf(out, len, "%.6s...%s", full, full + 38);
      } else {
        snprintf(out, len, "%s", full);
      }
      return true;
    }
    case ARG_FORMAT_AMOUNT: {
      /* ERC-7730's threshold: 2^255 and above (a 32-byte top bit). */
      if (arg->value_len == 32 && (arg->value[0] & 0x80)) {
        snprintf(out, len, "UNLIMITED");
        return true;
      }
      bignum256 amount;
      bn_from_metadata_bytes(arg->value, arg->value_len, &amount);
      return bn_format(&amount, NULL, " wei", 0, 0, false, out, len) != 0;
    }
    case ARG_FORMAT_STRING: {
      /* Attested printable label, validated at parse (arg_value_ok). */
      if (arg->value_len >= len) return false;
      memcpy(out, arg->value, arg->value_len);
      out[arg->value_len] = '\0';
      return true;
    }
    case ARG_FORMAT_TOKEN_AMOUNT: {
      /* decimals + symbol + BE amount, validated at parse. */
      uint8_t decimals = arg->value[0];
      uint8_t symlen = arg->value[1];
      char suffix[METADATA_MAX_TOKEN_SYMBOL_LEN + 2];
      suffix[0] = ' ';
      memcpy(suffix + 1, arg->value + 2, symlen);
      suffix[1 + symlen] = '\0';
      const uint8_t* amt = arg->value + 2 + symlen;
      uint16_t amt_len = arg->value_len - 2 - symlen;
      if (amt_len == 32 && (amt[0] & 0x80)) { /* >= 2^255, as ERC-7730 */
        snprintf(out, len, "UNLIMITED%s", suffix);
        return true;
      }
      bignum256 amount;
      bn_from_metadata_bytes(amt, amt_len, &amount);
      return bn_format(&amount, NULL, suffix, decimals, 0, false, out, len) !=
             0;
    }
    default:
      return false;
  }
}

/* Walk the template: literal runs and "{n}" (arg) / "{v}" (msg.value)
 * placeholders. False on any malformed or out-of-range placeholder or a
 * stray brace. */
typedef bool (*IntentVisit)(void* ctx, bool placeholder, bool value,
                            uint8_t index, const char* lit, size_t lit_len);

static bool intent_walk(const SignedMetadata* md, IntentVisit visit,
                        void* ctx) {
  const char* t = md->intent;
  const char* lit = t;
  while (*t) {
    if (*t == '}') return false;
    if (*t != '{') {
      t++;
      continue;
    }
    if (!visit(ctx, false, false, 0, lit, (size_t)(t - lit))) return false;
    if (t[1] == 'v' && t[2] == '}') {
      if (md->value_role == METADATA_ROLE_NONE) return false;
      if (!visit(ctx, true, true, 0, NULL, 0)) return false;
      t += 3;
    } else {
      if (t[1] < '0' || t[1] > '9' || t[2] != '}') return false;
      const uint8_t index = (uint8_t)(t[1] - '0');
      if (index >= md->num_args) return false;
      const ArgFormat f = md->args[index].format;
      if (!is_address_format(f) && f != ARG_FORMAT_AMOUNT &&
          f != ARG_FORMAT_TOKEN_AMOUNT) {
        return false; /* paged bytes cannot sit inside a sentence */
      }
      if (!visit(ctx, true, false, index, NULL, 0)) return false;
      t += 3;
    }
    lit = t;
  }
  return visit(ctx, false, false, 0, lit, (size_t)(t - lit));
}

typedef struct {
  uint8_t used[METADATA_MAX_ARGS];
  bool value_used;
} IntentUse;

static bool intent_mark(void* ctx, bool placeholder, bool value, uint8_t index,
                        const char* lit, size_t lit_len) {
  (void)lit;
  (void)lit_len;
  IntentUse* u = (IntentUse*)ctx;
  if (placeholder && value) u->value_used = true;
  if (placeholder && !value) u->used[index] = 1;
  return true;
}

typedef struct {
  const SignedMetadata* md;
  size_t width;
} IntentWidth;

/* Widest text each placeholder can expand to: a uint256 is 78 digits, plus
 * point, space and a 10-char symbol = 90; a short address "0xabcd...1234"
 * = 13. */
static bool intent_width(void* ctx, bool placeholder, bool value, uint8_t index,
                         const char* lit, size_t lit_len) {
  IntentWidth* w = (IntentWidth*)ctx;
  if (!placeholder) {
    if (!intent_literal_ok(lit, lit_len)) return false;
    w->width += lit_len;
  } else if (!value && is_address_format(w->md->args[index].format)) {
    w->width += 13;
  } else {
    w->width += 90;
  }
  return true;
}

void signed_metadata_take_name(MetadataNameRecord* out) {
  memzero(out, sizeof(*out));
  const bool name = stored_metadata.version == METADATA_VERSION_NAME;
  const bool decoder = stored_metadata.version == METADATA_VERSION_DECODER;
  if (metadata_available && metadata_tier == METADATA_TIER_KEEPKEY &&
      (name || decoder) &&
      stored_metadata.classification == METADATA_VERIFIED) {
    out->valid = true;
    out->chain_id = stored_metadata.chain_id;
    memcpy(out->address, stored_metadata.contract_address, 20);
    strlcpy(out->name,
            name ? stored_metadata.vouched_name : stored_metadata.title,
            sizeof(out->name));
    strlcpy(out->alias, delegate_alias, sizeof(out->alias));
    strlcpy(out->fp8, delegate_fp, sizeof(out->fp8));
    if (decoder) {
      out->num_tokens = stored_metadata.num_tokens;
      memcpy(out->tokens, stored_metadata.tokens, sizeof(out->tokens));
    }
  }
  signed_metadata_clear();
}

const MetadataToken* signed_metadata_record_token(const MetadataNameRecord* r,
                                                  uint64_t chain_id,
                                                  const uint8_t token[20]) {
  if (!r || !r->valid || r->chain_id != chain_id) return NULL;
  for (uint8_t i = 0; i < r->num_tokens && i < METADATA_MAX_TOKENS; i++) {
    if (memcmp(r->tokens[i].address, token, 20) == 0) return &r->tokens[i];
  }
  return NULL;
}

/* Placeholders "{n}" (arg) / "{v}" (msg.value) well-formed and in range,
 * every amount covered, {v} present iff the value has a role. */
static bool signed_metadata_intent_valid(const SignedMetadata* md) {
  if (!md || md->intent[0] == '\0') return false;
  IntentUse u;
  memset(&u, 0, sizeof(u));
  if (!intent_walk(md, intent_mark, &u)) return false;
  /* A valid template must always render in full, never be cut. */
  IntentWidth w = {md, 0};
  if (!intent_walk(md, intent_width, &w) ||
      w.width > METADATA_INTENT_TEXT_MAX) {
    return false;
  }
  for (uint8_t i = 0; i < md->num_args; i++) {
    const ArgFormat f = md->args[i].format;
    if ((f == ARG_FORMAT_AMOUNT || f == ARG_FORMAT_TOKEN_AMOUNT) &&
        !u.used[i]) {
      return false; /* coverage: every amount is in the sentence */
    }
  }
  return u.value_used == (md->value_role != METADATA_ROLE_NONE);
}

static bool metadata_value_text(const SignedMetadata* md, char* out,
                                size_t len) {
  bignum256 value;
  bn_read_be(md->tx_value, &value);
  return ethereumFormatAmount(&value, NULL, md->chain_id, out, len);
}

static bool intent_fill(void* ctx, bool placeholder, bool value, uint8_t index,
                        const char* lit, size_t lit_len) {
  IntentFill* f = (IntentFill*)ctx;
  const SignedMetadata* md = (const SignedMetadata*)f->src;
  if (!placeholder) {
    intent_fill_append(f, lit, lit_len);
    return f->ok;
  }
  char v[100];
  if (value ? !metadata_value_text(md, v, sizeof(v))
            : !metadata_arg_text(&md->args[index], md->chain_id, true, v,
                                 sizeof(v))) {
    return false;
  }
  intent_fill_append(f, v, strlen(v));
  return f->ok;
}

static bool metadata_limits(const SignedMetadata* md, ReviewEmit emit,
                            void* ctx) {
  char body[160], v[100];
  if (md->value_role != METADATA_ROLE_NONE) {
    if (!metadata_value_text(md, v, sizeof(v))) return false;
    snprintf(body, sizeof(body), "%s\n%s", intent_role_text(md->value_role), v);
    if (!emit(ctx, "Limits", body, NULL, 0)) return false;
  }
  for (uint8_t i = 0; i < md->num_args; i++) {
    const char* role = intent_role_text(md->args[i].role);
    if (!role) continue;
    if (!metadata_arg_text(&md->args[i], md->chain_id, false, v, sizeof(v))) {
      return false;
    }
    snprintf(body, sizeof(body), "%s\n%s", role, v);
    if (!emit(ctx, "Limits", body, NULL, 0)) return false;
  }
  return true;
}

bool signed_metadata_build_intent_review(const SignedMetadata* md,
                                         bool certified, const char* alias,
                                         const char* fp, ReviewEmit emit,
                                         void* ctx) {
  if (!md || !emit || md->version != METADATA_VERSION_SCHEMA_INTENT) {
    return false;
  }
  char intent[METADATA_INTENT_TEXT_MAX + 1], body[BODY_CHAR_MAX];
  IntentFill f = {md, intent, sizeof(intent), 0, true};
  intent[0] = '\0';
  if (!intent_walk(md, intent_fill, &f) || !f.ok) return false;
  if (!certified) {
    return intent_emit_unverified(emit, ctx, alias, intent) &&
           metadata_limits(md, emit, ctx);
  }
  if (!emit(ctx, md->title, intent, NULL, 0) ||
      !metadata_limits(md, emit, ctx)) {
    return false;
  }
  /* Details: the contract, then every argument the sentence does not state
   * in full (addresses it shortened, values it omits). Nothing is hidden. */
  char contract[43] = "0x";
  ethereum_address_checksum(md->contract_address, contract + 2, false,
                            md->chain_id);
  snprintf(body, sizeof(body), "%s\n%s", md->method_name, contract);
  if (!emit(ctx, "Contract", body, NULL, 0)) return false;
  IntentUse u;
  memset(&u, 0, sizeof(u));
  if (!intent_walk(md, intent_mark, &u)) return false;
  for (uint8_t i = 0; i < md->num_args; i++) {
    const MetadataArg* arg = &md->args[i];
    if (arg->role != METADATA_ROLE_NONE) continue; /* on Limits */
    if (u.used[i] && !is_address_format(arg->format)) continue;
    if (arg->format == ARG_FORMAT_BYTES || arg->format == ARG_FORMAT_RAW) {
      if (!emit(ctx, arg->name, NULL, arg->value, arg->value_len)) return false;
      continue;
    }
    char v[100];
    if (!metadata_arg_text(arg, md->chain_id, false, v, sizeof(v)) ||
        !emit(ctx, arg->name, v, NULL, 0)) {
      return false;
    }
  }
  return intent_emit_provenance(emit, ctx, alias, fp);
}

/* Amount with symbol; a token's all-ones maximum reads as UNLIMITED. */
static bool ur_amount_text(const SignedMetadata* md, bool eth,
                           const uint8_t address[20], const uint8_t amount[32],
                           size_t width_bytes, char* out, size_t len) {
  uint8_t decimals = 18;
  const char* symbol = "ETH";
  if (!eth) {
    const MetadataToken* t = metadata_token(md, address);
    if (!t) return false;
    decimals = t->decimals;
    symbol = t->symbol;
  }
  char suffix[METADATA_MAX_TOKEN_SYMBOL_LEN + 2];
  snprintf(suffix, sizeof(suffix), " %s", symbol);
  bool is_max = width_bytes <= 32;
  for (size_t i = 32 - width_bytes; i < 32 && is_max; i++) {
    if (amount[i] != 0xFF) is_max = false;
  }
  if (is_max) {
    snprintf(out, len, "UNLIMITED%s", suffix);
    return true;
  }
  bignum256 bn;
  bn_from_metadata_bytes(amount, 32, &bn);
  return bn_format(&bn, NULL, suffix, decimals, 0, false, out, len) != 0;
}

/* Civil date (UTC) from a Unix time, for the Permit2 expiration. */
static void ur_date_text(uint64_t t, char* out, size_t len) {
  int64_t z = (int64_t)(t / 86400) + 719468;
  int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  uint64_t doe = (uint64_t)(z - era * 146097);
  uint64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int64_t y = (int64_t)yoe + era * 400;
  uint64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  uint64_t mp = (5 * doy + 2) / 153;
  unsigned d = (unsigned)(doy - (153 * mp + 2) / 5 + 1);
  unsigned m = (unsigned)(mp < 10 ? mp + 3 : mp - 9);
  if (m <= 2) y++;
  snprintf(out, len, "%04d-%02u-%02u UTC", (int)y, m, d);
}

bool signed_metadata_build_ur_review(const SignedMetadata* md,
                                     const char* alias, const char* fp,
                                     ReviewEmit emit, void* ctx) {
  if (!md || !emit || md->version != METADATA_VERSION_DECODER) return false;
  const UrSummary* u = &md->ur;
  char in[100], out[100], body[BODY_CHAR_MAX];
  if (!ur_amount_text(md, u->in_is_eth, u->token_in, u->amount_in, 32, in,
                      sizeof(in)) ||
      !ur_amount_text(md, u->out_is_eth, u->token_out, u->amount_out, 32, out,
                      sizeof(out))) {
    return false;
  }
  /* Who, what, limit: one sentence; the full recipient is never hidden. */
  if (u->exact_in) {
    snprintf(body, sizeof(body), "Swap %s for at least %s", in, out);
  } else {
    snprintf(body, sizeof(body), "Swap at most %s for %s", in, out);
  }
  if (!emit(ctx, md->title, body, NULL, 0)) return false;
  snprintf(body, sizeof(body), "%s\n%s",
           u->exact_in ? "You spend" : "You spend at most", in);
  if (!emit(ctx, "Limits", body, NULL, 0)) return false;
  snprintf(body, sizeof(body), "%s\n%s",
           u->exact_in ? "You receive at least" : "You receive", out);
  if (!emit(ctx, "Limits", body, NULL, 0)) return false;
  if (!u->recipient_is_sender) {
    char who[43] = "0x";
    ethereum_address_checksum(u->recipient, who + 2, false, md->chain_id);
    snprintf(body, sizeof(body), "Output goes to\n%s", who);
    if (!emit(ctx, "Recipient", body, NULL, 0)) return false;
  }
  if (u->has_permit) {
    char amt[100], date[24];
    if (!ur_amount_text(md, false, u->permit_token, u->permit_amount, 20, amt,
                        sizeof(amt))) {
      return false;
    }
    ur_date_text(u->permit_expiration, date, sizeof(date));
    snprintf(body, sizeof(body), "This router may spend up to %s until %s", amt,
             date);
    if (!emit(ctx, "Allowance", body, NULL, 0)) return false;
  }
  if (u->has_fee) {
    char fee_to[43] = "0x";
    ethereum_address_checksum(u->fee_recipient, fee_to + 2, false,
                              md->chain_id);
    snprintf(body, sizeof(body), "%u.%02u%% of the output to\n%s",
             (unsigned)(u->fee_bips / 100), (unsigned)(u->fee_bips % 100),
             fee_to);
    if (!emit(ctx, "Fee", body, NULL, 0)) return false;
  }
  /* V4 pools whose hook contract runs during the swap: every one is shown.
   * The limits above hold whatever a hook does (the router checks them
   * after the swap). */
  for (uint8_t i = 0; i < u->n_hooks && i < UR_MAX_HOOKS; i++) {
    char hook[43] = "0x", title[24];
    ethereum_address_checksum(u->hooks[i], hook + 2, false, md->chain_id);
    if (u->n_hooks > 1) {
      snprintf(title, sizeof(title), "Pool hook %u/%u", (unsigned)(i + 1),
               (unsigned)u->n_hooks);
    } else {
      snprintf(title, sizeof(title), "Pool hook");
    }
    snprintf(body, sizeof(body), "The swap runs this hook contract\n%s", hook);
    if (!emit(ctx, title, body, NULL, 0)) return false;
  }
  char router[43] = "0x";
  ethereum_address_checksum(md->contract_address, router + 2, false,
                            md->chain_id);
  snprintf(body, sizeof(body), "%s\n%s", md->method_name, router);
  if (!emit(ctx, "Contract", body, NULL, 0)) return false;
  return intent_emit_provenance(emit, ctx, alias, fp);
}

bool signed_metadata_review_emit(void* ctx, const char* title, const char* body,
                                 const uint8_t* bytes, uint16_t bytes_len) {
  (void)ctx;
  if (bytes) {
    char hex[33];
    const size_t pages = (bytes_len + 15) / 16;
    for (size_t page = 0; page < (pages ? pages : 1); page++) {
      size_t chunk = bytes_len - page * 16;
      if (chunk > 16) chunk = 16;
      data2hex(bytes + page * 16, chunk, hex);
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                   "%u/%u\n%s", (unsigned)(page + 1),
                   (unsigned)(pages ? pages : 1), hex)) {
        return false;
      }
    }
    return true;
  }
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title, "%s",
                 body);
}

/* The signer icon stays set for every screen; the caller clears it. */
static bool signed_metadata_confirm_screens(void) {
  char body[128];
  IconType screen_icon = NO_ICON;
  Image icon_img;
  AnimationFrame icon_frame;

  /* Fail closed: any other tier must never get a warning-free presentation. */
  if (metadata_tier != METADATA_TIER_RUNTIME &&
      metadata_tier != METADATA_TIER_KEEPKEY) {
    return false;
  }

  /* KeepKey tier: a positive marker, not a missing warning. Alias and
   * fingerprint are the forensic handle if a delegate key leaks; no expiry
   * is shown (the device has no clock). */
  if (metadata_tier == METADATA_TIER_KEEPKEY &&
      stored_metadata.version == METADATA_VERSION_SCHEMA_INTENT) {
    /* Summary, limits, details, who (SRS-7.16 §3.7). Root-authenticated:
     * the short id suffices, as on Solana. */
    char fp8[9];
    strlcpy(fp8, delegate_fp, sizeof(fp8));
    if (!signed_metadata_build_intent_review(
            &stored_metadata, true, delegate_alias, fp8,
            signed_metadata_review_emit, NULL)) {
      return false;
    }
    relied_on_metadata = true;
    return true;
  }
  if (metadata_tier == METADATA_TIER_KEEPKEY &&
      stored_metadata.version == METADATA_VERSION_DECODER) {
    char fp8[9];
    strlcpy(fp8, delegate_fp, sizeof(fp8));
    if (!signed_metadata_build_ur_review(&stored_metadata, delegate_alias, fp8,
                                         signed_metadata_review_emit, NULL)) {
      return false;
    }
    relied_on_metadata = true;
    return true;
  }
  if (metadata_tier == METADATA_TIER_KEEPKEY &&
      !confirm(ButtonRequestType_ButtonRequest_Other, _("Verified by KeepKey"),
               "%s (%s)\ndescribes this transaction.", delegate_alias,
               delegate_fp)) {
    return false;
  }

  if (metadata_tier == METADATA_TIER_RUNTIME) {
    /* Identity first; the fingerprint exposes a swapped provider. */
    uint8_t key_id = stored_metadata.key_id;
    bool is_loaded = false;
    const uint8_t* pk = metadata_pubkey_for(key_id, &is_loaded);
    const char* alias = signed_metadata_signer_alias(key_id);
    char fingerprint[METADATA_FINGERPRINT_LEN];
    if (pk) {
      signed_metadata_pubkey_fingerprint(pk, fingerprint);
    } else {
      strlcpy(fingerprint, "????????????????", sizeof(fingerprint));
    }
    if (!alias) alias = "unknown";

    const uint8_t* icon_data;
    uint8_t icon_w, icon_h;
    uint16_t icon_len;
    if (signed_metadata_signer_icon(key_id, &icon_data, &icon_w, &icon_h,
                                    &icon_len)) {
      screen_icon = stage_runtime_icon(&icon_img, &icon_frame, icon_data,
                                       icon_w, icon_h, icon_len);
    }

    /* A runtime template is a heading only (SRS-7.15 R-1.5). */
    if (stored_metadata.version == METADATA_VERSION_SCHEMA_INTENT &&
        !signed_metadata_build_intent_review(
            &stored_metadata, false, alias, fingerprint,
            signed_metadata_review_emit, NULL)) {
      return false;
    }
    memset(body, 0, sizeof(body));
    /* Quoted and disclaimed like the consent screen: the alias is the
     * signer's own choice of words and may read as a claim. */
    snprintf(body, sizeof(body),
             "'%s' (%s) describes this tx. NOT verified by KeepKey.", alias,
             fingerprint);
    if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           screen_icon, "Identity", "%s", body)) {
      return false;
    }

    memset(body, 0, sizeof(body));
    snprintf(body, sizeof(body), "Call:\n%s", stored_metadata.method_name);
    if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           screen_icon, "Clearsign", "%s", body)) {
      return false;
    }
  } else {
    /* Screen 1: the KeepKey-vouched method (KEEPKEY tier only). */
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
   * The title stays fixed: a 64-char method name wraps over the body, and the
   * Call screen above already shows it in full. */
  char contract_addr[43] = "0x";
  ethereum_address_checksum(stored_metadata.contract_address, contract_addr + 2,
                            false, stored_metadata.chain_id);
  memset(body, 0, sizeof(body));
  snprintf(body, sizeof(body), "Contract:\n%s", contract_addr);
  if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         screen_icon, "Clearsign", "%s", body)) {
    return false;
  }

  /* Screen 3..N: Each decoded argument */
  for (uint8_t i = 0; i < stored_metadata.num_args; i++) {
    const MetadataArg* arg = &stored_metadata.args[i];
    memset(body, 0, sizeof(body));
    if (!is_address_format(arg->format) && arg->format != ARG_FORMAT_AMOUNT &&
        arg->format != ARG_FORMAT_STRING &&
        arg->format != ARG_FORMAT_TOKEN_AMOUNT) {
      /* Every byte affects the signed call. A prefix-only screen would
       * hide changes in the second half of an opaque ABI word. */
      const size_t pages = (arg->value_len + 15) / 16;
      for (size_t page = 0; page < (pages ? pages : 1); page++) {
        size_t offset = page * 16;
        size_t chunk_len = arg->value_len - offset;
        if (chunk_len > 16) chunk_len = 16;
        char hex[33];
        data2hex(arg->value + offset, chunk_len, hex);
        snprintf(body, sizeof(body), "%s (%u/%u):\n%s", arg->name,
                 (unsigned)(page + 1), (unsigned)(pages ? pages : 1), hex);
        if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                               screen_icon, "Clearsign", "%s", body)) {
          return false;
        }
      }
      continue;
    }
    char value[100];
    if (!metadata_arg_text(arg, stored_metadata.chain_id, false, value,
                           sizeof(value)) ||
        snprintf(body, sizeof(body), "%s:\n%s", arg->name, value) >=
            (int)sizeof(body)) {
      return false;
    }
    if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           screen_icon, "Clearsign", "%s", body)) {
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
  /* The icon frame lives on the helper's stack; must not outlive it. */
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
  /* v2/0x05 binding is structural (see decode_v2_args); `decoded` is the
   * explicit proof, never inferred from call order. */
  return !relied ||
         (available && decoded && classification == METADATA_VERIFIED);
}

bool signed_metadata_enforce(const uint8_t hash[32]) {
  if (metadata_available &&
      (stored_metadata.version == METADATA_VERSION_SCHEMA ||
       stored_metadata.version == METADATA_VERSION_SCHEMA_INTENT ||
       stored_metadata.version == METADATA_VERSION_DECODER)) {
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

void intent_fill_append(IntentFill* f, const char* str, size_t n) {
  if (f->used >= f->len || n >= f->len - f->used) {
    f->ok = false;
    return;
  }
  memcpy(f->out + f->used, str, n);
  f->used += n;
  f->out[f->used] = '\0';
}

bool intent_literal_ok(const char* lit, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (lit[i] >= '0' && lit[i] <= '9') return false;
  }
  return true;
}

const char* intent_role_text(uint8_t role) {
  switch (role) {
    case METADATA_ROLE_SPEND_MAX:
      return "You spend at most";
    case METADATA_ROLE_RECEIVE_MIN:
      return "You receive at least";
    case METADATA_ROLE_SPEND_EXACT:
      return "You spend";
    case METADATA_ROLE_RECEIVE_EXACT:
      return "You receive";
    case METADATA_ROLE_CAP:
      return "Each use at most";
    case METADATA_ROLE_ALLOWANCE:
      return "Can spend up to";
    default:
      return NULL;
  }
}

bool intent_emit_unverified(ReviewEmit emit, void* ctx, const char* alias,
                            const char* intent) {
  char body[BODY_CHAR_MAX];
  if (snprintf(body, sizeof(body), "%s (NOT verified by KeepKey) says:\n%s",
               alias ? alias : "Unknown signer", intent) >= (int)sizeof(body)) {
    return false;
  }
  return emit(ctx, "Unverified", body, NULL, 0);
}

bool intent_emit_provenance(ReviewEmit emit, void* ctx, const char* alias,
                            const char* fp) {
  char body[BODY_CHAR_MAX];
  int n =
      snprintf(body, sizeof(body), "Described by %s %s\ncertified by KeepKey",
               alias ? alias : "", fp ? fp : "");
  if (n < 0 || n >= (int)sizeof(body)) return false;
  return emit(ctx, "KeepKey ClearSign", body, NULL, 0);
}
