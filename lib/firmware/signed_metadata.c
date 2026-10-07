#include "keepkey/firmware/signed_metadata.h"

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
static bool metadata_signer_loaded = false;
/* moves_value: the tx carries native value v2 cannot bind (informational).
 * decoded: v2 args came from this tx's calldata; enforce requires it, since
 * v2 has no tx_hash. */
static bool metadata_schema_moves_value = false;
static bool metadata_schema_decoded = false;
static SignedMetadata stored_metadata;

/* Firmware 7.15 ships with NO built-in verification keys: every clearsign
 * signer is loaded at runtime via LoadClearsignSigner. */

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
  metadata_signer_loaded = false;
  metadata_schema_decoded = false;
  metadata_schema_moves_value = false;
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

MetadataClassification signed_metadata_process(const uint8_t* payload,
                                               size_t payload_len,
                                               uint8_t key_id) {
  uint8_t digest[32];
  size_t signed_len;
  bool is_loaded = false;
  const uint8_t* pubkey;

  signed_metadata_clear();

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
  metadata_signer_loaded = is_loaded;
  return stored_metadata.classification;
}

bool signed_metadata_matches_tx(const EthereumSignTx* msg) {
  /* Reset first: a stale `true` from a prior match must never let enforce
   * pass for a v2 blob that did not decode this tx. */
  metadata_schema_decoded = false;
  metadata_schema_moves_value = false;

  if (!metadata_available || !msg ||
      stored_metadata.classification != METADATA_VERIFIED ||
      msg->to.size != sizeof(stored_metadata.contract_address) ||
      msg->data_initial_chunk.size < sizeof(stored_metadata.selector)) {
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

  if ((msg->has_chain_id ? msg->chain_id : 0) != stored_metadata.chain_id) {
    return false;
  }

  if (stored_metadata.version == METADATA_VERSION_SCHEMA) {
    /* v2 does not commit to msg->value; record nonzero value. The amount
     * screen runs regardless, because metadata is additive. */
    metadata_schema_moves_value = false;
    for (uint32_t i = 0; i < msg->value.size; i++) {
      if (msg->value.bytes[i] != 0) {
        metadata_schema_moves_value = true;
        break;
      }
    }
    /* Decode from the calldata being signed; failure falls back to
     * blind-sign. enforce requires this flag for v2. */
    metadata_schema_decoded = decode_v2_args(&stored_metadata, msg);
    return metadata_schema_decoded;
  }

  /* v1 gates display only; the committed tx_hash is checked against the
   * final digest in signed_metadata_enforce(). */
  return true;
}

/* The signer icon stays set for every screen; the caller clears it. */
static bool signed_metadata_confirm_screens(void) {
  char body[128];
  IconType screen_icon = NO_ICON;
  Image icon_img;
  AnimationFrame icon_frame;

  /* Fail closed: a non-runtime identity must never get this presentation. */
  if (!metadata_signer_loaded) {
    return false;
  }

  {
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

    memset(body, 0, sizeof(body));
    snprintf(body, sizeof(body), "%s (%s)\ndescribes this tx.", alias,
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
          char formatted[96];
          if (bn_format(&amount, NULL, " wei", 0, 0, false, formatted,
                        sizeof(formatted)) == 0 ||
              snprintf(body, sizeof(body), "%s:\n%s", arg->name, formatted) >=
                  (int)sizeof(body)) {
            return false;
          }
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
        /* decimals + symbol + BE amount, validated at parse. */
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
          char formatted[96];
          if (bn_format(&amount, NULL, suffix, decimals, 0, false, formatted,
                        sizeof(formatted)) == 0 ||
              snprintf(body, sizeof(body), "%s:\n%s", arg->name, formatted) >=
                  (int)sizeof(body)) {
            return false;
          }
        }
        break;
      }
      case ARG_FORMAT_BYTES:
      case ARG_FORMAT_RAW:
      default: {
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
                                 screen_icon, stored_metadata.method_name, "%s",
                                 body)) {
            return false;
          }
        }
        continue;
      }
    }

    if (!confirm_with_icon(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           screen_icon, stored_metadata.method_name, "%s",
                           body)) {
      return false;
    }
  }

  /* User approved the decoded who/what/why. The screens are additive (the
   * amount and raw-data review still follow), and the signature MUST be bound
   * to this metadata's tx hash. */
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
  /* v2 binding is structural (see decode_v2_args); `decoded` is the explicit
   * proof, never inferred from call order. */
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

const SignedMetadata* signed_metadata_get(void) {
  return metadata_available ? &stored_metadata : NULL;
}
