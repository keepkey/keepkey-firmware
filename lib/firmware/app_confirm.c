/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2015 KeepKey LLC
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#if !defined(EMULATOR)
// FIXME: cortex.h should really have these includes inside it.
#include <inttypes.h>
#include <stdbool.h>
#include <libopencm3/cm3/cortex.h>
#endif

#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/util.h"

#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/coins.h"

#include "trezor/crypto/bignum.h"
#include "trezor/crypto/memzero.h"

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BITCOIN_DIVISIBILITY (8)
#define _(X) (X)

/*
 * confirm_cipher() - Show cipher confirmation
 *
 * INPUT
 *     - encrypt: true/false whether we are encrypting
 *     - key: string of key value
 * OUTPUT
 *     true/false of confirmation
 */
bool confirm_cipher(bool encrypt, const char* key) {
  bool ret_stat;

  if (encrypt) {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_Other,
                       "Encrypt Key Value", "%s", key);
  } else {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_Other,
                       "Decrypt Key Value", "%s", key);
  }

  return (ret_stat);
}

/*
 * confirm_encrypt_msg() - Show encrypt message confirmation
 *
 * INPUT
 *     - msg: message to encrypt
 *     - signing: true/false whether we are signing along with encryption
 * OUTPUT
 *     true/false of confirmation
 */
bool confirm_encrypt_msg(const char* msg, bool signing) {
  bool ret_stat;

  if (signing) {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_EncryptAndSignMessage,
                       "Encrypt and Sign Message", "%s", msg);
  } else {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_EncryptMessage,
                       "Encrypt Message", "%s", msg);
  }

  return (ret_stat);
}

/*
 * confirm_decrypt_msg() - Show decrypt message confirmation
 *
 * INPUT
 *      - msg: decrypted message
 *      - address: address used to sign message
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_decrypt_msg(const char* msg, const char* address) {
  bool ret_stat;

  if (address) {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_Other,
                       "Decrypted Signed Message", "%s", msg);
  } else {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_Other,
                       "Decrypted Message", "%s", msg);
  }

  return (ret_stat);
}

/*
 * confirm_transfer_output() - Show transfer output confirmation
 *
 * INPUT -
 *      - button_request: button request type
 *      - amount: amount to send
 *      - to: who to send to
 * OUTPUT -
 *     true/false of confirmation
 *
 */
bool confirm_transfer_output(ButtonRequestType button_request,
                             const char* amount, const char* to) {
  return confirm_with_custom_layout(&layout_notification_no_title_bold,
                                    button_request, "", "Transfer %s\nto %s",
                                    amount, to);
}

/*
 * confirm_transaction_output() - Show transaction output confirmation
 *
 * INPUT -
 *      - button_request: button request type
 *      - amount: amount to send
 *      - to: who to send to
 * OUTPUT -
 *     true/false of confirmation
 *
 */
bool confirm_transaction_output(ButtonRequestType button_request,
                                const char* amount, const char* to) {
  return confirm_with_custom_layout(&layout_notification_no_title_bold,
                                    button_request, "", "Send %s to\n%s",
                                    amount, to);
}

/*
 * confirm_erc_token_transfer() - Show transaction output confirmation without
 * bold
 *
 * INPUT -
 *      - button_request: button request type
 *      - amount: amount to send
 *      - to: who to send to
 * OUTPUT -
 *     true/false of confirmation
 *
 */
bool confirm_erc_token_transfer(ButtonRequestType button_request,
                                const char* msg_body) {
  return confirm_with_custom_layout(&layout_notification_no_title_no_bold,
                                    button_request, "", "Send %s", msg_body);
}

/*
 * confirm_transaction_output_no_bold() - Show transaction output confirmation
 * without bold
 *
 * INPUT -
 *      - button_request: button request type
 *      - amount: amount to send
 *      - to: who to send to
 * OUTPUT -
 *     true/false of confirmation
 *
 */
bool confirm_transaction_output_no_bold(ButtonRequestType button_request,
                                        const char* amount, const char* to) {
  return confirm_with_custom_layout(&layout_notification_no_title_no_bold,
                                    button_request, "", "Send %s to\n%s",
                                    amount, to);
}

/*
 * confirm_transaction() - Show transaction summary confirmation
 *
 * INPUT -
 *      - total_amount: total transaction amount
 *      - fee: fee amount
 * OUTPUT -
 *     true/false of confirmation
 *
 */
bool confirm_transaction(const char* total_amount, const char* fee) {
  if (!fee || strcmp(fee, "0.0 BTC") == 0) {
    return confirm(ButtonRequestType_ButtonRequest_SignTx, "Transaction",
                   "Do you want to send %s from your wallet?", total_amount);
  } else {
    return confirm(ButtonRequestType_ButtonRequest_SignTx, "Transaction",
                   "Do you want to send %s from your wallet? This includes a "
                   "transaction fee of %s.",
                   total_amount, fee);
  }
}

/*
 * confirm_load_device() - Show load device confirmation
 *
 * INPUT
 *     - is_node: true/false whether this is an hdnode
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_load_device(bool is_node) {
  bool ret_stat;

  if (is_node) {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_ImportPrivateKey,
                       "Import Private Key",
                       "Importing is not recommended unless you understand the "
                       "risks. Do you want to import private key?");
  } else {
    ret_stat = confirm(ButtonRequestType_ButtonRequest_ImportRecoverySentence,
                       "Import Recovery Sentence",
                       "Importing is not recommended unless you understand the "
                       "risks. Do you want to import recovery sentence?");
  }

  return (ret_stat);
}

/*
 * confirm_xpub() - Show extended public key confirmation
 *
 * INPUT
 *      - xpub: xpub to display as string
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_xpub(const char* node_str, const char* xpub) {
  return confirm_address_with_custom_layout(
      &layout_xpub_notification, ButtonRequestType_ButtonRequest_Address,
      node_str, "%s", xpub);
}

/*
 * confirm_cosmos_address() - Show cosmos address confirmation
 *
 * INPUT
 *      - desc: description to show with address
 *      - address: address to display both as string and in QR
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_cosmos_address(const char* desc, const char* address) {
  return confirm_address_with_custom_layout(
      &layout_cosmos_address_notification,
      ButtonRequestType_ButtonRequest_Address, desc, "%s", address);
}

/*
 * confirm_osmosis_address() - Show osmosis address confirmation
 *
 * INPUT
 *      - desc: description to show with address
 *      - address: address to display both as string and in QR
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_osmosis_address(const char* desc, const char* address) {
  return confirm_address_with_custom_layout(
      &layout_osmosis_address_notification,
      ButtonRequestType_ButtonRequest_Address, desc, "%s", address);
}

/*
 * confirm_ethereum_address() - Show ethereum address confirmation
 *
 * INPUT
 *      - desc: description to show with address
 *      - address: address to display both as string and in QR
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_ethereum_address(const char* desc, const char* address) {
  return confirm_address_with_custom_layout(
      &layout_ethereum_address_notification,
      ButtonRequestType_ButtonRequest_Address, desc, "%s", address);
}

/*
 * confirm_nano_address() - Show nano address confirmation
 *
 * INPUT
 *      - desc: description to show with address
 *      - address: address to display both as string and in QR
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_nano_address(const char* desc, const char* address) {
  return confirm_address_with_custom_layout(
      &layout_nano_address_notification,
      ButtonRequestType_ButtonRequest_Address, desc, "%s", address);
}

/*
 * confirm_zcash_address() - Show zcash address confirmation
 *
 * INPUT
 *      - desc: description (title) shown on both screens
 *      - address: zcash unified address — full text on the first screen,
 *        QR on the second
 * OUTPUT
 *     true/false of confirmation
 *
 */
#if ZCASH_PRIVACY
bool confirm_zcash_address(const char* desc, const char* address) {
  if (!confirm_with_custom_layout(&layout_zcash_address_text_notification,
                                  ButtonRequestType_ButtonRequest_Address, desc,
                                  "%s", address)) {
    return false;
  }

  return confirm_with_custom_layout(&layout_zcash_address_notification,
                                    ButtonRequestType_ButtonRequest_Address,
                                    desc, "%s", address);
}
#endif

/*
 * confirm_address() - Show address confirmation
 *
 * INPUT
 *      - desc: description to show with address
 *      - address: address to display both as string and in QR
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool confirm_address(const char* desc, const char* address) {
  return confirm_address_with_custom_layout(
      &layout_address_notification, ButtonRequestType_ButtonRequest_Address,
      desc, "%s", address);
}

/*
 * confirm_sign_identity() - Show identity confirmation
 *
 * INPUT
 *      - identity: identity information from protocol buffer
 *      - challenge: challenge string
 * OUTPUT
 *     true/false of confirmation
 *
 */
bool format_sign_identity_key_selection(const IdentityType* identity,
                                        const char* curve, char* out,
                                        size_t out_len) {
  if (!identity || !curve || !out || out_len == 0) return false;
  const int needed = snprintf(
      out, out_len, "Index: %" PRIu32 "\nCurve: %s\nPath: %s", identity->index,
      curve, (identity->has_path && identity->path[0]) ? "shown next" : "none");
  return needed >= 0 && (size_t)needed < out_len;
}

/* Every field cryptoIdentityFingerprint() hashes has to be renderable without
   ambiguity, because the screen that shows it is the only thing standing
   between two identities that derive DIFFERENT keys.

   proto goes into a title and host/port/user are concatenated into an ordinary
   body, both drawn as layout text: a byte below 0x20 is invisible, a leading
   space is dropped at a line start, and a newline re-wraps everything after
   it. So "ssh"/"ssh\n", or a user with a trailing space, can present the same
   approval while selecting different keys.

   path and the visual challenge already avoid this by going through
   confirm_bytes(). Putting the other four on their own escaped pages would add
   four screens to every identity signature; instead require them to be what
   they always are in practice -- URI components with no space and no control
   byte -- and refuse anything else before a screen is drawn. 0x21..0x7E is the
   same range confirm_bytes() renders literally. */
static bool identity_field_is_unambiguous(bool has_value, const char* value) {
  if (!has_value || !value) return true; /* absent is unambiguous */
  for (const unsigned char* p = (const unsigned char*)value; *p; ++p) {
    if (*p < 0x21 || *p > 0x7e) return false;
  }
  return true;
}

bool confirm_sign_identity(const IdentityType* identity, const char* challenge,
                           const char* curve) {
  char title[CONFIRM_SIGN_IDENTITY_TITLE], body[CONFIRM_SIGN_IDENTITY_BODY];

  if (!identity || !curve) return false;

  /* Refuse before anything is shown -- see identity_field_is_unambiguous(). */
  if (!identity_field_is_unambiguous(identity->has_proto, identity->proto) ||
      !identity_field_is_unambiguous(identity->has_host, identity->host) ||
      !identity_field_is_unambiguous(identity->has_port, identity->port) ||
      !identity_field_is_unambiguous(identity->has_user, identity->user)) {
    return false;
  }

  /* These values select the key and signing algorithm. Keep them out of the
   * free-form identity body so the maximum-size path can be reviewed by the
   * exact-byte pager instead of being shortened by a printf buffer. */
  char key_selection[CONFIRM_SIGN_IDENTITY_KEY];
  if (!format_sign_identity_key_selection(identity, curve, key_selection,
                                          sizeof(key_selection)) ||
      !confirm(ButtonRequestType_ButtonRequest_SignIdentity, "Identity Key",
               "%s", key_selection)) {
    memzero(key_selection, sizeof(key_selection));
    return false;
  }
  memzero(key_selection, sizeof(key_selection));

  if (identity->has_path && identity->path[0] &&
      !confirm_bytes(ButtonRequestType_ButtonRequest_SignIdentity,
                     "Identity Path", (const uint8_t*)identity->path,
                     strlen(identity->path))) {
    return false;
  }

  /* Format protocol -- verbatim, NOT uppercased.
   *
   * cryptoIdentityFingerprint() hashes identity->proto exactly as the host
   * sent it, so "ssh" and "SSH" select DIFFERENT keys. kk_strupr() made both
   * render as "SSH login to: ", so the one screen that names the protocol
   * could not distinguish two identities that sign with different keys.
   * Canonicalizing the other way is not open to us: the fingerprint is what
   * derives every existing identity key, and changing its input would strand
   * them. So show the bytes that are actually hashed. */
  if (identity->has_proto && identity->proto[0]) {
    strlcpy(title, identity->proto, sizeof(title));
    strlcat(title, " login to: ", sizeof(title));
  } else {
    strlcpy(title, "Login to: ", sizeof(title));
  }

  /* Format host and port */
  if (identity->has_host && identity->host[0]) {
    strlcpy(body, "host: ", sizeof(body));
    strlcat(body, identity->host, sizeof(body));

    if (identity->has_port && identity->port[0]) {
      strlcat(body, ":", sizeof(body));
      strlcat(body, identity->port, sizeof(body));
    }

    strlcat(body, "\n", sizeof(body));
  } else {
    body[0] = 0;
  }

  /* Format user */
  if (identity->has_user && identity->user[0]) {
    strlcat(body, "user: ", sizeof(body));
    strlcat(body, identity->user, sizeof(body));
    strlcat(body, "\n", sizeof(body));
  }

  /* EVERY visual challenge goes through the exact-byte pager.
   *
   * The challenge is hashed into the signature on the non-SSH/GPG identity
   * path, so the screen has to be able to tell two different challenges apart.
   * Short ones used to be strlcat'd into `body` and drawn with "%s", which
   * makes them layout text rather than bytes: a control byte is invisible, a
   * run of spaces collapses at a line start, and a newline re-wraps everything
   * around it. Two distinct signed challenges could therefore produce an
   * identical approval, and only challenges too long for the shared buffer got
   * the treatment that would have shown the difference.
   *
   * Confirm the identity metadata on its own screen -- always, so the title
   * still names the protocol even when there is no host or user -- then page
   * the challenge with confirm_bytes(), which escapes every byte outside
   * 0x21..0x7E. */
  if (challenge && challenge[0]) {
    if (!confirm(ButtonRequestType_ButtonRequest_SignIdentity, title, "%s",
                 body)) {
      return false;
    }
    return confirm_bytes(ButtonRequestType_ButtonRequest_SignIdentity,
                         "Visual Challenge", (const uint8_t*)challenge,
                         strlen(challenge));
  }

  return confirm(ButtonRequestType_ButtonRequest_SignIdentity, title, "%s",
                 body);
}

static size_t confirm_byte_token(uint8_t byte, char token[5]) {
  if (byte >= 0x21 && byte <= 0x7e && byte != '\\') {
    token[0] = (char)byte;
    token[1] = '\0';
    return 1;
  }

  snprintf(token, 5, "\\x%02X", byte);
  return 4;
}

bool confirm_bytes_escape(const uint8_t* data, size_t size, char* out,
                          size_t out_len) {
  if ((!data && size != 0) || !out || out_len == 0) return false;

  out[0] = '\0';
  size_t used = 0;
  for (size_t i = 0; i < size; i++) {
    char token[5];
    const size_t token_len = confirm_byte_token(data[i], token);
    if (token_len > (out_len - 1) - used) {
      out[0] = '\0';
      return false;
    }
    memcpy(out + used, token, token_len + 1);
    used += token_len;
  }
  return true;
}

size_t confirm_bytes_format_page(const uint8_t* data, size_t size, char* out,
                                 size_t out_len) {
  if ((!data && size != 0) || !out || out_len == 0) return 0;

  out[0] = '\0';
  size_t used = 0;
  size_t consumed = 0;
  while (consumed < size) {
    char token[5];
    const size_t token_len = confirm_byte_token(data[consumed], token);
    if (used >= out_len - 1 || token_len > (out_len - 1) - used) break;

    memcpy(out + used, token, token_len + 1);
    if (calc_str_line(get_body_font(), out, BODY_WIDTH) > BODY_ROWS) {
      out[used] = '\0';
      break;
    }

    used += token_len;
    consumed++;
  }

  return consumed;
}

bool confirm_bytes(ButtonRequestType button_request, const char* title,
                   const uint8_t* data, size_t size) {
  if (!title || (!data && size != 0)) return false;
  if (size == 0) return confirm(button_request, title, "(empty)");

  static char page_body[BODY_CHAR_MAX];
  static char page_title[TITLE_CHAR_MAX];
  bool approved = false;

  size_t pages = 0;
  size_t offset = 0;
  while (offset < size) {
    const size_t take = confirm_bytes_format_page(data + offset, size - offset,
                                                  page_body, sizeof(page_body));
    if (take == 0) goto cleanup;
    offset += take;
    pages++;
  }

  offset = 0;
  for (size_t page = 0; page < pages; page++) {
    const size_t take = confirm_bytes_format_page(data + offset, size - offset,
                                                  page_body, sizeof(page_body));
    if (take == 0) goto cleanup;

    int title_len;
    if (pages == 1) {
      title_len = snprintf(page_title, sizeof(page_title), "%s", title);
    } else {
      title_len = snprintf(page_title, sizeof(page_title), "%s %u/%u", title,
                           (unsigned)(page + 1), (unsigned)pages);
    }
    if (title_len < 0 || (size_t)title_len >= sizeof(page_title)) goto cleanup;

    const bool last = (page + 1 == pages);
    if (last) {
      /* Only the final page approves the signature, so it keeps the full hold.
       */
      if (!confirm(button_request, page_title, "%s", page_body)) goto cleanup;
    } else {
      /* Reading an intermediate page advances on a short click. Cancel and
       * Initialize still return false from the underlying confirmation screen.
       */
      if (!review_immediate(button_request, page_title, "%s", page_body))
        goto cleanup;
    }
    offset += take;
  }

  approved = true;

cleanup:
  memzero(page_body, sizeof(page_body));
  memzero(page_title, sizeof(page_title));
  return approved;
}

bool confirm_omni(ButtonRequestType button_request, const char* title,
                  const uint8_t* data, uint32_t size) {
  uint32_t tx_type_be = 0;
  uint32_t tx_type = UINT32_MAX;
  if (data && size == 20) {
    /* Protobuf byte arrays are size-delimited, not necessarily aligned. */
    memcpy(&tx_type_be, data + 4, sizeof(tx_type_be));
    REVERSE32(tx_type_be, tx_type);
  }
  if (tx_type == 0x00000000) {  // OMNI simple send
    char str_out[32];
    uint32_t currency_be;
    uint32_t currency;
    memcpy(&currency_be, data + 8, sizeof(currency_be));
    REVERSE32(currency_be, currency);
    const char* suffix = "UNKN";
    switch (currency) {
      case 1:
        suffix = " OMNI";
        break;
      case 2:
        suffix = " tOMNI";
        break;
      case 3:
        suffix = " MAID";
        break;
      case 31:
        suffix = " USDT";
        break;
      default:
        /* Asset identity is signed semantics. A generic UNKN ticker makes
         * every unsupported property ID look identical, so disclose the
         * complete payload instead of pretending it was decoded. */
        return confirm_bytes(button_request, title, data, size);
    }
    uint64_t amount_be, amount;
    memcpy(&amount_be, data + 12, sizeof(uint64_t));
    REVERSE64(amount_be, amount);
    if (!bn_format_uint64(amount, NULL, suffix, BITCOIN_DIVISIBILITY, 0, false,
                          str_out, sizeof(str_out))) {
      strlcpy(str_out, "AMOUNT TOO LARGE TO DISPLAY", sizeof(str_out));
    }
    return confirm(button_request, title, _("Do you want to send %s?"),
                   str_out);
  }

  /* Unknown/malformed Omni messages must still bind approval to every signed
   * OP_RETURN byte. */
  return confirm_bytes(button_request, title, data, size);
}

bool confirm_data(ButtonRequestType button_request, const char* title,
                  const uint8_t* data, uint32_t size) {
  /* OP_RETURN bytes and EOS memo bytes are committed to in full. Route both
   * through the length-delimited pager so embedded NULs, non-ASCII data, and
   * tails beyond the first screen cannot disappear from the approval flow. */
  return confirm_bytes(button_request, title, data, size);
}
