/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2024 KeepKey
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

#include "keepkey/firmware/solana.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/board/confirm_sm.h"
#include "trezor/crypto/ed25519-donna/ed25519.h"
#include "trezor/crypto/memzero.h"

#include <string.h>
#include <stdio.h>

/*
 * Sign Solana message (off-chain signature)
 *
 * This is used for authentication, proof-of-ownership, dApp interactions, etc.
 * Solana signs raw message bytes directly with Ed25519 (no prefix).
 * This matches Phantom, Solflare, and other standard Solana wallets.
 */
void solana_signMessage(const HDNode *node, const uint8_t *message,
                        size_t message_len, uint8_t *signature_out) {
  if (!node || !message || !signature_out) {
    return;
  }

  // Get Ed25519 public key
  uint8_t public_key[32];
  ed25519_publickey(node->private_key, public_key);

  // Sign the raw message with Ed25519 (no prefix - this is Solana standard)
  ed25519_sign(message, message_len, node->private_key, public_key,
               signature_out);
}

/*
 * Display message to user for confirmation
 * Shows first N chars of message in readable format
 */
bool solana_confirmMessage(const uint8_t *message, size_t message_len) {
  if (!message || message_len == 0) {
    return false;
  }

  // Prepare message preview (first 64 chars or less)
  char preview[65];
  size_t preview_len = message_len < 64 ? message_len : 64;

  // Check if message is printable ASCII
  bool is_printable = true;
  for (size_t i = 0; i < preview_len; i++) {
    if (message[i] < 32 || message[i] > 126) {
      is_printable = false;
      break;
    }
  }

  if (is_printable) {
    // Show text preview
    memcpy(preview, message, preview_len);
    preview[preview_len] = '\0';

    if (message_len > 64) {
      // Truncate with ...
      preview[61] = '.';
      preview[62] = '.';
      preview[63] = '.';
      preview[64] = '\0';
    }

    return confirm(ButtonRequestType_ButtonRequest_Other,
                   "Sign Message",
                   "Sign message:\n%s\n\n(%u bytes total)",
                   preview, (unsigned int)message_len);
  } else {
    // Show hex preview for binary data
    char hex_preview[17];
    size_t hex_len = message_len < 8 ? message_len : 8;

    for (size_t i = 0; i < hex_len; i++) {
      snprintf(hex_preview + (i * 2), 3, "%02x", message[i]);
    }
    hex_preview[hex_len * 2] = '\0';

    return confirm(ButtonRequestType_ButtonRequest_Other,
                   "Sign Message",
                   "Sign binary message:\n0x%s%s\n\n(%u bytes)",
                   hex_preview,
                   message_len > 8 ? "..." : "",
                   (unsigned int)message_len);
  }
}
