/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 Reid Rankin <reid.ran@shapeshift.io>
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

#include "keepkey/firmware/eip712.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/secp256k1.h"

#define _(X) (X)

void eip712_sign(const EIP712Sign* msg, const HDNode *node, EthereumMessageSignature *resp, EIP712EncodingSession* session) {
  (void)msg; // Currently unused

  if (!hdnode_get_ethereum_pubkeyhash(node, resp->address.bytes)) {
    return;
  }
  resp->has_address = true;
  resp->address.size = 20;

  const uint8_t* hash = eip712_finalize(session);
  if (!hash) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Unable to finalize EIP-712 encoding session"));
    return;
  }

  uint8_t v;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v, ethereum_is_canonic) != 0) {
    fsm_sendFailure(FailureType_Failure_Other, _("Signing failed"));
    return;
  }

  resp->has_signature = true;
  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_EthereumMessageSignature, resp);
}

int eip712_verify(const EIP712Verify *msg, EIP712EncodingSession* session) {
  if (msg->signature.size != 65 || msg->address.size != 20) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Malformed data"));
    return 1;
  }

  uint8_t pubkey[65];
  const uint8_t* hash = eip712_finalize(session);
  if (!hash) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Unable to finalize EIP-712 encoding session"));
    return 1;
  }

  /* v should be 27, 28 but some implementations use 0,1.  We are
   * compatible with both.
   */
  uint8_t v = msg->signature.bytes[64];
  if (v >= 27) {
    v -= 27;
  }
  if (v >= 2 || ecdsa_recover_pub_from_sig(
                    &secp256k1, pubkey, msg->signature.bytes, hash, v) != 0) {
    return 2;
  }

  uint8_t pubkeyHash[32];
  struct SHA3_CTX ctx;
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, pubkey + 1, 64);
  keccak_Final(&ctx, pubkeyHash);

  /* result are the least significant 160 bits */
  if (memcmp(msg->address.bytes, pubkeyHash + 12, 20) != 0) {
    return 2;
  }
  return 0;
}
