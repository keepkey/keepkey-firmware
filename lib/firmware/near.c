/*
 * NEAR Protocol support for KeepKey firmware.
 *
 * Crypto: Ed25519 (SLIP-0010 hardened derivation, coin type 397)
 * Address: lowercase hex of 32-byte Ed25519 public key (implicit account)
 * Signing: Ed25519(SHA256(borsh_serialized_transaction))
 */

#include "keepkey/firmware/near.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/fsm.h"

#include "trezor/crypto/bip32.h"
#include "trezor/crypto/sha2.h"
#include "messages-near.pb.h"

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

static const char HEX_CHARS[] = "0123456789abcdef";

bool near_encode_address(const uint8_t pubkey[32], char *addr, size_t addr_len)
{
    if (addr_len < NEAR_ADDRESS_SIZE) return false;
    for (int i = 0; i < 32; i++) {
        addr[2 * i]     = HEX_CHARS[pubkey[i] >> 4];
        addr[2 * i + 1] = HEX_CHARS[pubkey[i] & 0xf];
    }
    addr[64] = '\0';
    return true;
}

bool near_getAddress(const HDNode *node,
                     const NearGetAddress *msg,
                     NearAddress *resp)
{
    /* node->public_key for Ed25519 is 33 bytes: 0x00 prefix + 32-byte pubkey.
     * The actual Ed25519 public key is the last 32 bytes. */
    const uint8_t *pubkey32 = node->public_key + 1;

    if (!near_encode_address(pubkey32, resp->address, sizeof(resp->address))) {
        return false;
    }
    resp->has_address = true;

    resp->has_public_key = true;
    resp->public_key.size = 32;
    memcpy(resp->public_key.bytes, pubkey32, 32);

    if (msg->has_show_display && msg->show_display) {
        if (!confirm(ButtonRequestType_ButtonRequest_Address,
                     "NEAR Address", "%s", resp->address)) {
            return false;
        }
    }

    return true;
}

bool near_signTx(const HDNode *node,
                 const NearSignTx *msg,
                 NearSignedTx *resp)
{
    if (!msg->has_raw_tx || msg->raw_tx.size == 0) {
        return false;
    }

    /* Build confirmation string: show receiver and action summary */
    const char *receiver = (msg->has_receiver_id && msg->receiver_id[0])
                           ? msg->receiver_id : "unknown";
    const char *action   = (msg->has_action_display && msg->action_display[0])
                           ? msg->action_display : "Transaction";

    if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                 receiver, "%s", action)) {
        return false;
    }

    /* Hash the Borsh-serialized transaction with SHA256 */
    uint8_t hash[32];
    sha256_Raw(msg->raw_tx.bytes, msg->raw_tx.size, hash);

    /* Sign with Ed25519.
     * trezor-crypto hdnode_sign with hasher=0 signs the raw digest directly. */
    uint8_t signature[64];
    if (hdnode_sign_digest((HDNode *)node, hash, signature, NULL, NULL) != 0) {
        return false;
    }

    resp->has_signature = true;
    resp->signature.size = 64;
    memcpy(resp->signature.bytes, signature, 64);

    const uint8_t *pubkey32 = node->public_key + 1;
    resp->has_public_key = true;
    resp->public_key.size = 32;
    memcpy(resp->public_key.bytes, pubkey32, 32);

    return true;
}
