#ifndef LIB_FIRMWARE_NEAR_H
#define LIB_FIRMWARE_NEAR_H

#include "keepkey/firmware/near.pb.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/bip32.h"

/* Max size of a NEAR implicit account address (Base58 of 32-byte pubkey) */
#define NEAR_ADDRESS_SIZE 45

/*
 * Encode a 32-byte Ed25519 public key as a Base58 NEAR address.
 * Returns true on success; addr must be at least NEAR_ADDRESS_SIZE bytes.
 */
bool near_encode_address(const uint8_t pubkey[32], char *addr, size_t addr_len);

/*
 * Confirm a NEAR GetAddress request on-device and populate resp.
 * node must already have its public key filled (hdnode_fill_public_key called).
 */
bool near_getAddress(const HDNode *node,
                     const NearGetAddress *msg,
                     NearAddress *resp);

/*
 * Sign a NEAR transaction.
 * Computes SHA256(raw_tx), signs with Ed25519, returns 64-byte signature.
 * Shows receiver_id and action_display on screen for user confirmation.
 */
bool near_signTx(const HDNode *node,
                 const NearSignTx *msg,
                 NearSignedTx *resp);

#endif /* LIB_FIRMWARE_NEAR_H */
