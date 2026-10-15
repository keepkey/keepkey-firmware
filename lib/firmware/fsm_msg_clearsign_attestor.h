/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
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

/* Clearsign attestor: certifies the user's own address book with a key
 * derived from the seed. NEVER signs arbitrary bytes: only a KKABREQ1 list the
 * parser accepts and the user reviewed entry by entry, so a compromised host
 * gets no signing oracle. Do not add a "raw" mode.
 *
 * The device recomputes the Merkle root, shows every label, network and
 * address, and signs only the 46-byte KKABRT01 root manifest. No AdvancedMode:
 * these are the user's own contacts. EVM addresses only.
 */

#include "keepkey/firmware/contact_book.h"

/* m/'KK'/'CS'/0', all hardened and outside SLIP-44 space: never a funds key. */
#define ATTESTOR_PATH_LEN 3
static const uint32_t ATTESTOR_PATH[ATTESTOR_PATH_LEN] = {
    0x80000000 | 0x4B4B,
    0x80000000 | 0x4353,
    0x80000000u,
};

/* Derive the attestation node. Returns NULL and sends the failure itself. */
static HDNode* attestor_getNode(void) {
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, ATTESTOR_PATH,
                                    ATTESTOR_PATH_LEN, NULL);
  if (!node) return NULL;
  hdnode_fill_public_key(node);
  return node;
}

/* ECDSA over SHA256(bytes) with the attestor key, as
 * contact_book_process_proof() checks it. Sends the reply or the failure. */
static void attestor_signAndReply(const uint8_t* bytes, size_t len) {
  RESP_INIT(ClearsignAttestorSignature);

  HDNode* node = attestor_getNode();
  if (!node) return;

  uint8_t digest[32];
  sha256_Raw(bytes, len, digest);

  uint8_t sig[64];
  int ret =
      ecdsa_sign_digest(&secp256k1, node->private_key, digest, sig, NULL, NULL);
  memzero(digest, sizeof(digest));
  if (ret != 0) {
    memzero(node, sizeof(*node));
    memzero(sig, sizeof(sig));
    fsm_sendFailure(FailureType_Failure_Other, "Attestation failed");
    layoutHome();
    return;
  }

  resp->has_signature = true;
  resp->signature.size = sizeof(sig);
  memcpy(resp->signature.bytes, sig, sizeof(sig));
  resp->has_public_key = true;
  resp->public_key.size = 33;
  memcpy(resp->public_key.bytes, node->public_key, 33);

  memzero(sig, sizeof(sig));
  memzero(node, sizeof(*node));

  msg_write(MessageType_MessageType_ClearsignAttestorSignature, resp);
  layoutHome();
}

/* Every entry is reviewed before the root is signed: a label nobody saw is a
 * label nobody checked. */
static void attestor_certifyContacts(const ClearsignAttestorSign* msg) {
  _Static_assert(
      sizeof(msg->payload.bytes) >=
          14 + CONTACT_BOOK_MAX_ENTRIES *
                   (4 + CONTACT_BOOK_NETWORK_MAX + 20 + CONTACT_BOOK_LABEL_MAX),
      "Contact certification exceeds the wire payload bound");
  ContactBookEntry entries[CONTACT_BOOK_MAX_ENTRIES];
  ContactBookManifest manifest;
  bool ok = contact_book_parse_request(msg->payload.bytes, msg->payload.size,
                                       &manifest, entries, NULL);
  for (uint8_t i = 0; ok && i < manifest.count; i++) {
    ok = entries[i].destination_type == CONTACT_BOOK_DEST_EVM_ADDRESS &&
         entries[i].destination_len == 20 &&
         strncmp(entries[i].network, "eip155:", 7) == 0;
  }
  if (!ok) {
    memzero(entries, sizeof(entries));
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid address book");
    layoutHome();
    return;
  }

  bool confirmed =
      confirm(ButtonRequestType_ButtonRequest_SignTx, "Address Book",
              "Approve %u contacts?\nRevision %lu", (unsigned)manifest.count,
              (unsigned long)manifest.revision);
  for (uint8_t i = 0; confirmed && i < manifest.count; i++) {
    char address[43] = "0x";
    ethereum_address_checksum(entries[i].destination, address + 2, false, 0);
    confirmed =
        confirm(ButtonRequestType_ButtonRequest_SignTx, "Certify Contact",
                "%s\n%s", entries[i].label, entries[i].network) &&
        confirm(ButtonRequestType_ButtonRequest_SignTx, "Destination", "%s",
                address);
  }
  memzero(entries, sizeof(entries));
  if (!confirmed) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  uint8_t signed_bytes[46];
  contact_book_manifest_bytes(&manifest, signed_bytes);
  attestor_signAndReply(signed_bytes, sizeof(signed_bytes));
  memzero(signed_bytes, sizeof(signed_bytes));
}

void fsm_msgClearsignAttestorSign(const ClearsignAttestorSign* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  CHECK_PARAM(msg->has_payload && msg->payload.size > 0, "Missing payload");

  if (msg->payload.size >= 8 &&
      memcmp(msg->payload.bytes, "KKABREQ1", 8) == 0) {
    attestor_certifyContacts(msg);
    return;
  }

  fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid address book");
  layoutHome();
}
