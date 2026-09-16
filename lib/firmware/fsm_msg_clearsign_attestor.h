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

/* Clearsign attestor: let a KeepKey issue clear-sign schema attestations from
 * its seed. It ships in the regular firmware, but every operation is gated by
 * AdvancedMode. This lets builders prove the self-service workflow before a
 * future release pins a KeepKey production identity.
 *
 * The attestor NEVER signs arbitrary bytes. It parses the submitted payload
 * with the same validator verifying devices run (solana_parseInstrSchema for
 * KKSOLSC1) and refuses anything malformed. A fully compromised host can
 * therefore only obtain attestations over well-formed, user-confirmed
 * descriptors — never a general secp256k1 signing oracle. That is the single
 * most important property of this design; do not add a "raw" mode.
 *
 * Key custody: the attestation key is derived from the device seed at
 * ATTESTOR_PATH (a dedicated hardened path outside every coin space), so PIN
 * unlock gates its availability, seed backup is key backup, and wipe destroys
 * it.
 *
 * ponytail: KKSOLSC1 only. EVM v2 metadata blobs are attestable in principle
 * but sign a different range (payload minus the 65-byte signature trailer, see
 * signed_metadata_process) and their parser is static in signed_metadata.c;
 * add a second branch here plus an exported pure parser when EVM schemas need
 * device-issued signatures.
 */

/* The attestation key path: purpose 0x4B4B ("KK"), then 0x4353 ("CS") for
 * clearsign, then account 0. All hardened, and far outside any SLIP-44 coin
 * range, so an attestation key can never collide with a funds key. */
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

/* Human-readable ABI type names for the attestation review. The type is part
 * of the security boundary, not decoration: U64+PUBKEY and OPAQUE32+U64 have
 * the same total width but assign labels to different byte offsets. Never ask
 * an operator to attest an argument label without also showing its type. */
static const char* attestor_schemaArgTypeName(SolanaSchemaArgType type) {
  switch (type) {
    case SOL_SCHEMA_ARG_U64:
      return "u64 LE";
    case SOL_SCHEMA_ARG_U8:
      return "u8";
    case SOL_SCHEMA_ARG_PUBKEY:
      return "public key";
    case SOL_SCHEMA_ARG_OPAQUE32:
      return "bytes32 hex";
  }
  return "invalid"; /* Parser rejects unknown values; defense in depth. */
}

void fsm_msgClearsignAttestorGetPublicKey(
    const ClearsignAttestorGetPublicKey* msg) {
  (void)msg;
  RESP_INIT(ClearsignAttestorPublicKey);

  CHECK_INITIALIZED
  CHECK_PIN
  CHECK_PARAM(storage_isPolicyEnabled("AdvancedMode"),
              _("AdvancedMode required for clearsign attestation"));

  HDNode* node = attestor_getNode();
  if (!node) return;

  resp->has_public_key = true;
  resp->public_key.size = 33;
  memcpy(resp->public_key.bytes, node->public_key, 33);
  memzero(node, sizeof(*node));

  msg_write(MessageType_MessageType_ClearsignAttestorPublicKey, resp);
  layoutHome();
}

void fsm_msgClearsignAttestorSign(const ClearsignAttestorSign* msg) {
  RESP_INIT(ClearsignAttestorSignature);

  CHECK_INITIALIZED
  CHECK_PIN
  CHECK_PARAM(storage_isPolicyEnabled("AdvancedMode"),
              _("AdvancedMode required for clearsign attestation"));

  CHECK_PARAM(msg->has_payload && msg->payload.size > 0, "Missing payload");

  /* Validate before attesting. The payload must be a descriptor this firmware
   * can itself parse — the same code path fsm_msgSolanaSignTx runs — so a
   * compromised host cannot use the attestor as a raw signing oracle. */
  SolanaInstrSchema schema;
  if (msg->payload.size < 8 || memcmp(msg->payload.bytes, "KKSOLSC1", 8) != 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Unsupported descriptor");
    layoutHome();
    return;
  }
  if (!solana_parseInstrSchema(msg->payload.bytes, msg->payload.size,
                               &schema)) {
    memzero(&schema, sizeof(schema));
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid schema");
    layoutHome();
    return;
  }

  char program_id[45];
  char disc_hex[2 * SOL_SCHEMA_DISC_MAX + 1];
  solana_pubkeyToStr(schema.program_id, program_id, sizeof(program_id));
  for (uint8_t i = 0; i < schema.disc_len; i++) {
    snprintf(disc_hex + 2 * i, sizeof(disc_hex) - 2 * i, "%02x",
             schema.disc[i]);
  }

  /* Program IDs may consume two body rows, while an 8-byte discriminator plus
   * its label consumes another two. They therefore get separate confirmations:
   * combining them can silently clip the discriminator, which is precisely the
   * field the operator must compare against the contract ABI. */
  bool confirmed =
      confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema", "%s\n%s",
              schema.program_name, schema.instruction_name) &&
      confirm(ButtonRequestType_ButtonRequest_SignTx, "Program ID", "%s",
              program_id) &&
      confirm(ButtonRequestType_ButtonRequest_SignTx, "Discriminator", "%s",
              disc_hex);

  /* One label per screen. A structurally valid schema can still lie by
   * labelling the wrong offset ("Amount" over the order id), so the operator
   * has to read every label — and confirm()'s body is three rendered rows with
   * no pagination, so a batched list of max-length labels scrolls off. A label
   * nobody saw is a label nobody checked. */
  for (uint8_t i = 0; confirmed && i < schema.num_args; i++) {
    confirmed = confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema",
                        "Arg %u: %s\n%s", (unsigned)(i + 1),
                        attestor_schemaArgTypeName(schema.args[i].type),
                        schema.args[i].label);
  }
  for (uint8_t i = 0; confirmed && i < schema.num_accounts; i++) {
    confirmed =
        confirm(ButtonRequestType_ButtonRequest_SignTx, "Attest Schema",
                "Account #%u shows\n%s", (unsigned)schema.accounts[i].index,
                schema.accounts[i].label);
  }
  memzero(&schema, sizeof(schema));
  if (!confirmed) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  HDNode* node = attestor_getNode();
  if (!node) return;

  /* Plain ECDSA over SHA256(payload): exactly what
   * signed_metadata_verify_attestation() checks on the verifying device. */
  uint8_t digest[32];
  sha256_Raw(msg->payload.bytes, msg->payload.size, digest);

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
