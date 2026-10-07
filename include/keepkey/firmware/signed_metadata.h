#ifndef KEEPKEY_FIRMWARE_SIGNED_METADATA_H
#define KEEPKEY_FIRMWARE_SIGNED_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct _EthereumSignTx EthereumSignTx;

#define METADATA_MAX_ARGS 8
#define METADATA_MAX_METHOD_LEN 64
#define METADATA_MAX_ARG_NAME_LEN 32
/* Sized for TOKEN_AMOUNT: decimals(1) + symbol_len(1) + symbol(<=10) +
 * amount(<=32). Other formats remain capped at 32 by their own guards. */
#define METADATA_MAX_ARG_VALUE_LEN 44
#define METADATA_MAX_TOKEN_SYMBOL_LEN 10
#define METADATA_MAX_KEYS 4
#define METADATA_ALIAS_MAX_LEN 31
/* Must equal LoadClearsignSigner.icon max_size (messages-ethereum.options). */
#define METADATA_ICON_MAX 384
/* hex(sha256(pubkey)[0:8]) + NUL. 64 bits: a 32-bit prefix collision can be
 * ground in hours, passing a different key for the approved one. */
#define METADATA_FINGERPRINT_LEN 17

typedef enum {
  METADATA_OPAQUE = 0,
  METADATA_VERIFIED = 1,
  METADATA_MALFORMED = 2,
} MetadataClassification;

/* LEGACY (v1): per-tx blob with committed tx_hash and host-decoded values;
 * bound to the digest by signed_metadata_enforce. SCHEMA (v2): no tx_hash, no
 * values; the DEVICE decodes args from the calldata it signs, so the display
 * is bound by construction and the catalog can be signed once, offline. */
#define METADATA_VERSION_LEGACY 0x01
#define METADATA_VERSION_SCHEMA 0x02

typedef enum {
  ARG_FORMAT_RAW = 0,     /* hex dump (all bytes, paginated) */
  ARG_FORMAT_ADDRESS = 1, /* 20 bytes -> full EIP-55 address, never truncated */
  ARG_FORMAT_AMOUNT = 2,  /* big-endian uint256 -> raw integer, "wei" */
  ARG_FORMAT_BYTES = 3,   /* hex dump (all bytes, paginated) */
  /* Printable label; alias character rules minus length (no '%'). */
  ARG_FORMAT_STRING = 4,
  /* decimals(1) + symbol_len(1) + symbol(<=10, [A-Za-z0-9]) + amount(1..32
   * BE); all-0xFF 32-byte amount renders "UNLIMITED <symbol>". */
  ARG_FORMAT_TOKEN_AMOUNT = 5,
} ArgFormat;

typedef struct {
  char name[METADATA_MAX_ARG_NAME_LEN + 1];
  ArgFormat format;
  uint8_t value[METADATA_MAX_ARG_VALUE_LEN];
  uint16_t value_len;
} MetadataArg;

typedef struct {
  uint8_t version;
  uint32_t chain_id;
  uint8_t contract_address[20];
  uint8_t selector[4];
  uint8_t tx_hash[32];
  char method_name[METADATA_MAX_METHOD_LEN + 1];
  uint8_t num_args;
  MetadataArg args[METADATA_MAX_ARGS];
  MetadataClassification classification;
  uint32_t timestamp;
  uint8_t key_id;
  uint8_t signature[64];
  uint8_t recovery;
} SignedMetadata;

bool signed_metadata_available(void);

/* True iff the last matches_tx() decoded v2 args from this tx's calldata;
 * reset on every call so it is never stale. Required by v2 enforce. */
bool signed_metadata_schema_decoded(void);

/* Whether the v2 tx carries native value the schema cannot bind.
 * Informational: the ordinary amount screen always runs after metadata. */
bool signed_metadata_schema_moves_value(void);

void signed_metadata_clear(void);

/* Runtime-loaded signers are the ONLY verification path in 7.15: RAM-only,
 * loaded after on-device consent, always shown by alias before any page. */

/* Pure validation: slot, compressed secp256k1 point, printable alias. */
bool signed_metadata_signer_valid(uint8_t key_id, const uint8_t* pubkey,
                                  size_t pubkey_len, const char* alias);

/* Post-consent write only: caller MUST have validated and confirmed. RC18
 * rejects persist=true (public storage lacks authenticated integrity). */
bool signed_metadata_store_signer(uint8_t key_id, const uint8_t* pubkey,
                                  const char* alias, const uint8_t* icon,
                                  uint8_t icon_w, uint8_t icon_h,
                                  uint16_t icon_len, bool persist);

/* NULL when the slot has no signer. */
const char* signed_metadata_signer_alias(uint8_t key_id);

/* LoadClearsignSigner consent: icon + alias + fingerprint. */
bool signed_metadata_confirm_load(const char* alias, const char* fingerprint,
                                  const uint8_t* icon, uint8_t icon_w,
                                  uint8_t icon_h, uint16_t icon_len);

/* Drop all runtime-loaded signers (and any metadata they verified). */
void signed_metadata_clear_signers(void);

/* Shown at load and per-tx so the user can correlate the two. */
void signed_metadata_pubkey_fingerprint(const uint8_t pubkey[33],
                                        char out[METADATA_FINGERPRINT_LEN]);

/* Lets non-EVM callers keep their Advanced-mode review after a decode. */
bool signed_metadata_signer_is_runtime(uint8_t key_id);
MetadataClassification signed_metadata_process(const uint8_t* payload,
                                               size_t payload_len,
                                               uint8_t key_id);

/* True iff a runtime signer is loaded for key_id AND the 64-byte compact
 * ECDSA sig verifies over sha256(data). */
bool signed_metadata_verify_attestation(uint8_t key_id, const uint8_t* data,
                                        size_t data_len, const uint8_t* sig,
                                        size_t sig_len);

/* For envelopes carrying the delegate pubkey (ERC-7730). Enforces
 * AdvancedMode; returns the user-approved alias. */
bool signed_metadata_verify_runtime_attestation_for_pubkey(
    const uint8_t pubkey[33], const uint8_t* data, size_t data_len,
    const uint8_t* sig, size_t sig_len,
    char out_alias[METADATA_ALIAS_MAX_LEN + 1]);

/* Aliases are not unique; the fingerprint disambiguates signers. */
bool signed_metadata_signer_fingerprint(uint8_t key_id,
                                        char out[METADATA_FINGERPRINT_LEN]);
/* Display gate binding contract, selector and chain id; the full-tx binding
 * is signed_metadata_enforce(). */
bool signed_metadata_matches_tx(const EthereumSignTx* msg);
bool signed_metadata_confirm(void);

/* True once the user approved the decoded metadata screens, so signing is
 * gated on the metadata matching the final tx hash. The screens are additive:
 * the ordinary amount and raw-data review still follows them. */
bool signed_metadata_relied(void);

/* Called once the sighash exists (send_signature). Fail-closed unless no
 * metadata was relied on or its committed tx_hash equals hash. */
bool signed_metadata_enforce(const uint8_t hash[32]);

/* Pure decision behind signed_metadata_enforce(); exported for tests. */
bool signed_metadata_enforce_decision(bool relied, bool available,
                                      int classification,
                                      const uint8_t* stored_hash,
                                      const uint8_t* hash);

/* v2 has no tx_hash: proceed only if relied-upon metadata is available,
 * VERIFIED and `decoded`, which must be decode_v2_args()'s recorded result
 * for this operation, not inferred from call order. */
bool signed_metadata_enforce_schema_decision(bool relied, bool available,
                                             bool decoded, int classification);

const SignedMetadata* signed_metadata_get(void);

#endif
