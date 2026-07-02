#ifndef KEEPKEY_FIRMWARE_SIGNED_METADATA_H
#define KEEPKEY_FIRMWARE_SIGNED_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct _EthereumSignTx EthereumSignTx;

#define METADATA_MAX_ARGS 8
#define METADATA_MAX_METHOD_LEN 64
#define METADATA_MAX_ARG_NAME_LEN 32
#define METADATA_MAX_ARG_VALUE_LEN 32
#define METADATA_MAX_KEYS 4
#define METADATA_ALIAS_MAX_LEN 31
/* hex(first 4 bytes of sha256(pubkey)) + NUL */
#define METADATA_FINGERPRINT_LEN 9

typedef enum {
  METADATA_OPAQUE = 0,
  METADATA_VERIFIED = 1,
  METADATA_MALFORMED = 2,
} MetadataClassification;

typedef enum {
  ARG_FORMAT_RAW = 0,
  ARG_FORMAT_ADDRESS = 1,
  ARG_FORMAT_AMOUNT = 2,
  ARG_FORMAT_BYTES = 3,
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
void signed_metadata_clear(void);

/*
 * Runtime-loaded clearsign signers (phase 1: the ONLY verification path).
 *
 * A signer is a compressed secp256k1 pubkey + display alias loaded into a
 * key slot at the host's request, gated by a mandatory on-device confirm
 * (see fsm_msgLoadClearsignSigner). Loaded signers live in RAM only and are
 * gone on reboot. Metadata verified by a loaded signer always shows a
 * warning screen naming the alias before any clearsign page — only the
 * built-in (phase 2) keys sign warning-free.
 */

/* Pure validation: slot in range and not occupied by a built-in key, pubkey a
 * valid compressed secp256k1 point, alias non-empty printable ASCII within
 * METADATA_ALIAS_MAX_LEN. No state, no I/O. */
bool signed_metadata_signer_valid(uint8_t key_id, const uint8_t *pubkey,
                                  size_t pubkey_len, const char *alias);

/* Store a signer into a slot. Caller (the FSM handler) MUST have passed
 * signed_metadata_signer_valid() and obtained on-device user confirmation
 * first — this function is the post-consent write, nothing more. */
void signed_metadata_store_signer(uint8_t key_id, const uint8_t *pubkey,
                                  const char *alias);

/* Drop all runtime-loaded signers (and any metadata they verified). */
void signed_metadata_clear_signers(void);

/* out = hex of the first 4 bytes of sha256(pubkey[33]), NUL-terminated.
 * Shown at load-confirm and on the per-tx warning screen so the user can
 * correlate the two. */
void signed_metadata_pubkey_fingerprint(const uint8_t pubkey[33],
                                        char out[METADATA_FINGERPRINT_LEN]);

/* True when the currently stored metadata was verified by a runtime-loaded
 * signer (=> its confirm flow is warning-first, never "Insight Verified"). */
bool signed_metadata_from_loaded_signer(void);
MetadataClassification signed_metadata_process(const uint8_t *payload,
                                               size_t payload_len,
                                               uint8_t key_id);
/* Display gate: does this metadata plausibly describe `msg`? Binds contract
 * address, selector and chain id so the wrong method is never shown. The
 * authoritative full-tx binding is enforced later by signed_metadata_enforce().
 */
bool signed_metadata_matches_tx(const EthereumSignTx *msg);
bool signed_metadata_confirm(void);

/* True once a verified confirm has suppressed the raw-data confirmation, i.e.
 * the signature is now gated on the metadata matching the final tx hash. */
bool signed_metadata_relied(void);

/* Authoritative binding, called after the real Ethereum sighash is finalized
 * (in send_signature, the only point it exists). Returns true if signing may
 * proceed: either no metadata was relied upon, or the relied-upon metadata's
 * committed tx_hash equals `hash`. Fail-closed on any mismatch. */
bool signed_metadata_enforce(const uint8_t hash[32]);

/* Pure enforcement decision, exported for unit testing. Given the module flags
 * and the metadata's committed tx hash, decides whether signing may proceed for
 * the just-finalized `hash`. signed_metadata_enforce() is a thin wrapper that
 * feeds the module state into this function. No state, no I/O. */
bool signed_metadata_enforce_decision(bool relied, bool available,
                                      int classification,
                                      const uint8_t *stored_hash,
                                      const uint8_t *hash);

const SignedMetadata *signed_metadata_get(void);

#endif
