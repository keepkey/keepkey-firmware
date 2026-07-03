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
/* hex(first 4 bytes of sha256(pubkey)) + NUL */
#define METADATA_FINGERPRINT_LEN 9

typedef enum {
  METADATA_OPAQUE = 0,
  METADATA_VERIFIED = 1,
  METADATA_MALFORMED = 2,
} MetadataClassification;

/*
 * Blob format versions (the first payload byte).
 *
 * LEGACY (v1): per-transaction. The blob carries a committed tx_hash and the
 * pre-decoded argument VALUES; the host is trusted for the decode and the
 * device only binds it to the signed digest (signed_metadata_enforce). This is
 * the format that requires an online, per-tx signer holding the attestation
 * key.
 *
 * SCHEMA (v2): static. The blob carries NO tx_hash and NO values — only how to
 * decode the call: (chainId, contract, selector, method, per-arg name + display
 * format [+ static decimals/symbol]). The DEVICE decodes the argument values
 * from the exact calldata it is about to sign, so the display is bound to the
 * signature by construction. No tx_hash, no per-tx signing: the catalog is
 * signed ONCE, offline, and can be served from a host CDN (no hot key).
 */
#define METADATA_VERSION_LEGACY 0x01
#define METADATA_VERSION_SCHEMA 0x02

/*
 * Argument display formats. The goal of clear-signing is that the device
 * answers WHO the user is dealing with (validated contract address, protocol
 * name), WHAT the transaction does (method + human-readable typed args:
 * recipient, "Amount: 1,000 USDC"), and WHY the decode can be trusted
 * (signer attestation bound to the exact tx hash). RAW/BYTES hex dumps are
 * the fallback, not the product.
 */
typedef enum {
  ARG_FORMAT_RAW = 0,     /* hex dump (first 16 bytes) */
  ARG_FORMAT_ADDRESS = 1, /* 20 bytes -> full EIP-55 address, never truncated */
  ARG_FORMAT_AMOUNT = 2,  /* big-endian uint256 -> raw integer, "wei" */
  ARG_FORMAT_BYTES = 3,   /* hex dump (first 16 bytes) */
  /* Attested printable label, e.g. protocol: "Uniswap V2". Same character
   * rules as the signer alias minus length (printable subset, no '%'). */
  ARG_FORMAT_STRING = 4,
  /* decimals(1) + symbol_len(1) + symbol(<=10, [A-Za-z0-9]) + amount(1..32
   * big-endian). Rendered as a decimal-scaled amount with the symbol, e.g.
   * "1000 USDC"; all-0xFF 32-byte amounts render "UNLIMITED <symbol>". */
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

/* Pure enforcement decision for v2 (static schema) blobs, exported for unit
 * testing. v2 has no committed tx_hash; the binding is structural (args decoded
 * from the signed calldata), so signing proceeds when the relied-upon metadata
 * is available and VERIFIED — no digest comparison. signed_metadata_enforce()
 * dispatches here when the stored blob's version is METADATA_VERSION_SCHEMA. */
bool signed_metadata_enforce_schema_decision(bool relied, bool available,
                                             int classification);

const SignedMetadata *signed_metadata_get(void);

#endif
