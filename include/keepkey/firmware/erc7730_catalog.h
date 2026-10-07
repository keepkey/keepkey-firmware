#ifndef KEEPKEY_FIRMWARE_ERC7730_CATALOG_H
#define KEEPKEY_FIRMWARE_ERC7730_CATALOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_abi.h"
#include "keepkey/firmware/signed_metadata.h"
#include "trezor/crypto/sha2.h"

#define ERC7730_PROGRAM_MAX_SIZE (16u * 1024u)
#define ERC7730_TRANSPORT_CHUNK_MAX 1024u
#define ERC7730_CATALOG_MAX_PROOF_DEPTH 16u
#define ERC7730_PROGRAM_HEADER_SIZE 179u
#define ERC7730_PROGRAM_MAX_SECTIONS 9u
/* Delegate record: [0] version 1 and [2..5] scope == chain id are checked but
 * not signed; [10..41] alias is format-checked only (the user-approved alias
 * is shown); [42..74] pubkey must equal a loaded runtime signer; other bytes
 * are ignored. The envelope signature covers only the purpose tag and Merkle
 * root. */
#define ERC7730_DELEGATE_RECORD_LEN 139u
#define ERC7730_DELEGATE_ALIAS_LEN 32u
#define ERC7730_DELEGATE_OFF_VERSION 0u
#define ERC7730_DELEGATE_OFF_SCOPE 2u
#define ERC7730_DELEGATE_OFF_ALIAS 10u
#define ERC7730_DELEGATE_OFF_PUBKEY 42u
/* Enforced at preload so a preloaded definition cannot fail replay. */
#define ERC7730_PROGRAM_MAX_DISPLAY_INSTRUCTIONS 64u
#define ERC7730_LITERAL_MAX_LENGTH 258u

/* Revocation floor, raised only by firmware update (no flash state).
 * Enforced on the header: issuance_epoch >= this AND >= revocation_epoch.
 * provider_id and revocation_epoch are otherwise NOT enforced. */
#define ERC7730_MIN_ISSUANCE_EPOCH 0u

static inline uint16_t read_be16(const uint8_t* p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline uint32_t read_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

typedef enum {
  ERC7730_DEFINITION_CALLDATA = 1,
  ERC7730_DEFINITION_EIP712 = 2,
  ERC7730_DEFINITION_TOKEN = 3,
  ERC7730_DEFINITION_NETWORK = 4,
} Erc7730DefinitionKind;

typedef enum {
  ERC7730_CATALOG_MORE = 0,
  ERC7730_CATALOG_COMPLETE,
  ERC7730_CATALOG_BAD_SEQUENCE,
  ERC7730_CATALOG_BAD_ENVELOPE,
  ERC7730_CATALOG_BAD_PROGRAM,
  ERC7730_CATALOG_UNTRUSTED,
} Erc7730CatalogResult;

/* Authenticated facts; no pointer into a transport message. */
typedef struct {
  uint8_t definition_id[32];
  uint64_t chain_id;
  uint8_t contract_address[20];
  uint8_t selector_or_type_hash[32];
  uint32_t program_length;
  uint32_t envelope_length;
  char delegate_alias[ERC7730_DELEGATE_ALIAS_LEN + 1];
  char delegate_fingerprint[METADATA_FINGERPRINT_LEN];
  uint8_t kind;
  bool reads_value; /* a path reads @.value */
} Erc7730CatalogIdentity;

/* Incremental verifier; size independent of descriptor size. */
typedef struct {
  SHA256_CTX envelope_hash;
  SHA256_CTX leaf_hash;
  uint8_t expected_id[32];
  uint8_t header[ERC7730_PROGRAM_HEADER_SIZE];
  uint8_t cert[ERC7730_DELEGATE_RECORD_LEN];
  uint8_t signature[64];
  uint8_t display_frames[ERC7730_ABI_MAX_DEPTH * 5u];
  uint8_t merkle[32];
  uint8_t sibling[32];
  uint32_t total_length;
  uint32_t received;
  uint32_t program_length;
  uint32_t program_received;
  uint32_t section_remaining;
  uint32_t section_offset;
  uint64_t abi_child_mask;
  uint8_t literal_classes[32]; /* ERC7730_CLASS_* per literal, 4 bits each */
  uint8_t date_strings[12];    /* strings "timestamp"/"blockheight", 1 bit */
  uint8_t short_strings[12];   /* strings of at most SIGNER_TEXT_MAX, 1 bit */
  uint64_t literal_decimals_mask; /* one-byte integers <= UNIT_DECIMALS_MAX */
  uint8_t path_arrays[64];        /* ABI node of each path's [] step, or 0xff */
  uint64_t path_iterable_mask;    /* paths that end on their [] step */
  uint8_t formatter_value_array;
  uint8_t display_iteration_array;
  bool formatter_any_array;
  bool formatter_mixed_arrays;
  bool display_in_iteration;
  bool path_array_indexed;
  bool path_last_full;
  uint16_t cert_length;
  uint16_t field_received;
  uint16_t section_mask;
  uint16_t table_counts[8];
  uint16_t abi_node_count;
  uint16_t abi_node_index;
  uint16_t entry_count;
  uint16_t entry_index;
  uint16_t entry_length;
  uint16_t entry_offset;
  uint16_t previous_length;
  uint8_t state;
  uint8_t header_received;
  uint8_t proof_count;
  uint8_t proof_index;
  uint8_t last_section;
  uint8_t sections_seen;
  uint8_t recovery;
  uint8_t abi_max_depth;
  uint8_t max_string_length;
  uint8_t utf8_remaining;
  uint8_t utf8_lower;
  uint8_t utf8_upper;
  uint8_t compare_state;
  uint8_t path_source;
  uint8_t path_step_count;
  uint8_t path_step_index;
  uint8_t path_step_opcode;
  uint8_t path_step_remaining;
  bool path_full_seen;
  uint8_t path_node;
  uint8_t literal_kind;
  uint8_t literal_first;
  uint8_t literal_second;
  uint16_t literal_subcount;
  uint16_t literal_previous;
  uint32_t formatter_roles;
  uint8_t formatter_kind;
  uint8_t formatter_arg_count;
  uint8_t formatter_arg_index;
  uint8_t formatter_last_role;
  uint8_t display_depth;
  bool display_intent_run_closed;
  bool reads_value;
  bool formatter_value_literal; /* its value is a signer constant */
  uint8_t display_max_depth;
  uint8_t binding_kind;
  uint8_t binding_previous_kind;
  uint16_t binding_previous_length;
  uint8_t binding_domain_fields;
  bool binding_header_match;
  bool failed;
} Erc7730CatalogVerifier;

void erc7730_catalog_begin(Erc7730CatalogVerifier* v,
                           const uint8_t definition_id[32],
                           uint32_t total_length);

Erc7730CatalogResult erc7730_catalog_feed(Erc7730CatalogVerifier* v,
                                          uint32_t offset, const uint8_t* data,
                                          size_t data_len,
                                          Erc7730CatalogIdentity* identity);

void erc7730_catalog_abort(Erc7730CatalogVerifier* v);

/* Single preload slot; verifier and identity share storage. */
Erc7730CatalogResult erc7730_catalog_preload_chunk(
    const uint8_t definition_id[32], uint32_t offset, uint32_t total_length,
    const uint8_t* data, size_t data_len, uint32_t* next_offset,
    bool* complete);
bool erc7730_catalog_preloaded(Erc7730CatalogIdentity* identity);
/* Whether the preloaded definition shows @.value. */
bool erc7730_catalog_preloaded_reads_value(void);
bool erc7730_catalog_preloaded_replay_begin(uint8_t definition_id[32],
                                            uint32_t* total_length);
bool erc7730_catalog_preloaded_replay_waiting(uint8_t definition_id[32],
                                              uint32_t* next_offset,
                                              uint32_t* total_length);
Erc7730CatalogResult erc7730_catalog_preloaded_replay_feed(
    const uint8_t definition_id[32], uint32_t offset, uint32_t total_length,
    const uint8_t* data, size_t data_len, uint32_t* next_offset, bool* complete,
    uint32_t* program_offset, const uint8_t** program_data,
    size_t* program_data_len);
bool erc7730_catalog_matches_calldata(const Erc7730CatalogIdentity* identity,
                                      uint64_t chain_id,
                                      const uint8_t contract_address[20],
                                      const uint8_t selector[4]);
bool erc7730_catalog_matches_eip712(const Erc7730CatalogIdentity* identity,
                                    uint64_t chain_id,
                                    const uint8_t* verifying_contract,
                                    bool has_verifying_contract,
                                    const uint8_t primary_type_hash[32]);
/* Returned bytes remain untrusted until a complete replay of the envelope has
 * passed erc7730_catalog_feed() for identity->definition_id. */
bool erc7730_catalog_program_chunk(const Erc7730CatalogIdentity* identity,
                                   uint32_t envelope_offset,
                                   const uint8_t* envelope_data,
                                   size_t envelope_data_len,
                                   uint32_t* program_offset,
                                   const uint8_t** program_data,
                                   size_t* program_data_len);
void erc7730_catalog_clear_preload(void);

#endif
