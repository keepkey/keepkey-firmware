#ifndef KEEPKEY_FIRMWARE_ERC7730_CATALOG_H
#define KEEPKEY_FIRMWARE_ERC7730_CATALOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/clearsign_root.h"
#include "keepkey/firmware/erc7730_abi.h"
#include "sha2.h"

#define ERC7730_PROGRAM_MAX_SIZE (16u * 1024u)
#define ERC7730_TRANSPORT_CHUNK_MAX 1024u
#define ERC7730_CATALOG_MAX_PROOF_DEPTH 16u
#define ERC7730_PROGRAM_HEADER_SIZE 179u
#define ERC7730_PROGRAM_MAX_SECTIONS 9u

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

/* Authenticated lookup facts retained after a streamed envelope is accepted.
 * No pointer refers into a transport message and no descriptor bytes survive.
 */
typedef struct {
  uint8_t definition_id[32];
  uint8_t kind;
  uint64_t chain_id;
  uint8_t contract_address[20];
  uint8_t selector_or_type_hash[32];
  uint32_t provider_id;
  uint32_t issuance_epoch;
  uint32_t revocation_epoch;
  uint32_t program_length;
  char delegate_alias[CLEARSIGN_ALIAS_LEN + 1];
} Erc7730CatalogIdentity;

/* Incremental verifier. Its size is bounded independently of descriptor size;
 * callers may place it in a workflow union shared with EIP-712 state. */
typedef struct {
  SHA256_CTX envelope_hash;
  SHA256_CTX leaf_hash;
  uint8_t expected_id[32];
  uint8_t header[ERC7730_PROGRAM_HEADER_SIZE];
  uint8_t cert[CLEARSIGN_CERT_LEN];
  uint8_t signature[64];
  uint8_t merkle[32];
  uint8_t sibling[32];
  uint32_t total_length;
  uint32_t received;
  uint32_t program_length;
  uint32_t program_received;
  uint32_t section_remaining;
  uint32_t section_offset;
  uint64_t abi_child_mask;
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
  uint8_t path_slice_flags;
  bool path_full_seen;
  bool leaf_finalized;
  bool failed;
} Erc7730CatalogVerifier;

void erc7730_catalog_begin(Erc7730CatalogVerifier* verifier,
                           const uint8_t definition_id[32],
                           uint32_t total_length);

Erc7730CatalogResult erc7730_catalog_feed(Erc7730CatalogVerifier* verifier,
                                          uint32_t offset, const uint8_t* data,
                                          size_t data_len,
                                          Erc7730CatalogIdentity* identity);

void erc7730_catalog_abort(Erc7730CatalogVerifier* verifier);

/* Single offline-preload slot. Verifier storage is overlaid with the accepted
 * identity after authentication, so both never add together in .bss. */
Erc7730CatalogResult erc7730_catalog_preload_chunk(
    const uint8_t definition_id[32], uint32_t offset, uint32_t total_length,
    const uint8_t* data, size_t data_len, uint32_t* next_offset,
    bool* complete);
bool erc7730_catalog_preloaded(Erc7730CatalogIdentity* identity);
void erc7730_catalog_clear_preload(void);

#endif
