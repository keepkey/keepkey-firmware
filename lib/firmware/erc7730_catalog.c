#include "keepkey/firmware/erc7730_catalog.h"

#include <string.h>

#include "memzero.h"

#define ERC7730_ENVELOPE_FIXED_SIZE (4u + 1u + 1u + 4u + 1u + 2u + 64u + 1u)
#define ERC7730_ENVELOPE_MAX_SIZE                           \
  (ERC7730_PROGRAM_MAX_SIZE + ERC7730_ENVELOPE_FIXED_SIZE + \
   ERC7730_CATALOG_MAX_PROOF_DEPTH * 32u + CLEARSIGN_CERT_LEN)

enum {
  STREAM_ENVELOPE_PREFIX = 0,
  STREAM_PROGRAM,
  STREAM_PROOF_COUNT,
  STREAM_PROOF,
  STREAM_CERT_LENGTH,
  STREAM_CERT,
  STREAM_SIGNATURE,
  STREAM_RECOVERY,
  STREAM_DONE,
};

static struct {
  bool active;
  bool available;
  union {
    Erc7730CatalogVerifier verifier;
    Erc7730CatalogIdentity identity;
  } data;
} preload;

static uint16_t read_be16(const uint8_t* p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t read_be64(const uint8_t* p) {
  return ((uint64_t)read_be32(p) << 32) | read_be32(p + 4);
}

static bool all_zero(const uint8_t* p, size_t n) {
  uint8_t value = 0;
  for (size_t i = 0; i < n; i++) value |= p[i];
  return value == 0;
}

static bool validate_header(const Erc7730CatalogVerifier* v) {
  const uint8_t* h = v->header;
  if (memcmp(h, "C773", 4) != 0 || h[4] != 1) return false;
  if (h[5] != 2 || h[6] > 1) return false;
  if (h[7] < ERC7730_DEFINITION_CALLDATA || h[7] > ERC7730_DEFINITION_NETWORK)
    return false;
  const uint64_t chain_id = read_be64(h + 10);
  if (read_be16(h + 8) != 0 || chain_id == 0 || chain_id > UINT32_MAX)
    return false;
  if (h[7] == ERC7730_DEFINITION_CALLDATA) {
    if (all_zero(h + 38, 4) || !all_zero(h + 42, 28)) return false;
  } else if (h[7] == ERC7730_DEFINITION_EIP712) {
    if (all_zero(h + 38, 32)) return false;
  } else if (!all_zero(h + 38, 32)) {
    return false;
  }
  if (all_zero(h + 70, 32) || all_zero(h + 102, 32) || all_zero(h + 134, 32) ||
      read_be32(h + 166) == 0 || read_be32(h + 170) < read_be32(h + 174))
    return false;
  if (h[178] == 0 || h[178] > ERC7730_PROGRAM_MAX_SECTIONS) return false;
  return true;
}

static void merkle_parent(uint8_t node[32], const uint8_t sibling[32]) {
  uint8_t input[65];
  input[0] = 0x01;
  if (memcmp(node, sibling, 32) <= 0) {
    memcpy(input + 1, node, 32);
    memcpy(input + 33, sibling, 32);
  } else {
    memcpy(input + 1, sibling, 32);
    memcpy(input + 33, node, 32);
  }
  sha256_Raw(input, sizeof(input), node);
  memzero(input, sizeof(input));
}

static bool validate_abi_node(Erc7730CatalogVerifier* v, const uint8_t* node) {
  const uint8_t kind = node[0];
  const uint16_t size = read_be16(node + 1);
  const uint16_t first_child = read_be16(node + 3);
  const uint16_t child_count = read_be16(node + 5);
  const uint16_t array_length = read_be16(node + 7);

  if (kind < 1 || kind > 9) return false;
  if (v->abi_node_index == 0 && kind != 8) return false;
  if (kind == 1 || kind == 2) {
    if (size < 8 || size > 256 || size % 8 != 0) return false;
  } else if (kind == 5) {
    if (size == 0 || size > 32) return false;
  } else if (size != 0) {
    return false;
  }

  if (kind == 8 || kind == 9) {
    if (first_child <= v->abi_node_index || child_count == 0 ||
        first_child > v->abi_node_count ||
        child_count > v->abi_node_count - first_child)
      return false;
    if (kind == 9 && (child_count != 1 || array_length == 0 ||
                      (array_length > ERC7730_ABI_MAX_ARRAY_ELEMENTS &&
                       array_length != UINT16_MAX)))
      return false;
    if (kind == 8 && array_length != 0) return false;
    for (uint16_t i = 0; i < child_count; i++) {
      const uint64_t bit = UINT64_C(1) << (first_child + i);
      if ((v->abi_child_mask & bit) != 0) return false;
      v->abi_child_mask |= bit;
    }
  } else if (first_child != 0 || child_count != 0 || array_length != 0) {
    return false;
  }
  return true;
}

static bool consume_section_byte(Erc7730CatalogVerifier* v, uint8_t byte) {
  if (v->last_section != 2) {
    v->section_offset++;
    return true;
  }

  v->sibling[v->field_received++] = byte;
  v->section_offset++;
  if (v->section_offset == 2) {
    v->abi_node_count = read_be16(v->sibling);
    v->field_received = 0;
    if (v->abi_node_count == 0 || v->abi_node_count > ERC7730_ABI_MAX_NODES ||
        v->section_remaining != (uint32_t)v->abi_node_count * 9u + 1u)
      return false;
  } else if (v->section_offset > 2 && v->field_received == 9) {
    if (!validate_abi_node(v, v->sibling)) return false;
    v->abi_node_index++;
    v->field_received = 0;
  }
  return true;
}

static bool finish_section(Erc7730CatalogVerifier* v) {
  if (v->last_section != 2) return true;
  if (v->field_received != 0 || v->abi_node_index != v->abi_node_count)
    return false;
  const uint64_t expected = v->abi_node_count == 64
                                ? UINT64_MAX & ~UINT64_C(1)
                                : ((UINT64_C(1) << v->abi_node_count) - 2u);
  return v->abi_child_mask == expected;
}

static bool consume_program_byte(Erc7730CatalogVerifier* v, uint8_t byte) {
  if (v->program_received < ERC7730_PROGRAM_HEADER_SIZE) {
    v->header[v->program_received] = byte;
    v->header_received++;
  } else if (v->section_remaining == 0) {
    /* Section header bytes are staged in sibling[], which is otherwise unused
     * until the definition has ended. */
    v->sibling[v->field_received++] = byte;
    if (v->field_received == 5) {
      const uint8_t type = v->sibling[0];
      const uint32_t length = read_be32(v->sibling + 1);
      if (type == 0 || type > ERC7730_PROGRAM_MAX_SECTIONS ||
          type <= v->last_section ||
          length > v->program_length - v->program_received - 1u) {
        return false;
      }
      v->last_section = type;
      v->sections_seen++;
      v->section_mask |= (uint16_t)(1u << type);
      v->section_remaining = length;
      v->section_offset = 0;
      v->field_received = 0;
      v->abi_node_count = 0;
      v->abi_node_index = 0;
      v->abi_child_mask = 0;
      if (length == 0 && type == 2) return false;
    }
  } else {
    if (!consume_section_byte(v, byte)) return false;
    v->section_remaining--;
    if (v->section_remaining == 0 && !finish_section(v)) return false;
  }
  v->program_received++;
  return true;
}

static bool finish_program(Erc7730CatalogVerifier* v) {
  if (v->header_received != ERC7730_PROGRAM_HEADER_SIZE ||
      !validate_header(v) || v->field_received != 0 ||
      v->section_remaining != 0 || v->sections_seen != v->header[178] ||
      v->last_section != 9)
    return false;
  const uint16_t common = (1u << 1) | (1u << 8) | (1u << 9);
  if (v->header[7] == ERC7730_DEFINITION_CALLDATA ||
      v->header[7] == ERC7730_DEFINITION_EIP712) {
    const uint16_t executable =
        common | (1u << 2) | (1u << 3) | (1u << 6) | (1u << 7);
    return (v->section_mask & executable) == executable;
  }
  return (v->section_mask & common) == common;
}

static Erc7730CatalogResult finish(Erc7730CatalogVerifier* v,
                                   Erc7730CatalogIdentity* identity) {
  uint8_t actual_id[32];
  sha256_Final(&v->envelope_hash, actual_id);
  if (memcmp(actual_id, v->expected_id, sizeof(actual_id)) != 0 ||
      v->cert_length != CLEARSIGN_CERT_LEN || v->recovery > 1 ||
      !clearsign_root_verify_erc7730_catalog(
          v->cert, sizeof(v->cert), (uint32_t)read_be64(v->header + 10),
          v->merkle, v->signature, sizeof(v->signature),
          identity->delegate_alias)) {
    memzero(actual_id, sizeof(actual_id));
    v->failed = true;
    return ERC7730_CATALOG_UNTRUSTED;
  }
  memcpy(identity->definition_id, actual_id, sizeof(actual_id));
  identity->kind = v->header[7];
  identity->chain_id = read_be64(v->header + 10);
  memcpy(identity->contract_address, v->header + 18, 20);
  memcpy(identity->selector_or_type_hash, v->header + 38, 32);
  identity->provider_id = read_be32(v->header + 166);
  identity->issuance_epoch = read_be32(v->header + 170);
  identity->revocation_epoch = read_be32(v->header + 174);
  identity->program_length = v->program_length;
  memzero(actual_id, sizeof(actual_id));
  v->state = STREAM_DONE;
  return ERC7730_CATALOG_COMPLETE;
}

void erc7730_catalog_begin(Erc7730CatalogVerifier* v,
                           const uint8_t definition_id[32],
                           uint32_t total_length) {
  if (!v) return;
  memzero(v, sizeof(*v));
  if (!definition_id || total_length < ERC7730_ENVELOPE_FIXED_SIZE ||
      total_length > ERC7730_ENVELOPE_MAX_SIZE) {
    v->failed = true;
    return;
  }
  memcpy(v->expected_id, definition_id, 32);
  v->total_length = total_length;
  sha256_Init(&v->envelope_hash);
  sha256_Init(&v->leaf_hash);
  const uint8_t leaf_prefix = 0;
  sha256_Update(&v->leaf_hash, &leaf_prefix, 1);
}

Erc7730CatalogResult erc7730_catalog_feed(Erc7730CatalogVerifier* v,
                                          uint32_t offset, const uint8_t* data,
                                          size_t data_len,
                                          Erc7730CatalogIdentity* identity) {
  if (!v || !data || !identity || v->failed || v->state == STREAM_DONE ||
      data_len == 0 || data_len > ERC7730_TRANSPORT_CHUNK_MAX ||
      offset != v->received || data_len > v->total_length - v->received) {
    if (v) v->failed = true;
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }

  sha256_Update(&v->envelope_hash, data, data_len);
  for (size_t i = 0; i < data_len; i++, v->received++) {
    const uint8_t byte = data[i];
    switch (v->state) {
      case STREAM_ENVELOPE_PREFIX:
        v->sibling[v->field_received++] = byte;
        if (v->field_received == 10) {
          if (memcmp(v->sibling, "K773", 4) != 0 || v->sibling[4] != 1 ||
              v->sibling[5] != 1) {
            v->failed = true;
            return ERC7730_CATALOG_BAD_ENVELOPE;
          }
          v->program_length = read_be32(v->sibling + 6);
          if (v->program_length < ERC7730_PROGRAM_HEADER_SIZE ||
              v->program_length > ERC7730_PROGRAM_MAX_SIZE) {
            v->failed = true;
            return ERC7730_CATALOG_BAD_ENVELOPE;
          }
          v->field_received = 0;
          v->state = STREAM_PROGRAM;
        }
        break;
      case STREAM_PROGRAM:
        sha256_Update(&v->leaf_hash, &byte, 1);
        if (!consume_program_byte(v, byte)) {
          v->failed = true;
          return ERC7730_CATALOG_BAD_PROGRAM;
        }
        if (v->program_received == v->program_length) {
          if (!finish_program(v)) {
            v->failed = true;
            return ERC7730_CATALOG_BAD_PROGRAM;
          }
          sha256_Final(&v->leaf_hash, v->merkle);
          v->leaf_finalized = true;
          v->state = STREAM_PROOF_COUNT;
        }
        break;
      case STREAM_PROOF_COUNT:
        v->proof_count = byte;
        if (v->proof_count > ERC7730_CATALOG_MAX_PROOF_DEPTH) {
          v->failed = true;
          return ERC7730_CATALOG_BAD_ENVELOPE;
        }
        v->state = v->proof_count ? STREAM_PROOF : STREAM_CERT_LENGTH;
        break;
      case STREAM_PROOF:
        v->sibling[v->field_received++] = byte;
        if (v->field_received == 32) {
          merkle_parent(v->merkle, v->sibling);
          v->field_received = 0;
          if (++v->proof_index == v->proof_count) v->state = STREAM_CERT_LENGTH;
        }
        break;
      case STREAM_CERT_LENGTH:
        v->sibling[v->field_received++] = byte;
        if (v->field_received == 2) {
          v->cert_length = read_be16(v->sibling);
          if (v->cert_length != CLEARSIGN_CERT_LEN) {
            v->failed = true;
            return ERC7730_CATALOG_BAD_ENVELOPE;
          }
          v->field_received = 0;
          v->state = STREAM_CERT;
        }
        break;
      case STREAM_CERT:
        v->cert[v->field_received++] = byte;
        if (v->field_received == v->cert_length) {
          v->field_received = 0;
          v->state = STREAM_SIGNATURE;
        }
        break;
      case STREAM_SIGNATURE:
        v->signature[v->field_received++] = byte;
        if (v->field_received == sizeof(v->signature)) {
          v->field_received = 0;
          v->state = STREAM_RECOVERY;
        }
        break;
      case STREAM_RECOVERY:
        v->recovery = byte;
        v->state = STREAM_DONE;
        break;
      default:
        v->failed = true;
        return ERC7730_CATALOG_BAD_ENVELOPE;
    }
  }

  if (v->received != v->total_length) return ERC7730_CATALOG_MORE;
  if (v->state != STREAM_DONE) {
    v->failed = true;
    return ERC7730_CATALOG_BAD_ENVELOPE;
  }
  return finish(v, identity);
}

void erc7730_catalog_abort(Erc7730CatalogVerifier* v) {
  if (v) memzero(v, sizeof(*v));
}

Erc7730CatalogResult erc7730_catalog_preload_chunk(
    const uint8_t definition_id[32], uint32_t offset, uint32_t total_length,
    const uint8_t* data, size_t data_len, uint32_t* next_offset,
    bool* complete) {
  if (!next_offset || !complete || !definition_id)
    return ERC7730_CATALOG_BAD_SEQUENCE;
  *next_offset = 0;
  *complete = false;

  if (offset == 0) {
    erc7730_catalog_clear_preload();
    erc7730_catalog_begin(&preload.data.verifier, definition_id, total_length);
    preload.active = !preload.data.verifier.failed;
  }
  if (!preload.active || preload.available ||
      memcmp(preload.data.verifier.expected_id, definition_id, 32) != 0 ||
      preload.data.verifier.total_length != total_length) {
    erc7730_catalog_clear_preload();
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }

  Erc7730CatalogIdentity accepted;
  memzero(&accepted, sizeof(accepted));
  const Erc7730CatalogResult result = erc7730_catalog_feed(
      &preload.data.verifier, offset, data, data_len, &accepted);
  if (result == ERC7730_CATALOG_MORE) {
    *next_offset = preload.data.verifier.received;
    return result;
  }
  if (result != ERC7730_CATALOG_COMPLETE) {
    memzero(&accepted, sizeof(accepted));
    erc7730_catalog_clear_preload();
    return result;
  }

  memzero(&preload.data.verifier, sizeof(preload.data.verifier));
  memcpy(&preload.data.identity, &accepted, sizeof(accepted));
  memzero(&accepted, sizeof(accepted));
  preload.active = false;
  preload.available = true;
  *next_offset = total_length;
  *complete = true;
  return result;
}

bool erc7730_catalog_preloaded(Erc7730CatalogIdentity* identity) {
  if (!identity || !preload.available) return false;
  memcpy(identity, &preload.data.identity, sizeof(*identity));
  return true;
}

void erc7730_catalog_clear_preload(void) { memzero(&preload, sizeof(preload)); }
