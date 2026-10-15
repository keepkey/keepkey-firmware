#include "keepkey/firmware/erc7730_catalog.h"

#include <string.h>

#include "keepkey/firmware/erc7730_capabilities.h"
#include "trezor/crypto/memzero.h"

#define ERC7730_ENVELOPE_FIXED_SIZE (4u + 1u + 1u + 4u + 1u + 2u + 64u + 1u)
#define ERC7730_ENVELOPE_MAX_SIZE                           \
  (ERC7730_PROGRAM_MAX_SIZE + ERC7730_ENVELOPE_FIXED_SIZE + \
   ERC7730_CATALOG_MAX_PROOF_DEPTH * 32u + ERC7730_DELEGATE_RECORD_LEN)

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
  bool replaying;
  uint32_t replay_program_length;
  union {
    Erc7730CatalogVerifier verifier;
    Erc7730CatalogIdentity identity;
  } data;
} preload;

static uint64_t read_be64(const uint8_t* p) {
  return ((uint64_t)read_be32(p) << 32) | read_be32(p + 4);
}

static bool all_zero(const uint8_t* p, size_t n) {
  uint8_t value = 0;
  for (size_t i = 0; i < n; i++) value |= p[i];
  return value == 0;
}

static bool verify_runtime_delegate(
    const Erc7730CatalogVerifier* v, uint32_t expected_scope,
    char out_alias[ERC7730_DELEGATE_ALIAS_LEN + 1],
    char out_fingerprint[METADATA_FINGERPRINT_LEN]) {
  const uint8_t* record = v->cert;
  if (record[ERC7730_DELEGATE_OFF_VERSION] != 1 || expected_scope == 0 ||
      read_be32(record + ERC7730_DELEGATE_OFF_SCOPE) != expected_scope) {
    return false;
  }
  bool alias_ended = false;
  for (size_t i = 0; i < ERC7730_DELEGATE_ALIAS_LEN; i++) {
    const uint8_t c = record[ERC7730_DELEGATE_OFF_ALIAS + i];
    if (alias_ended) {
      if (c != 0) return false;
    } else if (c == 0) {
      if (i == 0) return false;
      alias_ended = true;
    } else if (c < 0x20 || c > 0x7e) {
      return false;
    }
  }
  if (!alias_ended) return false;

  const uint8_t* pubkey = record + ERC7730_DELEGATE_OFF_PUBKEY;
  if (pubkey[0] != 0x02 && pubkey[0] != 0x03) return false;
  static const uint8_t purpose[] = "KEEPKEY:ERC7730:CATALOG\0";
  uint8_t attestation[sizeof(purpose) - 1 + 32];
  memcpy(attestation, purpose, sizeof(purpose) - 1);
  memcpy(attestation + sizeof(purpose) - 1, v->merkle, 32);
  char runtime_alias[METADATA_ALIAS_MAX_LEN + 1];
  const bool ok = signed_metadata_verify_runtime_attestation_for_pubkey(
      pubkey, attestation, sizeof(attestation), v->signature,
      sizeof(v->signature), runtime_alias);
  memzero(attestation, sizeof(attestation));
  if (!ok) return false;
  memzero(out_alias, ERC7730_DELEGATE_ALIAS_LEN + 1);
  strlcpy(out_alias, runtime_alias, ERC7730_DELEGATE_ALIAS_LEN + 1);
  signed_metadata_pubkey_fingerprint(pubkey, out_fingerprint);
  memzero(runtime_alias, sizeof(runtime_alias));
  return true;
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
#if ERC7730_MIN_ISSUANCE_EPOCH > 0
  /* Compiled only once raised: a zero floor admits every epoch. */
  if (read_be32(h + 170) < ERC7730_MIN_ISSUANCE_EPOCH) return false;
#endif
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
  if (v->abi_node_index == 0) {
    v->signature[0] = 1;
    v->abi_max_depth = 1;
  }
  if (kind == 1 || kind == 2) {
    if (size < 8 || size > 256 || size % 8 != 0) return false;
  } else if (kind == 5) {
    if (size == 0 || size > 32) return false;
  } else if (size != 0) {
    return false;
  }

  if (kind == 8 || kind == 9) {
    if (kind == 8 && child_count == 0) {
      if (v->abi_node_index != 0 || v->abi_node_count != 1 ||
          first_child != 0 || array_length != 0)
        return false;
      v->cert[0] = 0x80; /* argumentless root: tuple, first_child 0 */
      v->cert[1] = 0;
      return true;
    }
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
      const uint8_t depth = (uint8_t)(v->signature[v->abi_node_index] + 1u);
      if (depth > ERC7730_ABI_MAX_DEPTH) return false;
      v->signature[first_child + i] = depth;
      if (depth > v->abi_max_depth) v->abi_max_depth = depth;
    }
  } else if (first_child != 0 || child_count != 0 || array_length != 0) {
    return false;
  }
  /* cert[] is unused until the delegate record, so it holds the table:
   * kind (10 = dyn array) << 12 | first_child << 6 | (count or length) - 1. */
  const uint8_t stored_kind =
      kind == 9 && array_length == UINT16_MAX ? 10 : kind;
  const uint16_t extent = kind == 8   ? child_count
                          : kind == 9 ? array_length
                                      : 1;
  const uint16_t packed = (uint16_t)((uint16_t)stored_kind << 12 |
                                     (uint16_t)(first_child & 0x3fu) << 6 |
                                     (uint16_t)((extent - 1u) & 0x3fu));
  v->cert[2u * v->abi_node_index] = (uint8_t)(packed >> 8);
  v->cert[2u * v->abi_node_index + 1u] = (uint8_t)packed;
  return true;
}

_Static_assert(2u * ERC7730_ABI_MAX_NODES <= ERC7730_DELEGATE_RECORD_LEN,
               "ABI walk table must fit the delegate record buffer");

static uint16_t abi_entry(const Erc7730CatalogVerifier* v, uint8_t node) {
  return read_be16(v->cert + 2u * node);
}

/* Descend one index step from v->path_node, exactly as the calldata capture
 * and the EIP-712 capture do; anything they would refuse is refused here. */
static bool walk_path_index(Erc7730CatalogVerifier* v, int32_t index,
                            bool whole_array) {
  const uint16_t node_count = v->table_counts[1];
  if (v->path_node >= node_count) return false;
  const uint16_t entry = abi_entry(v, v->path_node);
  const uint8_t kind = (uint8_t)(entry >> 12);
  const uint8_t first_child = (uint8_t)((entry >> 6) & 0x3fu);
  const uint32_t extent = (entry & 0x3fu) + 1u;
  if (kind == 8) {
    /* first_child 0 marks the argumentless root, which has no children. */
    if (whole_array || first_child == 0 || index < 0 ||
        (uint32_t)index >= extent)
      return false;
    v->path_node = (uint8_t)(first_child + (uint32_t)index);
  } else if (kind == 9 || kind == 10) {
    if (!whole_array) v->path_array_indexed = true;
    const uint32_t length = kind == 9 ? extent : ERC7730_ABI_MAX_ARRAY_ELEMENTS;
    if ((index >= 0 && (uint32_t)index >= length) ||
        (index < 0 && (uint32_t)(-(int64_t)index) > length))
      return false;
    v->path_node = first_child;
  } else {
    return false;
  }
  return v->path_node < node_count;
}

static bool consume_string_byte(Erc7730CatalogVerifier* v, uint8_t byte) {
  v->section_offset++;
  if (v->section_offset <= 2) {
    v->sibling[v->section_offset - 1] = byte;
    if (v->section_offset == 2) {
      v->entry_count = read_be16(v->sibling);
      if (v->entry_count > 96) return false;
      v->table_counts[0] = v->entry_count;
    }
    return true;
  }
  if (v->entry_index >= v->entry_count) return false;
  if (v->entry_length == 0) {
    v->sibling[v->field_received++] = byte;
    if (v->field_received == 2) {
      v->entry_length = read_be16(v->sibling);
      v->field_received = 0;
      v->entry_offset = 0;
      v->compare_state = 0;
      v->utf8_remaining = 0;
      v->utf8_lower = 0x80;
      v->utf8_upper = 0xbf;
      if (v->entry_length == 0 || v->entry_length > 128 ||
          v->entry_length > v->section_remaining - 1u)
        return false;
      if (v->entry_length > v->max_string_length)
        v->max_string_length = (uint8_t)v->entry_length;
    }
    return true;
  }

  if (!erc7730_utf8_consume(&v->utf8_remaining, &v->utf8_lower, &v->utf8_upper,
                            byte, true))
    return false;
  if (v->entry_index != 0 && v->compare_state == 0) {
    if (v->entry_offset >= v->previous_length) {
      v->compare_state = 1;
    } else if (byte > v->cert[v->entry_offset]) {
      v->compare_state = 1;
    } else if (byte < v->cert[v->entry_offset]) {
      return false;
    }
  }
  v->cert[v->entry_offset++] = byte;
  if (v->entry_offset == v->entry_length) {
    if (v->utf8_remaining != 0 ||
        (v->entry_index != 0 && v->compare_state == 0))
      return false;
    if (v->entry_length <= ERC7730_CAP_SIGNER_TEXT_MAX)
      v->short_strings[v->entry_index / 8u] |=
          (uint8_t)(1u << (v->entry_index % 8u));
    /* cert[] holds the whole string now: note the date encodings. */
    if (erc7730_cap_string_class((const char*)v->cert, v->entry_length) ==
        ERC7730_CLASS_DATE_ENCODING)
      v->date_strings[v->entry_index / 8u] |=
          (uint8_t)(1u << (v->entry_index % 8u));
    v->previous_length = v->entry_length;
    v->entry_length = 0;
    v->entry_offset = 0;
    v->entry_index++;
  }
  return true;
}

static bool finish_path_step(Erc7730CatalogVerifier* v) {
  v->path_step_index++;
  v->path_step_opcode = 0;
  v->path_step_remaining = 0;
  if (v->path_step_index == v->path_step_count) {
    /* The value must be a leaf the capture returns: never a tuple or array. */
    if (v->path_node >= v->table_counts[1]) return false;
    const uint8_t leaf = (uint8_t)(abi_entry(v, v->path_node) >> 12);
    if (v->path_last_full) {
      /* Ends on its "every element" step: the path an iteration walks. An
       * element that is a leaf is also a value (address[] recipients); a
       * tuple element names none (class NONE), so no formatter reads it. */
      v->path_iterable_mask |= UINT64_C(1) << v->entry_index;
      v->signature[v->entry_index] =
          leaf <= ERC7730_ABI_STRING ? leaf : ERC7730_CLASS_NONE;
    } else if (leaf > ERC7730_ABI_STRING) {
      return false;
    } else {
      /* Formatter arguments are type-checked against this class. signature[]
       * is idle from the end of the ABI section until the display section. */
      v->signature[v->entry_index] = leaf;
    }
    v->entry_index++;
    v->field_received = 0;
    v->path_step_index = 0;
    v->path_step_count = 0;
    v->path_source = 0;
    v->path_full_seen = false;
    v->path_node = 0;
  }
  return true;
}

static bool consume_path_byte(Erc7730CatalogVerifier* v, uint8_t byte) {
  v->section_offset++;
  if (v->section_offset <= 2) {
    v->sibling[v->section_offset - 1] = byte;
    if (v->section_offset == 2) {
      v->entry_count = read_be16(v->sibling);
      if (v->entry_count > 64) return false;
      v->table_counts[2] = v->entry_count;
    }
    return true;
  }
  if (v->entry_index >= v->entry_count) return false;

  if (v->path_step_count == 0) {
    v->sibling[v->field_received++] = byte;
    if (v->field_received != 4) return true;
    v->path_source = v->sibling[0];
    v->path_step_count = v->sibling[1];
    const uint16_t source_index = read_be16(v->sibling + 2);
    /* Execution captures refuse ERC7730_ABI_MAX_DEPTH or more steps (each
     * step descends one ABI level), so no longer path may pass preload. */
    if (v->path_source < 1 || v->path_source > 3 ||
        (ERC7730_CAP_PATH_SOURCES & ERC7730_CAP_BIT(v->path_source)) == 0 ||
        v->path_step_count >= ERC7730_ABI_MAX_DEPTH)
      return false;
    v->path_node = 0; /* every value path starts at the root tuple */
    v->path_array_indexed = false;
    v->path_last_full = false;
    v->path_arrays[v->entry_index] = 0xff; /* no "every element" step */
    if (v->path_source == 1) {
      if (source_index != UINT16_MAX || v->path_step_count == 0) return false;
    } else {
      if (v->path_step_count != 0) return false;
      if ((v->path_source == 2 && (source_index == 0 || source_index > 6)) ||
          (v->path_source == 3 && source_index == UINT16_MAX))
        return false;
      if (v->path_source == 2) {
        /* @.from and @.to are addresses; containers are calldata only. */
        if ((ERC7730_CAP_CONTAINERS & ERC7730_CAP_BIT(source_index)) == 0 ||
            v->header[7] != ERC7730_DEFINITION_CALLDATA)
          return false;
        v->signature[v->entry_index] =
            source_index == 3 ? ERC7730_CLASS_UINT : ERC7730_CLASS_ADDRESS;
        if (source_index == 3) v->reads_value = true;
      } else {
        /* The literal table follows; resolve the class at the formatter. */
        if (source_index >= 64) return false;
        v->signature[v->entry_index] = (uint8_t)(0x40u | source_index);
      }
    }
    v->field_received = 0;
    if (v->path_step_count == 0) {
      v->entry_index++;
      v->path_source = 0;
    }
    return true;
  }

  if (v->path_step_opcode == 0) {
    v->path_step_opcode = byte;
    if (byte > 3 ||
        (ERC7730_CAP_PATH_STEP_OPCODES & ERC7730_CAP_BIT(byte)) == 0)
      return false;
    if (byte == 1) {
      v->path_step_remaining = 4;
    } else if (byte == 2) {
      /* One "every element" step per path, reached through tuples only, so
       * the array's ABI node alone identifies the array iterated. */
      if (v->path_full_seen || v->path_array_indexed) return false;
      v->path_full_seen = true;
      v->path_arrays[v->entry_index] = v->path_node;
      if (!walk_path_index(v, 0, true)) return false;
      v->path_last_full = true;
      return finish_path_step(v);
    } else {
      return false;
    }
    return true;
  }

  if (v->path_step_remaining == 0) return false;
  v->sibling[8u - v->path_step_remaining] = byte; /* sibling[4..7] */
  if (--v->path_step_remaining != 0) return true;
  if (!walk_path_index(v, (int32_t)read_be32(v->sibling + 4), false))
    return false;
  v->path_last_full = false;
  return finish_path_step(v);
}

static uint8_t literal_class(const Erc7730CatalogVerifier* v,
                             uint16_t literal) {
  if (literal >= v->table_counts[3] || literal >= 64) return ERC7730_CLASS_NONE;
  return (uint8_t)((v->literal_classes[literal / 2u] >> (4u * (literal % 2u))) &
                   0x0fu);
}

static bool short_string(const Erc7730CatalogVerifier* v, uint16_t index) {
  return index < v->table_counts[0] && index < 96u &&
         ((v->short_strings[index / 8u] >> (index % 8u)) & 1u) != 0;
}

static void finish_literal(Erc7730CatalogVerifier* v) {
  if (v->literal_kind == 1 && v->entry_length == 1 &&
      v->literal_first <= ERC7730_CAP_UNIT_DECIMALS_MAX)
    v->literal_decimals_mask |= UINT64_C(1) << v->entry_index;
  v->literal_classes[v->entry_index / 2u] |=
      (uint8_t)(erc7730_cap_literal_class(
                    v->literal_kind, v->literal_kind == 1 ? v->entry_length
                                                          : v->literal_subcount)
                << (4u * (v->entry_index % 2u)));
  v->entry_index++;
  v->entry_length = 0;
  v->entry_offset = 0;
  v->field_received = 0;
  v->literal_kind = 0;
  v->literal_subcount = 0;
  v->literal_previous = UINT16_MAX;
}

static bool consume_literal_byte(Erc7730CatalogVerifier* v, uint8_t byte) {
  v->section_offset++;
  if (v->section_offset <= 2) {
    v->sibling[v->section_offset - 1] = byte;
    if (v->section_offset == 2) {
      v->entry_count = read_be16(v->sibling);
      if (v->entry_count > 64) return false;
      v->table_counts[3] = v->entry_count;
    }
    return true;
  }
  if (v->entry_index >= v->entry_count) return false;
  if (v->entry_length == 0) {
    v->sibling[v->field_received++] = byte;
    if (v->field_received != 3) return true;
    v->literal_kind = v->sibling[0];
    v->entry_length = read_be16(v->sibling + 1);
    v->entry_offset = 0;
    v->field_received = 0;
    v->literal_previous = UINT16_MAX;
    /* The replay reader refuses empty and over-long literals, so a definition
     * that preloads must never carry one. */
    if (v->literal_kind < 1 || v->literal_kind > 9 || v->entry_length == 0 ||
        v->entry_length > ERC7730_LITERAL_MAX_LENGTH ||
        v->entry_length > v->section_remaining - 1u)
      return false;
    if (((v->literal_kind == 1 || v->literal_kind == 2) &&
         v->entry_length > 32) ||
        (v->literal_kind == 4 && v->entry_length != 2) ||
        (v->literal_kind == 5 && v->entry_length != 20) ||
        (v->literal_kind == 6 && v->entry_length != 1) ||
        (v->literal_kind == 7 && v->entry_length > 8) ||
        ((v->literal_kind == 8 || v->literal_kind == 9) && v->entry_length < 2))
      return false;
    return true;
  }

  if (v->entry_offset == 0) v->literal_first = byte;
  if (v->entry_offset == 1) v->literal_second = byte;
  if (v->literal_kind == 6 && byte > 1) return false;

  if (v->literal_kind == 8 || v->literal_kind == 9) {
    v->sibling[v->field_received++] = byte;
    if (v->entry_offset == 1) {
      v->literal_subcount = read_be16(v->sibling);
      const uint32_t expected =
          2u + (uint32_t)v->literal_subcount * (v->literal_kind == 8 ? 4u : 2u);
      if (expected != v->entry_length) return false;
      v->field_received = 0;
    } else if (v->entry_offset >= 2 &&
               v->field_received == (v->literal_kind == 8 ? 4 : 2)) {
      const uint16_t reference = read_be16(v->sibling);
      if (reference >= v->entry_index || (v->literal_previous != UINT16_MAX &&
                                          reference <= v->literal_previous))
        return false;
      if (v->literal_kind == 8 &&
          (read_be16(v->sibling + 2) >= v->table_counts[0] ||
           !short_string(v, read_be16(v->sibling + 2))))
        return false;
      v->literal_previous = reference;
      v->field_received = 0;
    }
  }

  v->entry_offset++;
  if (v->entry_offset != v->entry_length) return true;
  if (v->literal_kind == 1 || v->literal_kind == 7) {
    if (v->entry_length > 1 && v->literal_first == 0) return false;
    if (v->literal_kind == 7 && v->entry_length == 1 && v->literal_first == 0)
      return false;
  } else if (v->literal_kind == 2 && v->entry_length > 1) {
    if ((v->literal_first == 0 && (v->literal_second & 0x80u) == 0) ||
        (v->literal_first == 0xff && (v->literal_second & 0x80u) != 0))
      return false;
  } else if (v->literal_kind == 4) {
    const uint16_t string_index =
        (uint16_t)(((uint16_t)v->literal_first << 8) | v->literal_second);
    if (string_index >= v->table_counts[0]) return false;
  }
  finish_literal(v);
  return true;
}

static bool validate_condition(Erc7730CatalogVerifier* v) {
  const uint8_t opcode = v->sibling[0];
  const uint16_t path = read_be16(v->sibling + 1);
  const uint16_t set = read_be16(v->sibling + 3);
  if (opcode < 1 || opcode > 8 || v->sibling[5] != 0 || v->sibling[6] != 0 ||
      v->sibling[7] != 0 ||
      (ERC7730_CAP_CONDITION_OPCODES & ERC7730_CAP_BIT(opcode)) == 0)
    return false;
  /* Only "optional" (3) is admitted, which names no path and no set. */
  return path == UINT16_MAX && set == UINT16_MAX;
}

static bool consume_condition_byte(Erc7730CatalogVerifier* v, uint8_t byte) {
  v->section_offset++;
  if (v->section_offset <= 2) {
    v->sibling[v->section_offset - 1] = byte;
    if (v->section_offset == 2) {
      v->entry_count = read_be16(v->sibling);
      if (v->entry_count > 32 ||
          v->section_remaining - 1u != (uint32_t)v->entry_count * 8u)
        return false;
      v->table_counts[4] = v->entry_count;
    }
    return true;
  }
  v->sibling[v->field_received++] = byte;
  if (v->field_received == 8) {
    if (!validate_condition(v)) return false;
    v->field_received = 0;
    v->entry_index++;
  }
  return true;
}

static bool finish_formatter(Erc7730CatalogVerifier* v) {
  /* Every role passed erc7730_cap_argument_sources(), so only the required
   * set (which includes the value, role 1) is left to check. */
  const uint32_t roles = v->formatter_roles;
  const uint32_t required =
      erc7730_cap_formatter_required_roles(v->formatter_kind);
  if (required == 0 || (roles & required) != required) return false;
  /* Embedded calldata is executed for calldata definitions only. */
  if (v->formatter_kind == 13 && v->header[7] != ERC7730_DEFINITION_CALLDATA)
    return false;
  /* The display section checks iteration against these; cert[] is idle from
   * the end of the path section until the bindings. */
  v->cert[v->entry_index] = v->formatter_value_array;
  /* bit 0: an argument iterates; bit 1: an auxiliary path uses another
   * array or a scalar; bit 2: embedded calldata; bit 3: signer constant. */
  v->cert[64u + v->entry_index] =
      (uint8_t)((v->formatter_any_array ? 1u : 0u) |
                (v->formatter_mixed_arrays ? 2u : 0u) |
                (v->formatter_kind == 13 ? 4u : 0u) |
                (v->formatter_value_literal ? 8u : 0u));
  v->formatter_value_array = 0xff;
  v->formatter_any_array = false;
  v->formatter_mixed_arrays = false;
  v->formatter_value_literal = false;
  v->entry_index++;
  v->formatter_kind = 0;
  v->formatter_arg_count = 0;
  v->formatter_arg_index = 0;
  v->formatter_last_role = 0;
  v->formatter_roles = 0;
  v->field_received = 0;
  return true;
}

static bool consume_formatter_byte(Erc7730CatalogVerifier* v, uint8_t byte) {
  v->section_offset++;
  if (v->section_offset <= 2) {
    v->sibling[v->section_offset - 1] = byte;
    if (v->section_offset == 2) {
      v->entry_count = read_be16(v->sibling);
      if (v->entry_count > 64) return false;
      v->table_counts[5] = v->entry_count;
    }
    return true;
  }
  if (v->entry_index >= v->entry_count) return false;
  if (v->formatter_kind == 0) {
    v->sibling[v->field_received++] = byte;
    if (v->field_received != 3) return true;
    v->formatter_kind = v->sibling[0];
    v->formatter_arg_count = v->sibling[2];
    v->field_received = 0;
    if (v->formatter_kind < 1 || v->formatter_kind > 14 || v->sibling[1] != 0 ||
        v->formatter_arg_count == 0 || v->formatter_arg_count > 23)
      return false;
    return true;
  }

  v->sibling[v->field_received++] = byte;
  if (v->field_received != 4) return true;
  const uint8_t role = v->sibling[0];
  const uint8_t source = v->sibling[1];
  const uint16_t index = read_be16(v->sibling + 2);
  if (role == 0 || role > 23 || role <= v->formatter_last_role || source == 0 ||
      source > 3 || (role == 1 && source != 1) ||
      (erc7730_cap_argument_sources(v->formatter_kind, role) &
       ERC7730_CAP_BIT(source)) == 0 ||
      (source == 1 && index >= v->table_counts[2]) ||
      (source == 2 && index >= v->table_counts[3]) ||
      (source == 3 && index >= v->table_counts[0]))
    return false;
  uint8_t cls;
  if (source == 3) {
    cls = (v->date_strings[index / 8u] >> (index % 8u)) & 1u
              ? ERC7730_CLASS_DATE_ENCODING
              : ERC7730_CLASS_STRING;
  } else {
    cls = source == 2 ? literal_class(v, index) : v->signature[index];
    if (source == 1 && (cls & 0x40u) != 0) cls = literal_class(v, cls & 0x3fu);
  }
  if (!erc7730_cap_value(v->formatter_kind, role, cls)) return false;
  /* Signer text shown in a value's screen stays short enough to render. */
  if (source == 3 && (role == 5 || role == 8) && !short_string(v, index))
    return false;
  /* unit decimals: a one-byte literal no greater than the digits of a word. */
  if (v->formatter_kind == 7 && role == 4 &&
      (index >= 64 || ((v->literal_decimals_mask >> index) & 1u) == 0))
    return false;
  /* Only raw may show a signer constant; an embedded call's callee, value and
   * authority always come from calldata or a tx container. */
  if (source == 1 && (v->signature[index] & 0x40u) != 0 &&
      ((role == 1 && v->formatter_kind != 1) ||
       (v->formatter_kind == 13 && (role == 15 || role == 17 || role == 18))))
    return false;
  if (role == 1 && (v->signature[index] & 0x40u) != 0)
    v->formatter_value_literal = true;
  if (source == 1) {
    const uint8_t argument_array = v->path_arrays[index];
    if (argument_array != 0xff) v->formatter_any_array = true;
    if (role == 1)
      v->formatter_value_array = argument_array;
    else if (argument_array != v->formatter_value_array)
      v->formatter_mixed_arrays = true;
  }
  v->formatter_last_role = role;
  v->formatter_roles |= ERC7730_CAP_BIT(role);
  v->formatter_arg_index++;
  v->field_received = 0;
  if (v->formatter_arg_index == v->formatter_arg_count)
    return finish_formatter(v);
  return true;
}

static bool optional_index(uint16_t index, uint16_t count) {
  return index == UINT16_MAX || index < count;
}

static bool validate_display_instruction(Erc7730CatalogVerifier* v) {
  const uint8_t opcode = v->sibling[0];
  const uint8_t flags = v->sibling[1];
  const uint16_t a = read_be16(v->sibling + 2);
  const uint16_t b = read_be16(v->sibling + 4);
  const uint16_t c = read_be16(v->sibling + 6);
  const uint16_t pc = v->entry_index;
  const Erc7730DisplayInstruction executable = {opcode, flags, a, b, c};
  if (opcode < 1 || opcode > 10 || flags != 0 ||
      !erc7730_cap_display(&executable, pc))
    return false;
  /* The runtime leaves the review only at an end instruction, so the last
   * instruction must be one. */
  if (pc + 1u == v->entry_count && opcode != 10) return false;
  /* Iteration: one array at a time, calldata only, and every field inside
   * reads that array; an argument that iterates only inside it. */
  if (opcode == 7) {
    if (a >= 64 || ((v->path_iterable_mask >> a) & 1u) == 0 ||
        v->display_in_iteration || v->header[7] != ERC7730_DEFINITION_CALLDATA)
      return false;
    v->display_in_iteration = true;
    v->display_iteration_array = v->path_arrays[a];
  } else if (opcode == 8) {
    v->display_in_iteration = false;
  } else if (opcode == 3 || opcode == 4) {
    const uint16_t formatter = opcode == 3 ? a : b;
    if (formatter >= 64) return false;
    const uint8_t value_array = v->cert[formatter];
    /* Intent value: never an embedded call or a signer constant. */
    if (opcode == 3 && (v->cert[64u + formatter] & 12u) != 0) return false;
    /* A field label is signer text shown with its value. */
    if (opcode == 4 && !short_string(v, a)) return false;
    if (((v->cert[64u + formatter] & 1u) != 0 && !v->display_in_iteration) ||
        (v->display_in_iteration &&
         (value_array != v->display_iteration_array ||
          (v->cert[64u + formatter] & 2u) != 0)))
      return false;
  }
  /* Interpolated-intent parts form one run directly after the intent. */
  if (pc != 0) {
    if (opcode == 2 || opcode == 3) {
      if (v->display_intent_run_closed) return false;
    } else {
      v->display_intent_run_closed = true;
    }
  }
  switch (opcode) {
    case 1:
      return a < v->table_counts[0] && optional_index(b, v->table_counts[4]) &&
             c == UINT16_MAX;
    case 2:
      return a < v->table_counts[0] && b == UINT16_MAX && c == UINT16_MAX;
    case 3:
      return a < v->table_counts[5] && b == UINT16_MAX && c == UINT16_MAX;
    case 4:
      return a < v->table_counts[0] && b < v->table_counts[5] &&
             optional_index(c, v->table_counts[4]);
    case 5:
    case 7: {
      if ((opcode == 5 && !optional_index(a, v->table_counts[0])) ||
          (opcode == 7 && a >= v->table_counts[2]) ||
          !optional_index(b, v->table_counts[4]) || c <= pc ||
          c >= v->entry_count || v->display_depth >= ERC7730_ABI_MAX_DEPTH)
        return false;
      uint8_t* frame = v->display_frames + v->display_depth * 5u;
      frame[0] = opcode;
      frame[1] = (uint8_t)(pc >> 8);
      frame[2] = (uint8_t)pc;
      frame[3] = (uint8_t)(c >> 8);
      frame[4] = (uint8_t)c;
      v->display_depth++;
      if (v->display_depth > v->display_max_depth)
        v->display_max_depth = v->display_depth;
      return true;
    }
    case 6:
    case 8: {
      if (v->display_depth == 0 || c != UINT16_MAX ||
          (opcode == 6 && b != UINT16_MAX) ||
          (opcode == 8 && !optional_index(b, v->table_counts[0])))
        return false;
      const uint8_t* frame = v->display_frames + (v->display_depth - 1u) * 5u;
      const uint16_t begin = (uint16_t)(((uint16_t)frame[1] << 8) | frame[2]);
      const uint16_t end = (uint16_t)(((uint16_t)frame[3] << 8) | frame[4]);
      if (a != begin || end != pc || (opcode == 6 && frame[0] != 5) ||
          (opcode == 8 && frame[0] != 7))
        return false;
      v->display_depth--;
      return true;
    }
    case 10:
      return pc + 1u == v->entry_count && v->display_depth == 0 &&
             a == UINT16_MAX && b == UINT16_MAX && c == UINT16_MAX;
  }
  return false;
}

static bool consume_display_byte(Erc7730CatalogVerifier* v, uint8_t byte) {
  v->section_offset++;
  if (v->section_offset <= 2) {
    v->sibling[v->section_offset - 1] = byte;
    if (v->section_offset == 2) {
      v->entry_count = read_be16(v->sibling);
      /* Match the replay reader: executable definitions need at least one
       * instruction and no program may exceed its 64-instruction table. */
      if ((v->entry_count == 0 && v->header[7] <= ERC7730_DEFINITION_EIP712) ||
          v->entry_count > ERC7730_PROGRAM_MAX_DISPLAY_INSTRUCTIONS ||
          v->section_remaining - 1u != (uint32_t)v->entry_count * 8u)
        return false;
      v->table_counts[6] = v->entry_count;
    }
    return true;
  }
  v->sibling[v->field_received++] = byte;
  if (v->field_received == 8) {
    if (!validate_display_instruction(v)) return false;
    v->field_received = 0;
    v->entry_index++;
  }
  return true;
}

static bool finish_binding(Erc7730CatalogVerifier* v) {
  const uint8_t* payload = v->cert;
  if (v->entry_index != 0 && v->compare_state == 0) return false;
  switch (v->binding_kind) {
    case 1: {
      const uint64_t chain_id = read_be64(payload);
      if (chain_id == 0 || chain_id > UINT32_MAX || all_zero(payload + 8, 20))
        return false;
      const uint8_t* header_address = v->header + 18;
      if (chain_id == read_be64(v->header + 10) &&
          (all_zero(header_address, 20) ||
           memcmp(header_address, payload + 8, 20) == 0))
        v->binding_header_match = true;
      break;
    }
    case 2: {
      const uint8_t field = payload[0];
      const uint8_t operation = payload[1];
      const uint16_t literal = read_be16(payload + 2);
      /* The loader keeps one constraint per domain field and refuses a
       * second one, so the verifier must as well. */
      if (field == 0 || field > 5 || operation == 0 || operation > 2 ||
          (operation == 1 && literal >= v->table_counts[3]) ||
          (operation == 2 && literal != UINT16_MAX) ||
          (v->binding_domain_fields & (1u << field)) != 0)
        return false;
      v->binding_domain_fields |= (uint8_t)(1u << field);
      break;
    }
    case 3: {
      const uint64_t chain_id = read_be64(payload);
      if (chain_id == 0 || chain_id > UINT32_MAX || all_zero(payload + 8, 20) ||
          read_be16(payload + 28) >= v->table_counts[0])
        return false;
      if (v->header[7] == ERC7730_DEFINITION_TOKEN &&
          chain_id == read_be64(v->header + 10) &&
          memcmp(v->header + 18, payload + 8, 20) == 0)
        v->binding_header_match = true;
      break;
    }
    case 4:
      if (read_be64(payload) == 0 || read_be64(payload) > UINT32_MAX ||
          read_be16(payload + 8) >= v->table_counts[0] ||
          read_be16(payload + 10) >= v->table_counts[0])
        return false;
      if (v->header[7] == ERC7730_DEFINITION_NETWORK &&
          read_be64(payload) == read_be64(v->header + 10))
        v->binding_header_match = true;
      break;
    default:
      return false;
  }
  v->binding_previous_kind = v->binding_kind;
  v->binding_previous_length = v->entry_length;
  v->entry_index++;
  v->binding_kind = 0;
  v->entry_length = 0;
  v->entry_offset = 0;
  v->field_received = 0;
  v->compare_state = 0;
  return true;
}

static bool consume_binding_byte(Erc7730CatalogVerifier* v, uint8_t byte) {
  v->section_offset++;
  if (v->section_offset <= 2) {
    v->sibling[v->section_offset - 1] = byte;
    if (v->section_offset == 2) {
      v->entry_count = read_be16(v->sibling);
      if (v->entry_count > 64) return false;
      v->table_counts[7] = v->entry_count;
    }
    return true;
  }
  if (v->entry_index >= v->entry_count) return false;
  if (v->binding_kind == 0) {
    v->sibling[v->field_received++] = byte;
    if (v->field_received != 3) return true;
    v->binding_kind = v->sibling[0];
    v->entry_length = read_be16(v->sibling + 1);
    v->field_received = 0;
    v->entry_offset = 0;
    v->compare_state =
        v->entry_index != 0 && v->binding_kind > v->binding_previous_kind ? 1
                                                                          : 0;
    const uint16_t expected = v->binding_kind == 1   ? 28
                              : v->binding_kind == 2 ? 4
                              : v->binding_kind == 3 ? 31
                              : v->binding_kind == 4 ? 13
                                                     : 0;
    if (expected == 0 || v->entry_length != expected ||
        v->entry_length > v->section_remaining - 1u ||
        (v->entry_index != 0 && v->binding_kind < v->binding_previous_kind))
      return false;
    return true;
  }

  if (v->entry_index != 0 && v->compare_state == 0 &&
      v->binding_kind == v->binding_previous_kind) {
    if (v->entry_offset >= v->binding_previous_length ||
        byte > v->cert[v->entry_offset])
      v->compare_state = 1;
    else if (byte < v->cert[v->entry_offset])
      return false;
  }
  v->cert[v->entry_offset++] = byte;
  if (v->entry_offset == v->entry_length) return finish_binding(v);
  return true;
}

static bool consume_section_byte(Erc7730CatalogVerifier* v, uint8_t byte) {
  if (v->last_section == 1) return consume_string_byte(v, byte);
  if (v->last_section == 3) return consume_path_byte(v, byte);
  if (v->last_section == 4) return consume_literal_byte(v, byte);
  if (v->last_section == 5) return consume_condition_byte(v, byte);
  if (v->last_section == 6) return consume_formatter_byte(v, byte);
  if (v->last_section == 7) return consume_display_byte(v, byte);
  if (v->last_section == 8) return consume_binding_byte(v, byte);
  if (v->last_section == 9) {
    if (v->section_offset >= 22) return false;
    v->sibling[v->section_offset++] = byte;
    return true;
  }

  if (v->last_section != 2) {
    if (v->section_offset < 2) {
      v->sibling[v->section_offset] = byte;
      if (++v->section_offset == 2)
        v->table_counts[v->last_section - 1] = read_be16(v->sibling);
    } else {
      v->section_offset++;
    }
    return true;
  }

  v->sibling[v->field_received++] = byte;
  v->section_offset++;
  if (v->section_offset == 2) {
    v->abi_node_count = read_be16(v->sibling);
    v->table_counts[1] = v->abi_node_count;
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

static bool finish_section(const Erc7730CatalogVerifier* v) {
  if (v->last_section == 1)
    return v->section_offset >= 2 && v->entry_index == v->entry_count &&
           v->entry_length == 0 && v->field_received == 0;
  if (v->last_section == 3)
    return v->section_offset >= 2 && v->entry_index == v->entry_count &&
           v->field_received == 0 && v->path_step_count == 0 &&
           v->path_step_opcode == 0;
  if (v->last_section == 4)
    return v->section_offset >= 2 && v->entry_index == v->entry_count &&
           v->entry_length == 0 && v->field_received == 0;
  if (v->last_section == 5)
    return v->section_offset >= 2 && v->entry_index == v->entry_count &&
           v->field_received == 0;
  if (v->last_section == 6)
    return v->section_offset >= 2 && v->entry_index == v->entry_count &&
           v->formatter_kind == 0 && v->field_received == 0;
  if (v->last_section == 7)
    return v->section_offset >= 2 && v->entry_index == v->entry_count &&
           v->field_received == 0 && v->display_depth == 0;
  if (v->last_section == 8)
    return v->section_offset >= 2 && v->entry_index == v->entry_count &&
           v->binding_kind == 0 && v->field_received == 0 &&
           v->binding_header_match;
  if (v->last_section == 9) {
    if (v->section_offset != 22) return false;
    for (uint8_t i = 0; i < 8; i++) {
      if (read_be16(v->sibling + i * 2) != v->table_counts[i]) return false;
    }
    if (v->sibling[16] != v->abi_max_depth ||
        v->sibling[17] > ERC7730_ABI_MAX_ARRAY_ELEMENTS ||
        v->sibling[18] != v->display_max_depth || v->sibling[19] > 4 ||
        read_be16(v->sibling + 20) != v->max_string_length)
      return false;
    return true;
  }
  if (v->last_section != 2) return v->section_offset >= 2;
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
      v->entry_count = 0;
      v->entry_index = 0;
      v->entry_length = 0;
      v->entry_offset = 0;
      v->previous_length = 0;
      v->path_source = 0;
      v->path_step_count = 0;
      v->path_step_index = 0;
      v->path_step_opcode = 0;
      v->path_step_remaining = 0;
      v->path_full_seen = false;
      v->literal_kind = 0;
      v->literal_subcount = 0;
      v->literal_previous = UINT16_MAX;
      v->formatter_kind = 0;
      v->formatter_arg_count = 0;
      v->formatter_arg_index = 0;
      v->formatter_last_role = 0;
      v->formatter_roles = 0;
      v->formatter_value_array = 0xff;
      v->formatter_any_array = false;
      v->formatter_mixed_arrays = false;
      v->display_depth = 0;
      v->binding_kind = 0;
      v->binding_previous_kind = 0;
      v->binding_previous_length = 0;
      v->binding_header_match = false;
      v->binding_domain_fields = 0;
      if ((type == 9 && length != 22) || (type != 9 && length < 2))
        return false;
    }
  } else {
    if (!consume_section_byte(v, byte)) return false;
    v->section_remaining--;
    if (v->section_remaining == 0 && !finish_section(v)) return false;
  }
  v->program_received++;
  return true;
}

static bool finish_program(const Erc7730CatalogVerifier* v) {
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
  const uint16_t external_metadata = common | (1u << 4);
  return (v->section_mask & external_metadata) == external_metadata;
}

static Erc7730CatalogResult finish(Erc7730CatalogVerifier* v,
                                   Erc7730CatalogIdentity* identity) {
  uint8_t actual_id[32];
  sha256_Final(&v->envelope_hash, actual_id);
  if (memcmp(actual_id, v->expected_id, sizeof(actual_id)) != 0 ||
      v->cert_length != ERC7730_DELEGATE_RECORD_LEN || v->recovery > 1 ||
      !verify_runtime_delegate(v, (uint32_t)read_be64(v->header + 10),
                               identity->delegate_alias,
                               identity->delegate_fingerprint)) {
    memzero(actual_id, sizeof(actual_id));
    v->failed = true;
    return ERC7730_CATALOG_UNTRUSTED;
  }
  memcpy(identity->definition_id, actual_id, sizeof(actual_id));
  identity->kind = v->header[7];
  identity->chain_id = read_be64(v->header + 10);
  memcpy(identity->contract_address, v->header + 18, 20);
  memcpy(identity->selector_or_type_hash, v->header + 38, 32);
  identity->program_length = v->program_length;
  identity->envelope_length = v->total_length;
  identity->reads_value = v->reads_value;
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
          if (v->cert_length != ERC7730_DELEGATE_RECORD_LEN) {
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

bool erc7730_catalog_preloaded_reads_value(void) {
  return preload.available && preload.data.identity.reads_value;
}

bool erc7730_catalog_preloaded_replay_begin(uint8_t definition_id[32],
                                            uint32_t* total_length) {
  if (!definition_id || !total_length || !preload.available) return false;
  Erc7730CatalogIdentity identity;
  memcpy(&identity, &preload.data.identity, sizeof(identity));
  memcpy(definition_id, identity.definition_id, 32);
  *total_length = identity.envelope_length;
  preload.active = false;
  preload.available = false;
  preload.replaying = true;
  preload.replay_program_length = identity.program_length;
  erc7730_catalog_begin(&preload.data.verifier, identity.definition_id,
                        identity.envelope_length);
  memzero(&identity, sizeof(identity));
  if (preload.data.verifier.failed) {
    erc7730_catalog_clear_preload();
    return false;
  }
  return true;
}

bool erc7730_catalog_preloaded_replay_waiting(uint8_t definition_id[32],
                                              uint32_t* next_offset,
                                              uint32_t* total_length) {
  if (!definition_id || !next_offset || !total_length || !preload.replaying ||
      preload.data.verifier.failed) {
    return false;
  }
  memcpy(definition_id, preload.data.verifier.expected_id, 32);
  *next_offset = preload.data.verifier.received;
  *total_length = preload.data.verifier.total_length;
  return true;
}

Erc7730CatalogResult erc7730_catalog_preloaded_replay_feed(
    const uint8_t definition_id[32], uint32_t offset, uint32_t total_length,
    const uint8_t* data, size_t data_len, uint32_t* next_offset, bool* complete,
    uint32_t* program_offset, const uint8_t** program_data,
    size_t* program_data_len) {
  if (!next_offset || !complete || !program_offset || !program_data ||
      !program_data_len) {
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }
  *next_offset = 0;
  *complete = false;
  *program_offset = 0;
  *program_data = NULL;
  *program_data_len = 0;
  if (!preload.replaying || !definition_id ||
      memcmp(preload.data.verifier.expected_id, definition_id, 32) != 0 ||
      preload.data.verifier.total_length != total_length) {
    erc7730_catalog_clear_preload();
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }

  Erc7730CatalogIdentity extraction_identity;
  memzero(&extraction_identity, sizeof(extraction_identity));
  extraction_identity.program_length = preload.replay_program_length;
  uint32_t candidate_offset;
  const uint8_t* candidate_data;
  size_t candidate_length;
  if (!erc7730_catalog_program_chunk(&extraction_identity, offset, data,
                                     data_len, &candidate_offset,
                                     &candidate_data, &candidate_length)) {
    memzero(&extraction_identity, sizeof(extraction_identity));
    erc7730_catalog_clear_preload();
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }
  memzero(&extraction_identity, sizeof(extraction_identity));

  Erc7730CatalogIdentity accepted;
  memzero(&accepted, sizeof(accepted));
  const Erc7730CatalogResult result = erc7730_catalog_feed(
      &preload.data.verifier, offset, data, data_len, &accepted);
  if (result != ERC7730_CATALOG_MORE && result != ERC7730_CATALOG_COMPLETE) {
    memzero(&accepted, sizeof(accepted));
    erc7730_catalog_clear_preload();
    return result;
  }
  *program_offset = candidate_offset;
  *program_data = candidate_data;
  *program_data_len = candidate_length;
  if (result == ERC7730_CATALOG_MORE) {
    *next_offset = preload.data.verifier.received;
    return result;
  }

  memzero(&preload.data.verifier, sizeof(preload.data.verifier));
  memcpy(&preload.data.identity, &accepted, sizeof(accepted));
  memzero(&accepted, sizeof(accepted));
  preload.replaying = false;
  preload.available = true;
  *next_offset = total_length;
  *complete = true;
  return result;
}

bool erc7730_catalog_matches_calldata(const Erc7730CatalogIdentity* identity,
                                      uint64_t chain_id,
                                      const uint8_t contract_address[20],
                                      const uint8_t selector[4]) {
  /* No deployment may name the zero address, so a zero header contract can
   * never describe a transaction. */
  static const uint8_t zero_address[20] = {0};
  if (!identity || !contract_address || !selector ||
      identity->kind != ERC7730_DEFINITION_CALLDATA ||
      identity->chain_id != chain_id ||
      memcmp(identity->contract_address, zero_address, 20) == 0 ||
      memcmp(identity->contract_address, contract_address, 20) != 0 ||
      memcmp(identity->selector_or_type_hash, selector, 4) != 0) {
    return false;
  }

  /* Recheck the zero tail so two distinct keys never compare equal. */
  static const uint8_t zero_tail[28] = {0};
  return memcmp(identity->selector_or_type_hash + 4, zero_tail,
                sizeof(zero_tail)) == 0;
}

bool erc7730_catalog_matches_eip712(const Erc7730CatalogIdentity* identity,
                                    uint64_t chain_id,
                                    const uint8_t* verifying_contract,
                                    bool has_verifying_contract,
                                    const uint8_t primary_type_hash[32]) {
  if (!identity || !primary_type_hash ||
      identity->kind != ERC7730_DEFINITION_EIP712 ||
      identity->chain_id != chain_id ||
      memcmp(identity->selector_or_type_hash, primary_type_hash, 32) != 0)
    return false;

  /* EIP-712 needs a verifyingContract at a signed deployment; a zero header
   * contract defers that check to the loader, a nonzero one must equal it. */
  if (!has_verifying_contract || !verifying_contract) return false;
  static const uint8_t zero_address[20] = {0};
  return memcmp(identity->contract_address, zero_address,
                sizeof(zero_address)) == 0 ||
         memcmp(identity->contract_address, verifying_contract, 20) == 0;
}

bool erc7730_catalog_program_chunk(const Erc7730CatalogIdentity* identity,
                                   uint32_t envelope_offset,
                                   const uint8_t* envelope_data,
                                   size_t envelope_data_len,
                                   uint32_t* program_offset,
                                   const uint8_t** program_data,
                                   size_t* program_data_len) {
  if (!identity || !envelope_data || envelope_data_len == 0 ||
      envelope_data_len > ERC7730_TRANSPORT_CHUNK_MAX || !program_offset ||
      !program_data || !program_data_len ||
      identity->program_length < ERC7730_PROGRAM_HEADER_SIZE ||
      identity->program_length > ERC7730_PROGRAM_MAX_SIZE ||
      envelope_offset > UINT32_MAX - envelope_data_len) {
    return false;
  }

  *program_offset = 0;
  *program_data = NULL;
  *program_data_len = 0;
  const uint32_t chunk_end = envelope_offset + (uint32_t)envelope_data_len;
  const uint32_t program_start = 10;
  const uint32_t program_end = program_start + identity->program_length;
  const uint32_t overlap_start =
      envelope_offset > program_start ? envelope_offset : program_start;
  const uint32_t overlap_end =
      chunk_end < program_end ? chunk_end : program_end;
  if (overlap_start >= overlap_end) return true;

  *program_offset = overlap_start - program_start;
  *program_data = envelope_data + (overlap_start - envelope_offset);
  *program_data_len = overlap_end - overlap_start;
  return true;
}

void erc7730_catalog_clear_preload(void) { memzero(&preload, sizeof(preload)); }
