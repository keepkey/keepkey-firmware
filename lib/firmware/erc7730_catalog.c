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
  bool replaying;
  uint32_t replay_program_length;
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
    if (child_count == 0) {
      if (kind != 8 || v->abi_node_index != 0 || first_child != 0 ||
          v->abi_node_count != 1)
        return false;
    } else if (first_child <= v->abi_node_index ||
               first_child > v->abi_node_count ||
               child_count > v->abi_node_count - first_child) {
      return false;
    }
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
  return true;
}

static bool consume_utf8(Erc7730CatalogVerifier* v, uint8_t byte) {
  if (v->utf8_remaining != 0) {
    if (byte < v->utf8_lower || byte > v->utf8_upper) return false;
    v->utf8_lower = 0x80;
    v->utf8_upper = 0xbf;
    v->utf8_remaining--;
    return true;
  }
  if (byte >= 0x20 && byte <= 0x7e) return true;
  if (byte >= 0xc2 && byte <= 0xdf) {
    v->utf8_remaining = 1;
  } else if (byte == 0xe0) {
    v->utf8_remaining = 2;
    v->utf8_lower = 0xa0;
    v->utf8_upper = 0xbf;
  } else if (byte >= 0xe1 && byte <= 0xec) {
    v->utf8_remaining = 2;
  } else if (byte == 0xed) {
    v->utf8_remaining = 2;
    v->utf8_upper = 0x9f;
  } else if (byte >= 0xee && byte <= 0xef) {
    v->utf8_remaining = 2;
  } else if (byte == 0xf0) {
    v->utf8_remaining = 3;
    v->utf8_lower = 0x90;
    v->utf8_upper = 0xbf;
  } else if (byte >= 0xf1 && byte <= 0xf3) {
    v->utf8_remaining = 3;
  } else if (byte == 0xf4) {
    v->utf8_remaining = 3;
    v->utf8_upper = 0x8f;
  } else {
    return false;
  }
  return true;
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

  if (!consume_utf8(v, byte)) return false;
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
    v->previous_length = v->entry_length;
    v->entry_length = 0;
    v->entry_offset = 0;
    v->entry_index++;
  }
  return true;
}

static void finish_path_step(Erc7730CatalogVerifier* v) {
  v->path_step_index++;
  v->path_step_opcode = 0;
  v->path_step_remaining = 0;
  v->path_slice_flags = 0;
  if (v->path_step_index == v->path_step_count) {
    v->entry_index++;
    v->field_received = 0;
    v->path_step_index = 0;
    v->path_step_count = 0;
    v->path_source = 0;
    v->path_full_seen = false;
  }
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
    if (v->path_source < 1 || v->path_source > 3 ||
        v->path_step_count > ERC7730_ABI_MAX_PATH)
      return false;
    if (v->path_source == 1) {
      if (source_index != UINT16_MAX || v->path_step_count == 0) return false;
    } else {
      if (v->path_step_count != 0) return false;
      if ((v->path_source == 2 && (source_index == 0 || source_index > 6)) ||
          (v->path_source == 3 && source_index == UINT16_MAX))
        return false;
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
    if (byte == 1) {
      v->path_step_remaining = 4;
    } else if (byte == 2) {
      v->path_full_seen = true;
      finish_path_step(v);
    } else if (byte == 3) {
      if (v->path_step_index + 1 != v->path_step_count) return false;
      /* A zero remaining count means the next byte is the slice flags. */
    } else {
      return false;
    }
    return true;
  }

  if (v->path_step_opcode == 3 && v->path_slice_flags == 0) {
    if (byte == 0 || (byte & (uint8_t)~0x03u) != 0) return false;
    v->path_slice_flags = byte;
    v->path_step_remaining =
        (uint8_t)(((byte & 1u) ? 4u : 0u) + ((byte & 2u) ? 4u : 0u));
    return true;
  }

  if (v->path_step_remaining == 0) return false;
  if (--v->path_step_remaining == 0) finish_path_step(v);
  return true;
}

static void finish_literal(Erc7730CatalogVerifier* v) {
  if (v->literal_kind == 9)
    v->literal_set_mask |= UINT64_C(1) << v->entry_index;
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
    if (v->literal_kind < 1 || v->literal_kind > 9 ||
        v->entry_length > v->section_remaining - 1u)
      return false;
    if (((v->literal_kind == 1 || v->literal_kind == 2) &&
         (v->entry_length == 0 || v->entry_length > 32)) ||
        (v->literal_kind == 4 && v->entry_length != 2) ||
        (v->literal_kind == 5 && v->entry_length != 20) ||
        (v->literal_kind == 6 && v->entry_length != 1) ||
        (v->literal_kind == 7 &&
         (v->entry_length == 0 || v->entry_length > 8)) ||
        ((v->literal_kind == 8 || v->literal_kind == 9) && v->entry_length < 2))
      return false;
    if (v->entry_length == 0) finish_literal(v);
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
          read_be16(v->sibling + 2) >= v->table_counts[0])
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
      v->sibling[7] != 0)
    return false;
  if (opcode <= 3) return path == UINT16_MAX && set == UINT16_MAX;
  if (path >= v->table_counts[2]) return false;
  if (opcode <= 5) return set == UINT16_MAX;
  return set < v->table_counts[3] &&
         (v->literal_set_mask & (UINT64_C(1) << set)) != 0;
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

#define FORMAT_ROLE_BIT(role) (UINT32_C(1) << (role))

static uint32_t formatter_allowed_roles(uint8_t kind) {
  const uint32_t value = FORMAT_ROLE_BIT(1);
  switch (kind) {
    case 1: /* raw */
    case 2: /* native amount */
    case 6: /* duration */
    case 9: /* chain id */
      return value;
    case 3: /* token amount */
      return value | FORMAT_ROLE_BIT(2) | FORMAT_ROLE_BIT(7) |
             FORMAT_ROLE_BIT(8) | FORMAT_ROLE_BIT(11) | FORMAT_ROLE_BIT(22);
    case 4: /* NFT */
      return value | FORMAT_ROLE_BIT(3) | FORMAT_ROLE_BIT(11);
    case 5: /* date */
      return value | FORMAT_ROLE_BIT(9);
    case 7: /* unit */
      return value | FORMAT_ROLE_BIT(4) | FORMAT_ROLE_BIT(5) |
             FORMAT_ROLE_BIT(6);
    case 8: /* enum */
      return value | FORMAT_ROLE_BIT(10);
    case 10: /* address name */
    case 12: /* interoperable address */
      return value | FORMAT_ROLE_BIT(12) | FORMAT_ROLE_BIT(13) |
             FORMAT_ROLE_BIT(14);
    case 11: /* token ticker */
      return value | FORMAT_ROLE_BIT(11);
    case 13: /* embedded calldata */
      return value | FORMAT_ROLE_BIT(11) | FORMAT_ROLE_BIT(15) |
             FORMAT_ROLE_BIT(16) | FORMAT_ROLE_BIT(17) | FORMAT_ROLE_BIT(18);
    case 14: /* encrypted value */
      return value | FORMAT_ROLE_BIT(19) | FORMAT_ROLE_BIT(20) |
             FORMAT_ROLE_BIT(21) | FORMAT_ROLE_BIT(23);
    default:
      return 0;
  }
}

static bool finish_formatter(Erc7730CatalogVerifier* v) {
  const uint32_t roles = v->formatter_roles;
  if ((roles & FORMAT_ROLE_BIT(1)) == 0 ||
      (roles & ~formatter_allowed_roles(v->formatter_kind)) != 0)
    return false;
  if ((v->formatter_kind == 4 && (roles & FORMAT_ROLE_BIT(3)) == 0) ||
      (v->formatter_kind == 8 && (roles & FORMAT_ROLE_BIT(10)) == 0) ||
      (v->formatter_kind == 13 && (roles & FORMAT_ROLE_BIT(15)) == 0) ||
      (v->formatter_kind == 14 &&
       (roles &
        (FORMAT_ROLE_BIT(19) | FORMAT_ROLE_BIT(20) | FORMAT_ROLE_BIT(23))) !=
           (FORMAT_ROLE_BIT(19) | FORMAT_ROLE_BIT(20) | FORMAT_ROLE_BIT(23))))
    return false;
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
      (source == 1 && index >= v->table_counts[2]) ||
      (source == 2 && index >= v->table_counts[3]) ||
      (source == 3 && index >= v->table_counts[0]))
    return false;
  v->formatter_last_role = role;
  v->formatter_roles |= FORMAT_ROLE_BIT(role);
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
  if (opcode < 1 || opcode > 10 || flags != 0) return false;
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
      uint8_t* frame = v->signature + v->display_depth * 5u;
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
      const uint8_t* frame = v->signature + (v->display_depth - 1u) * 5u;
      const uint16_t begin = (uint16_t)(((uint16_t)frame[1] << 8) | frame[2]);
      const uint16_t end = (uint16_t)(((uint16_t)frame[3] << 8) | frame[4]);
      if (a != begin || end != pc || (opcode == 6 && frame[0] != 5) ||
          (opcode == 8 && frame[0] != 7))
        return false;
      v->display_depth--;
      return true;
    }
    case 9:
      return optional_index(a, v->table_counts[0]) && b < v->table_counts[5] &&
             optional_index(c, v->table_counts[4]);
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
      if (v->entry_count > 192 ||
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
      if (field == 0 || field > 5 || operation == 0 || operation > 2 ||
          (operation == 1 && literal >= v->table_counts[3]) ||
          (operation == 2 && literal != UINT16_MAX))
        return false;
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
      v->path_slice_flags = 0;
      v->path_full_seen = false;
      v->literal_kind = 0;
      v->literal_subcount = 0;
      v->literal_previous = UINT16_MAX;
      v->formatter_kind = 0;
      v->formatter_arg_count = 0;
      v->formatter_arg_index = 0;
      v->formatter_last_role = 0;
      v->formatter_roles = 0;
      v->display_depth = 0;
      v->binding_kind = 0;
      v->binding_previous_kind = 0;
      v->binding_previous_length = 0;
      v->binding_header_match = false;
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
  identity->envelope_length = v->total_length;
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
  if (!identity || !contract_address || !selector ||
      identity->kind != ERC7730_DEFINITION_CALLDATA ||
      identity->chain_id != chain_id ||
      memcmp(identity->contract_address, contract_address, 20) != 0 ||
      memcmp(identity->selector_or_type_hash, selector, 4) != 0) {
    return false;
  }

  /* Calldata selectors occupy exactly four bytes in the canonical header.
   * Recheck the zero tail here so a future parser relaxation cannot make two
   * distinct lookup keys compare as the same selector. */
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

  /* A zero contract in the authenticated header means the definition is
   * domain-wide. A nonzero contract is an additional mandatory binding fact;
   * it can never be satisfied by a missing domain member. */
  static const uint8_t zero_address[20] = {0};
  if (memcmp(identity->contract_address, zero_address, sizeof(zero_address)) ==
      0)
    return true;
  return has_verifying_contract && verifying_contract &&
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

void erc7730_catalog_replay_begin(Erc7730CatalogReplay* replay,
                                  const Erc7730CatalogIdentity* identity) {
  if (!replay) return;
  memzero(replay, sizeof(*replay));
  if (!identity) {
    replay->verifier.failed = true;
    return;
  }
  replay->program_length = identity->program_length;
  erc7730_catalog_begin(&replay->verifier, identity->definition_id,
                        identity->envelope_length);
}

Erc7730CatalogResult erc7730_catalog_replay_feed(
    Erc7730CatalogReplay* replay, const uint8_t definition_id[32],
    uint32_t offset, uint32_t total_length, const uint8_t* data,
    size_t data_len, uint32_t* program_offset, const uint8_t** program_data,
    size_t* program_data_len, Erc7730CatalogIdentity* accepted_identity) {
  if (program_offset) *program_offset = 0;
  if (program_data) *program_data = NULL;
  if (program_data_len) *program_data_len = 0;
  if (!replay || !definition_id || !program_offset || !program_data ||
      !program_data_len || !accepted_identity ||
      memcmp(replay->verifier.expected_id, definition_id, 32) != 0 ||
      replay->verifier.total_length != total_length) {
    if (replay) replay->verifier.failed = true;
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }

  Erc7730CatalogIdentity extraction_identity;
  memzero(&extraction_identity, sizeof(extraction_identity));
  extraction_identity.program_length = replay->program_length;
  uint32_t candidate_offset;
  const uint8_t* candidate_data;
  size_t candidate_length;
  if (!erc7730_catalog_program_chunk(&extraction_identity, offset, data,
                                     data_len, &candidate_offset,
                                     &candidate_data, &candidate_length)) {
    replay->verifier.failed = true;
    return ERC7730_CATALOG_BAD_SEQUENCE;
  }

  const Erc7730CatalogResult result = erc7730_catalog_feed(
      &replay->verifier, offset, data, data_len, accepted_identity);
  if (result == ERC7730_CATALOG_MORE || result == ERC7730_CATALOG_COMPLETE) {
    *program_offset = candidate_offset;
    *program_data = candidate_data;
    *program_data_len = candidate_length;
  }
  memzero(&extraction_identity, sizeof(extraction_identity));
  return result;
}

void erc7730_catalog_clear_preload(void) { memzero(&preload, sizeof(preload)); }
