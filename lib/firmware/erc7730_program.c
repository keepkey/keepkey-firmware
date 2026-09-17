#include "keepkey/firmware/erc7730_program.h"

#include "memzero.h"

static uint32_t read_be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

static uint16_t read_be16(const uint8_t* p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

void erc7730_program_index_begin(Erc7730ProgramIndex* index,
                                 uint32_t program_length) {
  if (!index) return;
  memzero(index, sizeof(*index));
  index->program_length = program_length;
  if (program_length < ERC7730_PROGRAM_HEADER_SIZE ||
      program_length > ERC7730_PROGRAM_MAX_SIZE) {
    index->failed = true;
  }
}

bool erc7730_program_index_feed(Erc7730ProgramIndex* index,
                                uint32_t program_offset, const uint8_t* data,
                                size_t data_len) {
  if (!index || !data || data_len == 0 || index->failed || index->complete ||
      program_offset != index->received ||
      data_len > index->program_length - index->received) {
    if (index) index->failed = true;
    return false;
  }

  for (size_t i = 0; i < data_len; i++, index->received++) {
    const uint8_t byte = data[i];
    if (index->received < ERC7730_PROGRAM_HEADER_SIZE) {
      if (index->received == ERC7730_PROGRAM_HEADER_SIZE - 1u)
        index->declared_sections = byte;
      continue;
    }
    if (index->section_remaining != 0) {
      index->section_remaining--;
      continue;
    }

    index->section_header[index->section_header_received++] = byte;
    if (index->section_header_received != sizeof(index->section_header))
      continue;
    const uint8_t type = index->section_header[0];
    const uint32_t length = read_be32(index->section_header + 1);
    const uint32_t payload_offset = index->received + 1u;
    if (type == 0 || type > ERC7730_PROGRAM_MAX_SECTIONS ||
        type <= index->last_section ||
        length > index->program_length - payload_offset) {
      index->failed = true;
      return false;
    }
    index->sections[type].offset = payload_offset;
    index->sections[type].length = length;
    index->last_section = type;
    index->sections_seen++;
    index->section_remaining = length;
    index->section_header_received = 0;
  }

  if (index->received == index->program_length) {
    index->complete = !index->failed && index->section_remaining == 0 &&
                      index->section_header_received == 0 &&
                      index->sections_seen == index->declared_sections;
    if (!index->complete) index->failed = true;
  }
  return !index->failed;
}

bool erc7730_program_index_complete(const Erc7730ProgramIndex* index) {
  return index && index->complete && !index->failed;
}

bool erc7730_program_index_section(const Erc7730ProgramIndex* index,
                                   uint8_t section,
                                   Erc7730ProgramSection* result) {
  if (!erc7730_program_index_complete(index) || !result || section == 0 ||
      section > ERC7730_PROGRAM_MAX_SECTIONS ||
      index->sections[section].length == 0) {
    return false;
  }
  *result = index->sections[section];
  return true;
}

void erc7730_program_index_clear(Erc7730ProgramIndex* index) {
  if (index) memzero(index, sizeof(*index));
}

void erc7730_program_abi_begin(Erc7730ProgramAbi* abi,
                               uint32_t section_length) {
  if (!abi) return;
  memzero(abi, sizeof(*abi));
  abi->section_length = section_length;
  if (section_length < 11 || section_length > 2 + 9 * ERC7730_ABI_MAX_NODES)
    abi->failed = true;
}

bool erc7730_program_abi_feed(Erc7730ProgramAbi* abi, uint32_t section_offset,
                              const uint8_t* data, size_t data_len) {
  if (!abi || !data || data_len == 0 || abi->failed || abi->complete ||
      section_offset != abi->received ||
      data_len > abi->section_length - abi->received) {
    if (abi) abi->failed = true;
    return false;
  }
  for (size_t i = 0; i < data_len; i++, abi->received++) {
    const uint8_t byte = data[i];
    if (abi->received < 2) {
      abi->entry[abi->received] = byte;
      if (abi->received == 1) {
        abi->node_count = read_be16(abi->entry);
        if (abi->node_count == 0 || abi->node_count > ERC7730_ABI_MAX_NODES ||
            abi->section_length != 2u + (uint32_t)abi->node_count * 9u) {
          abi->failed = true;
          return false;
        }
      }
      continue;
    }

    abi->entry[abi->entry_received++] = byte;
    if (abi->entry_received == sizeof(abi->entry)) {
      Erc7730AbiNode* node = &abi->nodes[abi->node_index++];
      node->kind = abi->entry[0];
      node->size = read_be16(abi->entry + 1);
      node->first_child = read_be16(abi->entry + 3);
      node->child_count = read_be16(abi->entry + 5);
      node->array_length = read_be16(abi->entry + 7);
      abi->entry_received = 0;
    }
  }

  if (abi->received == abi->section_length) {
    Erc7730AbiProgram program = {abi->nodes, abi->node_count, 0};
    abi->complete = abi->node_index == abi->node_count &&
                    abi->entry_received == 0 &&
                    erc7730_abi_validate_program(&program) == ERC7730_ABI_OK;
    if (!abi->complete) abi->failed = true;
  }
  return !abi->failed;
}

bool erc7730_program_abi_complete(const Erc7730ProgramAbi* abi,
                                  Erc7730AbiProgram* program) {
  if (!abi || !program || !abi->complete || abi->failed) return false;
  program->nodes = abi->nodes;
  program->node_count = abi->node_count;
  program->root = 0;
  return true;
}

void erc7730_program_abi_clear(Erc7730ProgramAbi* abi) {
  if (abi) memzero(abi, sizeof(*abi));
}
