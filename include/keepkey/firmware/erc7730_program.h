#ifndef KEEPKEY_FIRMWARE_ERC7730_PROGRAM_H
#define KEEPKEY_FIRMWARE_ERC7730_PROGRAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_catalog.h"

typedef struct {
  uint32_t offset;
  uint32_t length;
} Erc7730ProgramSection;

typedef struct {
  Erc7730ProgramSection sections[ERC7730_PROGRAM_MAX_SECTIONS + 1];
  uint32_t program_length;
  uint32_t received;
  uint8_t section_header[5];
  uint8_t declared_sections;
  uint8_t sections_seen;
  uint8_t section_header_received;
  uint8_t last_section;
  uint32_t section_remaining;
  bool complete;
  bool failed;
} Erc7730ProgramIndex;

typedef struct {
  Erc7730AbiNode nodes[ERC7730_ABI_MAX_NODES];
  uint32_t section_length;
  uint32_t received;
  uint8_t entry[9];
  uint16_t node_count;
  uint16_t node_index;
  uint8_t entry_received;
  bool complete;
  bool failed;
} Erc7730ProgramAbi;

void erc7730_program_index_begin(Erc7730ProgramIndex* index,
                                 uint32_t program_length);
bool erc7730_program_index_feed(Erc7730ProgramIndex* index,
                                uint32_t program_offset, const uint8_t* data,
                                size_t data_len);
bool erc7730_program_index_complete(const Erc7730ProgramIndex* index);
bool erc7730_program_index_section(const Erc7730ProgramIndex* index,
                                   uint8_t section,
                                   Erc7730ProgramSection* result);
void erc7730_program_index_clear(Erc7730ProgramIndex* index);
void erc7730_program_abi_begin(Erc7730ProgramAbi* abi, uint32_t section_length);
bool erc7730_program_abi_feed(Erc7730ProgramAbi* abi, uint32_t section_offset,
                              const uint8_t* data, size_t data_len);
bool erc7730_program_abi_complete(const Erc7730ProgramAbi* abi,
                                  Erc7730AbiProgram* program);
void erc7730_program_abi_clear(Erc7730ProgramAbi* abi);

#endif
