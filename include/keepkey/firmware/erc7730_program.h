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

/* Sections are canonical and ascending; the ABI is section 2. */
#define ERC7730_PROGRAM_SECTION_ABI 2u

typedef struct {
  uint16_t literals[5];
  uint8_t operations[5];
  uint8_t scratch[7];
  /* Required kind-1 payload (chain_id:u64 || verifyingContract) for typed
   * data; see erc7730_program_loader_require_deployment(). */
  uint8_t deployment[28];
  uint32_t received;
  uint16_t count;
  uint16_t index;
  uint16_t remaining;
  uint8_t staged;
  bool deployment_required;
  bool deployment_mismatch;
  bool deployment_listed;
} Erc7730DomainBindings;

typedef struct {
  Erc7730ProgramIndex index;
  Erc7730ProgramAbi abi;
  Erc7730DomainBindings domain;
  bool abi_started;
  bool failed;
} Erc7730ProgramLoader;

typedef struct {
  uint8_t opcode;
  int32_t first;
} Erc7730PathStep;

typedef struct {
  uint8_t source;
  uint8_t step_count;
  uint16_t source_index;
  Erc7730PathStep steps[ERC7730_ABI_MAX_PATH];
} Erc7730Path;

typedef struct {
  Erc7730Path selected;
  uint32_t section_length;
  uint32_t received;
  uint8_t scratch[8];
  uint16_t path_count;
  uint16_t path_index;
  uint16_t target_index;
  uint8_t header_received;
  uint8_t current_step_count;
  uint8_t step_index;
  uint8_t step_opcode;
  uint8_t step_value_received;
  uint8_t step_value_length;
  bool full_array_seen;
  bool selected_found;
  bool complete;
  bool failed;
} Erc7730ProgramPath;

#define ERC7730_PROGRAM_MAX_STRING_LENGTH 128u

typedef struct {
  uint8_t value[ERC7730_PROGRAM_MAX_STRING_LENGTH + 1u];
  uint32_t section_length;
  uint32_t received;
  uint16_t string_count;
  uint16_t string_index;
  uint16_t target_index;
  uint16_t selected_length;
  uint16_t current_length;
  uint16_t current_received;
  uint8_t header[2];
  uint8_t header_received;
  bool selected_found;
  bool complete;
  bool failed;
} Erc7730ProgramString;

typedef struct {
  uint8_t opcode;
  uint8_t flags;
  uint16_t a;
  uint16_t b;
  uint16_t c;
} Erc7730DisplayInstruction;

typedef struct {
  Erc7730DisplayInstruction selected;
  uint32_t section_length;
  uint32_t received;
  uint16_t instruction_count;
  uint16_t target_index;
  uint16_t instruction_index;
  /* Intent parts (opcodes 2, 3) directly following the intent. */
  uint16_t intent_parts;
  uint8_t entry[8];
  uint8_t entry_received;
  bool intent_run_closed;
  bool complete;
  bool failed;
} Erc7730ProgramDisplay;

#define ERC7730_FORMATTER_MAX_ARGUMENTS 23u

typedef struct {
  uint8_t role;
  uint8_t source;
  uint16_t index;
} Erc7730FormatterArgument;

typedef struct {
  uint8_t kind;
  uint8_t flags;
  uint8_t argument_count;
  Erc7730FormatterArgument arguments[ERC7730_FORMATTER_MAX_ARGUMENTS];
} Erc7730Formatter;

typedef struct {
  Erc7730Formatter selected;
  uint32_t section_length;
  uint32_t received;
  uint16_t formatter_count;
  uint16_t formatter_index;
  uint16_t target_index;
  uint8_t scratch[4];
  uint8_t header_received;
  uint8_t current_argument_count;
  uint8_t argument_index;
  uint8_t argument_received;
  bool complete;
  bool failed;
} Erc7730ProgramFormatter;

typedef struct {
  uint8_t kind;
  uint16_t length;
  uint8_t value[ERC7730_LITERAL_MAX_LENGTH];
} Erc7730Literal;

typedef struct {
  Erc7730Literal selected;
  uint32_t section_length;
  uint32_t received;
  uint16_t literal_count;
  uint16_t literal_index;
  uint16_t target_index;
  uint16_t current_length;
  uint16_t current_received;
  uint8_t header[3];
  uint8_t header_received;
  bool complete;
  bool failed;
} Erc7730ProgramLiteral;

void erc7730_program_index_begin(Erc7730ProgramIndex* index,
                                 uint32_t program_length);
bool erc7730_program_index_feed(Erc7730ProgramIndex* index,
                                uint32_t program_offset, const uint8_t* data,
                                size_t data_len);
bool erc7730_program_index_complete(const Erc7730ProgramIndex* index);
bool erc7730_program_index_section(const Erc7730ProgramIndex* index,
                                   uint8_t section,
                                   Erc7730ProgramSection* result);
bool erc7730_program_index_known_section(const Erc7730ProgramIndex* index,
                                         uint8_t section,
                                         Erc7730ProgramSection* result);
void erc7730_program_abi_begin(Erc7730ProgramAbi* abi, uint32_t section_length);
bool erc7730_program_abi_feed(Erc7730ProgramAbi* abi, uint32_t section_offset,
                              const uint8_t* data, size_t data_len);
bool erc7730_program_abi_complete(const Erc7730ProgramAbi* abi,
                                  Erc7730AbiProgram* program);
void erc7730_program_loader_begin(Erc7730ProgramLoader* loader,
                                  uint32_t program_length);
bool erc7730_program_loader_feed(Erc7730ProgramLoader* loader,
                                 uint32_t program_offset, const uint8_t* data,
                                 size_t data_len);
/* Typed data: loader_complete() fails unless a signed deployment equals
 * (chain_id, contract) exactly. Call after begin(), before the first feed. */
bool erc7730_program_loader_require_deployment(Erc7730ProgramLoader* loader,
                                               uint64_t chain_id,
                                               const uint8_t contract[20]);
bool erc7730_program_loader_complete(const Erc7730ProgramLoader* loader,
                                     Erc7730AbiProgram* program);
void erc7730_program_loader_clear(Erc7730ProgramLoader* loader);
void erc7730_program_path_begin(Erc7730ProgramPath* path,
                                uint32_t section_length, uint16_t target_index);
bool erc7730_program_path_feed(Erc7730ProgramPath* path,
                               uint32_t section_offset, const uint8_t* data,
                               size_t data_len);
bool erc7730_program_path_complete(const Erc7730ProgramPath* path,
                                   Erc7730Path* result);
void erc7730_program_string_begin(Erc7730ProgramString* string,
                                  uint32_t section_length,
                                  uint16_t target_index);
bool erc7730_program_string_feed(Erc7730ProgramString* string,
                                 uint32_t section_offset, const uint8_t* data,
                                 size_t data_len);
bool erc7730_program_string_complete(const Erc7730ProgramString* string,
                                     const char** value, size_t* value_len);
void erc7730_program_display_begin(Erc7730ProgramDisplay* display,
                                   uint32_t section_length,
                                   uint16_t target_index);
bool erc7730_program_display_feed(Erc7730ProgramDisplay* display,
                                  uint32_t section_offset, const uint8_t* data,
                                  size_t data_len);
bool erc7730_program_display_complete(const Erc7730ProgramDisplay* display,
                                      Erc7730DisplayInstruction* instruction,
                                      uint16_t* instruction_count);
void erc7730_program_formatter_begin(Erc7730ProgramFormatter* formatter,
                                     uint32_t section_length,
                                     uint16_t target_index);
bool erc7730_program_formatter_feed(Erc7730ProgramFormatter* formatter,
                                    uint32_t section_offset,
                                    const uint8_t* data, size_t data_len);
bool erc7730_program_formatter_complete(
    const Erc7730ProgramFormatter* formatter, Erc7730Formatter* result);
void erc7730_program_literal_begin(Erc7730ProgramLiteral* literal,
                                   uint32_t section_length,
                                   uint16_t target_index);
bool erc7730_program_literal_feed(Erc7730ProgramLiteral* literal,
                                  uint32_t section_offset, const uint8_t* data,
                                  size_t data_len);
bool erc7730_program_literal_complete(const Erc7730ProgramLiteral* literal,
                                      Erc7730Literal* result);

#endif
