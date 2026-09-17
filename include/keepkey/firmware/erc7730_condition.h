#ifndef KEEPKEY_FIRMWARE_ERC7730_CONDITION_H
#define KEEPKEY_FIRMWARE_ERC7730_CONDITION_H

#include <stdbool.h>

#include "keepkey/firmware/erc7730_abi_stream.h"
#include "keepkey/firmware/erc7730_program.h"

/* Evaluate conditions that depend only on presence/emptiness. Membership and
 * must-match use signed literal-set replay and are handled separately. */
bool erc7730_condition_evaluate_basic(const Erc7730Condition* condition,
                                      const Erc7730AbiProgram* program,
                                      const Erc7730AbiCapture* capture,
                                      bool* visible);

bool erc7730_capture_equals_literal(const Erc7730AbiProgram* program,
                                    const Erc7730AbiCapture* capture,
                                    const Erc7730Literal* literal);
bool erc7730_literal_set_count(const Erc7730Literal* set, uint16_t* count);
bool erc7730_literal_set_index(const Erc7730Literal* set, uint16_t position,
                               uint16_t* literal_index);
bool erc7730_enum_map_count(const Erc7730Literal* map, uint16_t* count);
bool erc7730_enum_map_index(const Erc7730Literal* map, uint16_t position,
                            uint16_t* key_literal, uint16_t* value_string);

#endif
