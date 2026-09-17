#ifndef KEEPKEY_FIRMWARE_ERC7730_ABI_STREAM_H
#define KEEPKEY_FIRMWARE_ERC7730_ABI_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_abi.h"

#define ERC7730_ABI_STREAM_MAX_PENDING ERC7730_ABI_MAX_ARRAY_ELEMENTS

typedef struct {
  uint16_t node;
  size_t declared_offset;
} Erc7730AbiPending;

typedef struct {
  uint16_t node;
  uint16_t first_child;
  uint16_t child_count;
  uint16_t item_index;
  uint16_t pending_start;
  uint16_t pending_count;
  uint16_t pending_index;
  size_t base;
  size_t payload_remaining;
  uint8_t mode;
  uint8_t utf8_remaining;
  uint8_t utf8_lower;
  uint8_t utf8_upper;
  bool repeated;
} Erc7730AbiStreamFrame;

typedef struct {
  const Erc7730AbiProgram* program;
  Erc7730AbiStreamFrame frames[ERC7730_ABI_MAX_DEPTH];
  Erc7730AbiPending pending[ERC7730_ABI_STREAM_MAX_PENDING];
  uint8_t word[32];
  size_t total_length;
  size_t received;
  uint32_t elements;
  uint16_t pending_used;
  uint8_t depth;
  uint8_t word_received;
  bool complete;
  bool failed;
} Erc7730AbiStream;

Erc7730AbiResult erc7730_abi_stream_begin(Erc7730AbiStream* stream,
                                          const Erc7730AbiProgram* program,
                                          size_t total_length);
Erc7730AbiResult erc7730_abi_stream_feed(Erc7730AbiStream* stream,
                                         size_t offset, const uint8_t* data,
                                         size_t data_len);
Erc7730AbiResult erc7730_abi_stream_finish(Erc7730AbiStream* stream);
void erc7730_abi_stream_clear(Erc7730AbiStream* stream);

#endif
