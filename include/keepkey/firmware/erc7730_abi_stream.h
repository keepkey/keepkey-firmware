#ifndef KEEPKEY_FIRMWARE_ERC7730_ABI_STREAM_H
#define KEEPKEY_FIRMWARE_ERC7730_ABI_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_abi.h"

#define ERC7730_ABI_STREAM_MAX_PENDING ERC7730_ABI_MAX_ARRAY_ELEMENTS
#define ERC7730_ABI_CAPTURE_MAX 128u

typedef struct {
  uint16_t node;
  uint32_t declared_offset;
  uint8_t path_depth;
  bool target_prefix;
} Erc7730AbiPending;

typedef struct {
  uint16_t node;
  uint16_t first_child;
  uint16_t child_count;
  uint16_t item_index;
  uint16_t pending_start;
  uint16_t pending_count;
  uint16_t pending_index;
  uint32_t base;
  uint32_t payload_remaining;
  uint8_t mode;
  uint8_t utf8_remaining;
  uint8_t utf8_lower;
  uint8_t utf8_upper;
  uint8_t path_depth;
  bool repeated;
  bool target_prefix;
  bool capture;
} Erc7730AbiStreamFrame;

typedef struct {
  uint8_t data[ERC7730_ABI_CAPTURE_MAX];
  uint16_t length;
  uint16_t node;
} Erc7730AbiCapture;

typedef struct {
  const Erc7730AbiProgram* program;
  Erc7730AbiStreamFrame frames[ERC7730_ABI_MAX_DEPTH];
  Erc7730AbiPending pending[ERC7730_ABI_STREAM_MAX_PENDING];
  uint8_t word[32];
  uint32_t total_length;
  uint32_t received;
  uint32_t elements;
  int32_t capture_path[ERC7730_ABI_MAX_PATH];
  Erc7730AbiCapture capture;
  uint16_t pending_used;
  uint8_t depth;
  uint8_t word_received;
  uint8_t capture_path_count;
  bool capture_enabled;
  bool capture_found;
  bool complete;
  bool failed;
} Erc7730AbiStream;

Erc7730AbiResult erc7730_abi_stream_begin(Erc7730AbiStream* stream,
                                          const Erc7730AbiProgram* program,
                                          size_t total_length);
Erc7730AbiResult erc7730_abi_stream_feed(Erc7730AbiStream* stream,
                                         size_t offset, const uint8_t* data,
                                         size_t data_len);
Erc7730AbiResult erc7730_abi_stream_capture_path(Erc7730AbiStream* stream,
                                                 const int32_t* path,
                                                 size_t path_count);
Erc7730AbiResult erc7730_abi_stream_finish(Erc7730AbiStream* stream);
bool erc7730_abi_stream_captured(const Erc7730AbiStream* stream,
                                 Erc7730AbiCapture* capture);
void erc7730_abi_stream_clear(Erc7730AbiStream* stream);

#endif
