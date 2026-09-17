#ifndef KEEPKEY_FIRMWARE_ERC7730_ABI_H
#define KEEPKEY_FIRMWARE_ERC7730_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Resource limits are part of the compiled-descriptor ABI. Raising one is a
 * protocol and firmware review decision, not a host-controlled parameter. */
#define ERC7730_ABI_MAX_NODES 64
#define ERC7730_ABI_MAX_DEPTH 8
#define ERC7730_ABI_MAX_ARRAY_ELEMENTS 64
#define ERC7730_ABI_MAX_PATH 16

#define ERC7730_ABI_DYNAMIC_ARRAY UINT16_MAX

typedef enum {
  ERC7730_ABI_UINT = 1,
  ERC7730_ABI_INT = 2,
  ERC7730_ABI_ADDRESS = 3,
  ERC7730_ABI_BOOL = 4,
  ERC7730_ABI_FIXED_BYTES = 5,
  ERC7730_ABI_BYTES = 6,
  ERC7730_ABI_STRING = 7,
  ERC7730_ABI_TUPLE = 8,
  ERC7730_ABI_ARRAY = 9,
} Erc7730AbiKind;

/* A flat, forward-only type graph. Tuple children occupy
 * [first_child, first_child + child_count). Arrays have exactly one child.
 * Forward-only edges make cycles impossible and allow validation without a
 * visited bitmap or dynamic allocation. */
typedef struct {
  uint8_t kind;
  uint16_t size; /* int width in bits, fixed-bytes width in bytes */
  uint16_t first_child;
  uint16_t child_count;
  uint16_t array_length; /* UINT16_MAX means dynamic */
} Erc7730AbiNode;

typedef struct {
  const Erc7730AbiNode* nodes;
  uint16_t node_count;
  uint16_t root;
} Erc7730AbiProgram;

typedef struct {
  const uint8_t* data;
  size_t data_len;
  uint16_t node;
  size_t encoded_offset;
  size_t encoded_length;
} Erc7730AbiValue;

typedef enum {
  ERC7730_ABI_OK = 0,
  ERC7730_ABI_BAD_PROGRAM,
  ERC7730_ABI_BOUNDS,
  ERC7730_ABI_NON_CANONICAL,
  ERC7730_ABI_RESOURCE_LIMIT,
  ERC7730_ABI_BAD_PATH,
} Erc7730AbiResult;

Erc7730AbiResult erc7730_abi_validate_program(const Erc7730AbiProgram* p);

/* Validate a complete ABI argument block (calldata excluding its selector).
 * Success proves that exactly data_len bytes are represented by the root. */
Erc7730AbiResult erc7730_abi_validate(const Erc7730AbiProgram* program,
                                      const uint8_t* data, size_t data_len);

/* Resolve tuple fields and array elements. Negative array indices count from
 * the end. The returned view always points into the already validated input;
 * dynamic bytes/string views contain payload bytes, while other values contain
 * their canonical ABI encoding. */
Erc7730AbiResult erc7730_abi_resolve(const Erc7730AbiProgram* program,
                                     const uint8_t* data, size_t data_len,
                                     const int32_t* path, size_t path_len,
                                     Erc7730AbiValue* out);

#endif
