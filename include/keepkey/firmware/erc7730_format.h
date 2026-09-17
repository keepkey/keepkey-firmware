#ifndef KEEPKEY_FIRMWARE_ERC7730_FORMAT_H
#define KEEPKEY_FIRMWARE_ERC7730_FORMAT_H

#include <stdbool.h>
#include <stddef.h>

#include "keepkey/firmware/erc7730_abi_stream.h"

#define ERC7730_FORMATTED_VALUE_MAX (2u + 2u * ERC7730_ABI_CAPTURE_MAX)

bool erc7730_format_raw(const Erc7730AbiProgram* program,
                        const Erc7730AbiCapture* capture, char* output,
                        size_t output_size);
bool erc7730_format_amount(const Erc7730AbiProgram* program,
                           const Erc7730AbiCapture* capture, uint8_t decimals,
                           const char* ticker, char* output,
                           size_t output_size);
bool erc7730_format_duration(const Erc7730AbiProgram* program,
                             const Erc7730AbiCapture* capture, char* output,
                             size_t output_size);
bool erc7730_format_timestamp(const Erc7730AbiProgram* program,
                              const Erc7730AbiCapture* capture, char* output,
                              size_t output_size);

#endif
