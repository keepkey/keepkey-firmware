#ifndef __KK_STELLAR_H
#define __KK_STELLAR_H

#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_STELLAR_ADDR_SIZE 56

bool stellar_get_address(const uint8_t* pubkey, const uint32_t version_byte, char* address, const size_t size);

#endif