#ifndef __KK_STELLAR_H
#define __KK_STELLAR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_STELLAR_ADDR_SIZE 56

bool stellar_get_address(uint8_t* pubkey, uint32_t version_byte, char* address, size_t size);

#endif