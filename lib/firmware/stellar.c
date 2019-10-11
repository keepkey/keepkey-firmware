#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "trezor/crypto/stellar.h"

bool stellar_get_address(uint8_t* pubkey, uint32_t version_byte, char* address, size_t size) {
    if (version_byte > 255) {
        return false;
    }
    if (size < 57) { // 56 characters, 1 null termination byte
        return false;
    }
    uint8_t vb8 = (uint8_t)version_byte;

    uint8_t keylen = 35
    uint8_t bytes_full[keylen];
    bytes_full[0] = 6 << 3;  // 'G'
    memcpy(bytes_full + 1, pubkey, 32);

    uint16_t checksum = stellar_crc16(bytes_full, 33);
    bytes_full[keylen - 2] = checksum & 0x00ff;
    bytes_full[keylen - 1] = (checksum >> 8) & 0x00ff;
    base32_encode(bytes_full, keylen, address, size, BASE32_ALPHABET_RFC4648);

    return true;
}