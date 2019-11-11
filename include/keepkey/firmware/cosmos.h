#ifndef __COSMOS_H__
#define __COSMOS_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto.h"
#include "fsm.h"
#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

bool cosmos_getAddress(const uint8_t *public_key, char *address);
bool cosmos_signTx(const uint8_t* private_key,
                   const uint64_t account_number,
                   const char* chain_id,
                   const size_t chain_id_length,
                   const uint32_t fee_uatom_amount,
                   const uint32_t gas,
                   const char* memo,
                   const size_t memo_length,
                   const uint64_t amount,
                   const char* from_address,
                   const char* to_address,
                   const uint64_t sequence,
                   uint8_t* signature);

#endif