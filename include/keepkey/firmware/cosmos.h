#ifndef __COSMOS_H__
#define __COSMOS_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto.h"
#include "fsm.h"
#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

bool cosmos_path_mismatched(const CoinType *_coin,
                            const uint32_t *address_n,
                            const uint32_t address_n_count);
bool cosmos_getAddress(const HDNode *node, char *address);
bool cosmos_signTxInit(const HDNode* _node,
                       const uint32_t _address_n[8],
                       const size_t _address_n_count,
                       const uint64_t account_number,
                       const char *chain_id,
                       const size_t chain_id_length,
                       const uint32_t fee_uatom_amount,
                       const uint32_t gas,
                       const char *memo,
                       const size_t memo_length,
                       const uint64_t _sequence,
                       const uint32_t msg_count);
bool cosmos_signTxUpdateMsgSend(const uint64_t amount,
                                const char *from_address,
                                const char *to_address);
bool cosmos_signTxFinalize(uint8_t* public_key, uint8_t* signature);
bool cosmos_signingIsInited();
bool cosmos_signingIsFinished();
void cosmos_signAbort(void);
size_t cosmos_getAddressNCount();
bool cosmos_getAddressN(uint32_t* address_n, size_t address_n_count);
// bool cosmos_signTx(const uint8_t* private_key,
//                    const uint64_t account_number,
//                    const char* chain_id,
//                    const size_t chain_id_length,
//                    const uint32_t fee_uatom_amount,
//                    const uint32_t gas,
//                    const char* memo,
//                    const size_t memo_length,
//                    const uint64_t amount,
//                    const char* from_address,
//                    const char* to_address,
//                    const uint64_t sequence,
//                    uint8_t* signature);

#endif