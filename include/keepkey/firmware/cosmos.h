#ifndef KEEPKEY_FIRMWARE_COSMOS_H
#define KEEPKEY_FIRMWARE_COSMOS_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _CosmosSignTx CosmosSignTx;

bool cosmos_path_mismatched(const CoinType *_coin,
                            const uint32_t *_address_n,
                            const uint32_t _address_n_count);
bool cosmos_getAddress(const HDNode *_node, char *address);
bool cosmos_signTxInit(const HDNode *_node, const CosmosSignTx *_msg);
bool cosmos_signTxUpdateMsgSend(const uint64_t amount,
                                const char *to_address);
bool cosmos_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool cosmos_signingIsInited(void);
bool cosmos_signingIsFinished(void);
void cosmos_signAbort(void);
const CosmosSignTx *cosmos_getCosmosSignTx(void);

#endif