#ifndef KEEPKEY_FIRMWARE_THORCHAIN_H
#define KEEPKEY_FIRMWARE_THORCHAIN_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _ThorChainSignTx ThorChainSignTx;

bool thorchain_signTxInit(const HDNode *_node, const ThorChainSignTx *_msg);
bool thorchain_signTxUpdateMsgSend(const uint64_t amount, const char *to_address);
bool thorchain_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool thorchain_signingIsInited(void);
bool thorchain_signingIsFinished(void);
void thorchain_signAbort(void);
const ThorChainSignTx *thorchain_getThorChainSignTx(void);

#endif
