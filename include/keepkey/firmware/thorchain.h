#ifndef KEEPKEY_FIRMWARE_THORCHAIN_H
#define KEEPKEY_FIRMWARE_THORCHAIN_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _ThorchainSignTx ThorchainSignTx;

bool thorchain_signTxInit(const HDNode *_node, const ThorchainSignTx *_msg);
bool thorchain_signTxUpdateMsgSend(const uint64_t amount, const char *to_address);
bool thorchain_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool thorchain_signingIsInited(void);
bool thorchain_signingIsFinished(void);
void thorchain_signAbort(void);
const ThorchainSignTx *thorchain_getThorchainSignTx(void);

// Thorchain swap data parse and confirm
//      input: 
//          swapStr - Null terminated string in thorchain swap format
//      output:
//          true if confirmed by user
bool thorchain_parseConfirmSwap(const char *swapStr);

#endif
