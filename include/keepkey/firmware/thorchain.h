#ifndef KEEPKEY_FIRMWARE_THORCHAIN_H
#define KEEPKEY_FIRMWARE_THORCHAIN_H

#include "messages.pb.h"
#include "hwcrypto/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _ThorchainSignTx ThorchainSignTx;
typedef struct _ThorchainMsgDeposit ThorchainMsgDeposit;

bool thorchain_signTxInit(const HDNode *_node, const ThorchainSignTx *_msg);
bool thorchain_signTxUpdateMsgSend(const uint64_t amount, const char *to_address);
bool thorchain_signTxUpdateMsgDeposit(const ThorchainMsgDeposit *depmsg);
bool thorchain_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool thorchain_signingIsInited(void);
bool thorchain_signingIsFinished(void);
void thorchain_signAbort(void);
const ThorchainSignTx *thorchain_getThorchainSignTx(void);

// Thorchain swap data parse and confirm
//      input: 
//          swapStr - string in thorchain swap format
//          size - size of input string (must be <= 256)
//      output:
//          true if thorchain data parsed and confirmed by user, false otherwise
bool thorchain_parseConfirmMemo(const char *swapStr, size_t size);

#endif
