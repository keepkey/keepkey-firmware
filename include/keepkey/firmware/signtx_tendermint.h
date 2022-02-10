#ifndef KEEPKEY_FIRMWARE_SIGNTXTENDERMINT_H
#define KEEPKEY_FIRMWARE_SIGNTXTENDERMINT_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _TendermintSignTx TendermintSignTx;

bool tendermint_signTxInit(const HDNode *_node, const void *_msg, const size_t msgsize, const char *denom);
bool tendermint_signTxUpdateMsgSend(const uint64_t amount, const char *to_address, const char *chainstr, const char *denom, const char *msgTypePrefix);
bool tendermint_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool tendermint_signingIsInited(void);
bool tendermint_signingIsFinished(void);
void tendermint_signAbort(void);
const void *tendermint_getSignTx(void);

#endif
