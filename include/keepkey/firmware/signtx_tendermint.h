#ifndef KEEPKEY_FIRMWARE_SIGNTXTENDERMINT_H
#define KEEPKEY_FIRMWARE_SIGNTXTENDERMINT_H

#include "messages.pb.h"
#include "hwcrypto/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _TendermintSignTx TendermintSignTx;

bool tendermint_signTxInit(const HDNode *_node, const void *_msg,
                           const size_t msgsize, const char *denom);
bool tendermint_signTxUpdateMsgSend(const uint64_t amount,
                                    const char *to_address,
                                    const char *chainstr, const char *denom,
                                    const char *msgTypePrefix);
bool tendermint_signTxUpdateMsgDelegate(const uint64_t amount,
                                        const char *delegator_address,
                                        const char *validator_address,
                                        const char *chainstr, const char *denom,
                                        const char *msgTypePrefix);
bool tendermint_signTxUpdateMsgUndelegate(const uint64_t amount,
                                          const char *delegator_address,
                                          const char *validator_address,
                                          const char *chainstr,
                                          const char *denom,
                                          const char *msgTypePrefix);
bool tendermint_signTxUpdateMsgRedelegate(
    const uint64_t amount, const char *delegator_address,
    const char *validator_src_address, const char *validator_dst_address,
    const char *chainstr, const char *denom, const char *msgTypePrefix);
bool tendermint_signTxUpdateMsgRewards(const uint64_t *amount,
                                       const char *delegator_address,
                                       const char *validator_address,
                                       const char *chainstr, const char *denom,
                                       const char *msgTypePrefix);
bool tendermint_signTxUpdateMsgIBCTransfer(
    const uint64_t amount, const char *sender, const char *receiver,
    const char *source_channel, const char *source_port,
    const char *revision_number, const char *revision_height,
    const char *chainstr, const char *denom, const char *msgTypePrefix);
bool tendermint_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool tendermint_signingIsInited(void);
bool tendermint_signingIsFinished(void);
void tendermint_signAbort(void);
const void *tendermint_getSignTx(void);

#endif