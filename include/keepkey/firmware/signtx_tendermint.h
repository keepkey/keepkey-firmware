#ifndef KEEPKEY_FIRMWARE_SIGNTXTENDERMINT_H
#define KEEPKEY_FIRMWARE_SIGNTXTENDERMINT_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

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
bool tendermint_signTxUpdateMsgLPAdd(
    const char *sender, const char *pool_id, const uint64_t share_out_amount,
    const char *denom_in_max_a, const uint64_t amount_in_max_a,
    const char *denom_in_max_b, const uint64_t amount_in_max_b,
    const char *chainstr, const char *denom, const char *msgTypePrefix);
bool tendermint_signTxUpdateMsgLPRemove(
    const char *sender, const char *pool_id, const uint64_t share_out_amount,
    const char *denom_out_min_a, const uint64_t amount_out_min_a,
    const char *denom_out_min_b, const uint64_t amount_out_min_b,
    const char *chainstr, const char *denom, const char *msgTypePrefix);
bool tendermint_signTxUpdateMsgLPStake(const char *owner,
                                       const uint64_t duration,
                                       const uint64_t amount,
                                       const char *chainstr, const char *denom,
                                       const char *msgTypePrefix);
bool tendermint_signTxUpdateMsgLPUnstake(const char *owner, const char *id,
                                         const char *chainstr,
                                         const char *denom,
                                         const char *msgTypePrefix);
bool tendermint_signTxUpdateMsgIBCTransfer(
    const uint64_t amount, const char *sender, const char *receiver,
    const char *source_channel, const char *source_port,
    const char *revision_number, const char *revision_height,
    const char *chainstr, const char *denom, const char *msgTypePrefix);
bool tendermint_signTxUpdateMsgSwap(const char *sender, const char *pool_id,
                                    const char *token_out_denom,
                                    const char *token_in_denom,
                                    const uint64_t token_in_amount,
                                    const uint64_t token_out_min_amount,
                                    const char *chainstr, const char *denom,
                                    const char *msgTypePrefix);
bool tendermint_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool tendermint_signingIsInited(void);
bool tendermint_signingIsFinished(void);
void tendermint_signAbort(void);
const void *tendermint_getSignTx(void);

#endif
