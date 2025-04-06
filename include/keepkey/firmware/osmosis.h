#ifndef KEEPKEY_FIRMWARE_OSMOSIS_H
#define KEEPKEY_FIRMWARE_OSMOSIS_H

#include "messages.pb.h"
#include "hwcrypto/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _OsmosisSignTx OsmosisSignTx;
typedef struct _OsmosisMsgLPAdd OsmosisMsgLPAdd;
typedef struct _OsmosisMsgLPRemove OsmosisMsgLPRemove;
typedef struct _OsmosisMsgSwap OsmosisMsgSwap;

void debug_intermediate_hash(void);

bool osmosis_signTxInit(const HDNode *_node, const OsmosisSignTx *_msg);

bool osmosis_signTxUpdateMsgSend(const char *amount, const char *to_address);

bool osmosis_signTxUpdateMsgDelegate(const char *amount,
                                     const char *delegator_address,
                                     const char *validator_address,
                                     const char *denom);

bool osmosis_signTxUpdateMsgUndelegate(const char *amount,
                                       const char *delegator_address,
                                       const char *validator_address,
                                       const char *denom);

bool osmosis_signTxUpdateMsgRedelegate(const char *amount,
                                       const char *delegator_address,
                                       const char *validator_src_address,
                                       const char *validator_dst_address,
                                       const char *denom);

bool osmosis_signTxUpdateMsgLPAdd(const uint64_t pool_id, const char *sender,
                                  const char *share_out_amount,
                                  const char *amount_in_max_a,
                                  const char *denom_in_max_a,
                                  const char *amount_in_max_b,
                                  const char *denom_in_max_b);

bool osmosis_signTxUpdateMsgLPRemove(const uint64_t pool_id, const char *sender,
                                     const char *share_out_amount,
                                     const char *amount_out_min_a,
                                     const char *denom_out_min_a,
                                     const char *amount_out_min_b,
                                     const char *denom_out_min_b);

bool osmosis_signTxUpdateMsgRewards(const char *delegator_address,
                                    const char *validator_address);

bool osmosis_signTxUpdateMsgIBCTransfer(const char *amount, const char *sender,
                                        const char *receiver,
                                        const char *source_channel,
                                        const char *source_port,
                                        const char *revision_number,
                                        const char *revision_height,
                                        const char *denom);

bool osmosis_signTxUpdateMsgSwap(const uint64_t pool_id,
                                 const char *token_out_denom,
                                 const char *sender,
                                 const char *token_in_amount,
                                 const char *token_in_denom,
                                 const char *token_out_min_amount);

bool osmosis_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool osmosis_signingIsInited(void);
bool osmosis_signingIsFinished(void);
void osmosis_signAbort(void);
const OsmosisSignTx *osmosis_getOsmosisSignTx(void);

#endif
