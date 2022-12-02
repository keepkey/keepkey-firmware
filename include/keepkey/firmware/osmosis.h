#ifndef KEEPKEY_FIRMWARE_OSMOSIS_H
#define KEEPKEY_FIRMWARE_OSMOSIS_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _OsmosisSignTx OsmosisSignTx;
typedef struct _OsmosisMsgLPAdd OsmosisMsgLPAdd;
typedef struct _OsmosisMsgLPRemove OsmosisMsgLPRemove;
typedef struct _OsmosisMsgLPStake OsmosisMsgLPStake;
typedef struct _OsmosisMsgLPUnstake OsmosisMsgLPUnstake;
typedef struct _OsmosisMsgSwap OsmosisMsgSwap;

bool osmosis_signTxInit(const HDNode *_node, const OsmosisSignTx *_msg);

bool osmosis_signTxUpdateMsgLPAdd(const OsmosisMsgLPAdd msglpadd);

bool osmosis_signTxUpdateMsgLPRemove(const OsmosisMsgLPRemove msglpremove);

bool osmosis_signTxUpdateMsgLPStake(const OsmosisMsgLPStake msgstake);

bool osmosis_signTxUpdateMsgLPUnstake(const OsmosisMsgLPUnstake msgunstake);

bool osmosis_signTxUpdateMsgSwap(const OsmosisMsgSwap msgswap);

bool osmosis_signTxUpdateMsgSend(const uint64_t amount, const char *to_address,
                                 const char *denom);

bool osmosis_signTxUpdateMsgDelegate(const uint64_t amount,
                                     const char *delegator_address,
                                     const char *validator_address,
                                     const char *denom);

bool osmosis_signTxUpdateMsgUndelegate(const uint64_t amount,
                                       const char *delegator_address,
                                       const char *validator_address,
                                       const char *denom);

bool osmosis_signTxUpdateMsgRedelegate(const uint64_t amount,
                                       const char *delegator_address,
                                       const char *validator_src_address,
                                       const char *validator_dst_address,
                                       const char *denom);

bool osmosis_signTxUpdateMsgRewards(const uint64_t *amount,
                                    const char *delegator_address,
                                    const char *validator_address,
                                    const char *denom);
bool osmosis_signTxUpdateMsgIBCTransfer(
    const uint64_t amount, const char *sender, const char *receiver,
    const char *source_channel, const char *source_port,
    const char *revision_number, const char *revision_height,
    const char *denom);
bool osmosis_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool osmosis_signingIsInited(void);
bool osmosis_signingIsFinished(void);
void osmosis_signAbort(void);
const OsmosisSignTx *osmosis_getOsmosisSignTx(void);

#endif
