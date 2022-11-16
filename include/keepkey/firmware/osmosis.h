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

bool osmosis_signTxUpdateMsgLPAdd(const OsmosisMsgLPAdd msglpadd);

bool osmosis_signTxUpdateMsgLPRemove(const OsmosisMsgLPRemove msglpremove);

bool osmosis_signTxUpdateMsgLPStake(const OsmosisMsgLPStake msgstake);

bool osmosis_signTxUpdateMsgLPUnstake(const OsmosisMsgLPUnstake msgunstake);

bool osmosis_signTxUpdateMsgSwap(const OsmosisMsgSwap msgswap);

#endif
