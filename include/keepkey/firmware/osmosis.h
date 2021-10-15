#ifndef KEEPKEY_FIRMWARE_OSMOSIS_H
#define KEEPKEY_FIRMWARE_OSMOSIS_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _OsmosisSignTx OsmosisSignTx;
typedef struct _OsmosisMsgDelegate OsmosisMsgDelegate;
typedef struct _OsmosisMsgUndelegate OsmosisMsgUndelegate;
typedef struct _OsmosisMsgClaim OsmosisMsgClaim;

bool osmosis_signTxInit(const HDNode *_node, const OsmosisSignTx *_msg);
bool osmosis_signTxUpdateMsgSend(const uint64_t amount, const char *to_address);
bool osmosis_signTxUpdateMsgDelegate(const OsmosisMsgDelegate *delegatemsg);
bool osmosis_signTxUpdateMsgUndelegate(const OsmosisMsgUndelegate *undelegatemsg);
bool osmosis_signTxUpdateMsgClaim(const OsmosisMsgClaim *claimmsg);
bool osmosis_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool osmosis_signingIsInited(void);
bool osmosis_signingIsFinished(void);
void osmosis_signAbort(void);
const OsmosisSignTx *osmosis_getOsmosisSignTx(void);

#endif
