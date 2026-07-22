#ifndef KEEPKEY_FIRMWARE_OSMOSIS_H
#define KEEPKEY_FIRMWARE_OSMOSIS_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct _OsmosisSignTx OsmosisSignTx;
typedef struct _OsmosisMsgLPAdd OsmosisMsgLPAdd;
typedef struct _OsmosisMsgLPRemove OsmosisMsgLPRemove;
typedef struct _OsmosisMsgSwap OsmosisMsgSwap;

void debug_intermediate_hash(void);

bool osmosis_signTxInit(const HDNode* _node, const OsmosisSignTx* _msg);

bool osmosis_signTxUpdateMsgSend(const char* amount, const char* to_address,
                                 const char* denom);

bool osmosis_signTxUpdateMsgDelegate(const char* amount,
                                     const char* delegator_address,
                                     const char* validator_address,
                                     const char* denom);

bool osmosis_signTxUpdateMsgUndelegate(const char* amount,
                                       const char* delegator_address,
                                       const char* validator_address,
                                       const char* denom);

bool osmosis_signTxUpdateMsgRedelegate(const char* amount,
                                       const char* delegator_address,
                                       const char* validator_src_address,
                                       const char* validator_dst_address,
                                       const char* denom);

bool osmosis_signTxUpdateMsgLPAdd(const uint64_t pool_id, const char* sender,
                                  const char* share_out_amount,
                                  const char* amount_in_max_a,
                                  const char* denom_in_max_a,
                                  const char* amount_in_max_b,
                                  const char* denom_in_max_b);

bool osmosis_signTxUpdateMsgLPRemove(const uint64_t pool_id, const char* sender,
                                     const char* share_out_amount,
                                     const char* amount_out_min_a,
                                     const char* denom_out_min_a,
                                     const char* amount_out_min_b,
                                     const char* denom_out_min_b);

bool osmosis_signTxUpdateMsgRewards(const char* delegator_address,
                                    const char* validator_address);

bool osmosis_signTxUpdateMsgIBCTransfer(const char* amount, const char* sender,
                                        const char* receiver,
                                        const char* source_channel,
                                        const char* source_port,
                                        const char* revision_number,
                                        const char* revision_height,
                                        const char* denom);

bool osmosis_signTxUpdateMsgSwap(const uint64_t pool_id,
                                 const char* token_out_denom,
                                 const char* sender,
                                 const char* token_in_amount,
                                 const char* token_in_denom,
                                 const char* token_out_min_amount);

#define OSMOSIS_PRECISION 6
#define OSMOSIS_MAX_AMOUNT_DIGITS 32
#define OSMOSIS_MAX_DENOM_LEN 68

// Longest amount a confirm screen renders: the digits, a point, a space and
// the longest denom a message can carry.
#define OSMOSIS_AMOUNT_STR_LEN 103

/**
 * Render an integer base-unit amount for a confirm screen:
 * ("1500000", "uosmo") -> "1.500000 OSMO".
 *
 * Only uosmo is scaled — any other denom is shown exactly as the chain states
 * it, because the device does not know its precision. Returns false unless the
 * amount is a canonical, schema-bounded unsigned decimal and the denomination
 * is a schema-bounded Cosmos asset identifier. Native uosmo additionally must
 * fit uint64, which is the range accepted by the native-asset display policy.
 */
bool osmosis_formatAmount(char* out, size_t out_len, const char* value,
                          const char* denom);

bool osmosis_signTxFinalize(uint8_t* public_key, uint8_t* signature);
bool osmosis_signingIsInited(void);
bool osmosis_signingIsFinished(void);
void osmosis_signAbort(void);
const OsmosisSignTx* osmosis_getOsmosisSignTx(void);

#endif
