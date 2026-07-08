#ifndef KEEPKEY_FIRMWARE_MAYACHAIN_H
#define KEEPKEY_FIRMWARE_MAYACHAIN_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _MayachainSignTx MayachainSignTx;
typedef struct _MayachainMsgDeposit MayachainMsgDeposit;

// Returns true iff `denom` is a plausible MAYAChain denom: non-empty,
// and contains only lowercase alpha, digits, '.', '/', or '-'.
bool mayachain_isValidDenom(const char* denom);

// Deposit asset grammar: as above but uppercase alpha also allowed.
bool mayachain_isValidAsset(const char* asset);
// Deposit signer must be bech32 with the active network's HRP.
bool mayachain_isValidSigner(const char* signer);

bool mayachain_signTxInit(const HDNode* _node, const MayachainSignTx* _msg);
bool mayachain_signTxUpdateMsgSend(const uint64_t amount,
                                   const char* to_address, const char* denom);
bool mayachain_signTxUpdateMsgDeposit(const MayachainMsgDeposit* depmsg);
bool mayachain_signTxFinalize(uint8_t* public_key, uint8_t* signature);
bool mayachain_signingIsInited(void);
bool mayachain_signingIsFinished(void);
void mayachain_signAbort(void);
const MayachainSignTx* mayachain_getMayachainSignTx(void);

// Mayachain swap data parse and confirm
//      input:
//          swapStr - string in mayachain swap format
//          size - size of input string (must be <= 256)
//      output:
//          true if mayachain data parsed and confirmed by user, false otherwise
bool mayachain_parseConfirmMemo(const char* swapStr, size_t size);

#endif
