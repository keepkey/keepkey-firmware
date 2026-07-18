#ifndef KEEPKEY_FIRMWARE_THORCHAIN_H
#define KEEPKEY_FIRMWARE_THORCHAIN_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _ThorchainSignTx ThorchainSignTx;
typedef struct _ThorchainMsgDeposit ThorchainMsgDeposit;

// Returns true iff denom contains only chars safe in JSON without escaping.
// Valid: [a-z0-9./\-]. Rejects empty string, quotes, backslashes, whitespace.
bool thorchain_isValidDenom(const char* denom);

// Deposit asset grammar: as above but uppercase alpha also allowed.
bool thorchain_isValidAsset(const char* asset);
// Deposit signer must be bech32 with the active network's HRP.
bool thorchain_isValidSigner(const char* signer);

bool thorchain_signTxInit(const HDNode* _node, const ThorchainSignTx* _msg);
bool thorchain_signTxUpdateMsgSend(const uint64_t amount,
                                   const char* to_address, const char* denom);
bool thorchain_signTxUpdateMsgDeposit(const ThorchainMsgDeposit* depmsg);
bool thorchain_signTxFinalize(uint8_t* public_key, uint8_t* signature);
bool thorchain_signingIsInited(void);
bool thorchain_signingIsFinished(void);
void thorchain_signAbort(void);
const ThorchainSignTx* thorchain_getThorchainSignTx(void);

// Thorchain swap data parse and confirm
//      input:
//          swapStr - string in thorchain swap format
//          size - size of input string (must be <= 256)
//      output:
//          true if thorchain data parsed and confirmed by user, false otherwise
bool thorchain_parseConfirmMemo(const char* swapStr, size_t size);

// Pages the COMPLETE raw memo (ASCII as text pages, binary as hex pages) so no
// byte is ever truncated behind confirm()'s body budget. Native THOR/MAYA
// deposit/send handlers call this as the authoritative disclosure after their
// best-effort structured summary, so a field the structured view omits (or a
// long field that would truncate) can never be signed unseen. Returns false if
// the user rejects any page. Shared by the MAYA path (same memo grammar).
bool thorchain_confirm_full_memo(const char* title, const char* memo,
                                 size_t len);

#endif
