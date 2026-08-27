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

// Result of thorchain_parseConfirmMemo(). A memo the device could not parse
// and a refusal at a confirm screen are DIFFERENT outcomes and must never be
// conflated: an unparsed memo means the caller still has to disclose the raw
// bytes itself, while a refusal is a "no" that must abort the signing.
typedef enum {
  // Memo parsed, and every field it contains was confirmed on the device.
  THORCHAIN_MEMO_CONFIRMED = 0,
  // Not recognizable thorchain data; nothing was shown and nothing was
  // confirmed. The caller must disclose the raw memo itself, or refuse.
  THORCHAIN_MEMO_UNPARSED,
  // A confirm screen returned false. On a one-button device that happens only
  // when the host sends Cancel/Initialize, so it is a refusal to sign: the
  // caller must abort, and must never re-ask with a different screen.
  THORCHAIN_MEMO_CANCELLED,
} ThorchainMemoResult;

// Thorchain swap data parse and confirm
//      input:
//          swapStr - candidate thorchain memo bytes; NOT required to be NUL
//                    terminated
//          size - number of bytes at swapStr (must be <= 256)
//      output:
//          see ThorchainMemoResult
ThorchainMemoResult thorchain_parseConfirmMemo(const char* swapStr,
                                               size_t size);

// Pages the COMPLETE raw memo (ASCII as text pages, binary as hex pages) so no
// byte is ever truncated behind confirm()'s body budget. Native THOR/MAYA
// deposit/send handlers call this as the authoritative disclosure after their
// best-effort structured summary, so a field the structured view omits (or a
// long field that would truncate) can never be signed unseen. Returns false if
// the user rejects any page. Shared by the MAYA path (same memo grammar).
bool thorchain_confirm_full_memo(const char* title, const char* memo,
                                 size_t len);

#endif
