#ifndef KEEPKEY_FIRMWARE_MAYACHAIN_H
#define KEEPKEY_FIRMWARE_MAYACHAIN_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Suffix widths for the confirmation screens, from
 * include/keepkey/transport/messages-mayachain.options:
 *   MayachainMsgSend.denom     max_size:69 -> 68 visible chars
 *   MayachainMsgDeposit.asset  max_size:20 -> 19 visible chars
 * plus the leading space each is prefixed with. Named here so the buffer that
 * holds "<amount> <denom>" is sized from the protocol maximum rather than a
 * guess -- bn_format() zeroes its output and returns 0 if it does not fit. */
#define MAYACHAIN_DENOM_SUFFIX_LEN 69
#define MAYACHAIN_ASSET_SUFFIX_LEN 20

typedef struct _MayachainSignTx MayachainSignTx;
typedef struct _MayachainMsgDeposit MayachainMsgDeposit;

bool mayachain_signTxInit(const HDNode* _node, const MayachainSignTx* _msg);
bool mayachain_signTxUpdateMsgSend(const uint64_t amount,
                                   const char* to_address, const char* denom);
bool mayachain_signTxUpdateMsgDeposit(const MayachainMsgDeposit* depmsg);
bool mayachain_signTxFinalize(uint8_t* public_key, uint8_t* signature);
bool mayachain_signingIsInited(void);

/// True iff `address` is the account this session's key signs as. Use for
/// MsgDeposit's `signer`, which is serialized verbatim as the authority.
bool mayachain_addressIsSigner(const char* address);
bool mayachain_signingIsFinished(void);
void mayachain_signAbort(void);
const MayachainSignTx* mayachain_getMayachainSignTx(void);

/* Format a signed MAYAChain coin amount without inventing an exponent for a
 * host-controlled denomination. Only cacao is defined here as 10 decimals;
 * every other denomination is shown as its exact base-unit integer. */
bool mayachain_formatAmount(uint64_t amount, const char* denom, char* out,
                            size_t out_len);

// Result of mayachain_parseConfirmMemo(). A memo the device could not parse
// and a refusal at a confirm screen are DIFFERENT outcomes and must never be
// conflated: an unparsed memo means the caller still has to disclose the raw
// bytes itself, while a refusal is a "no" that must abort the signing.
// Mirrors ThorchainMemoResult -- Maya is a fork of that path.
typedef enum {
  // Memo parsed, and every field it contains was confirmed on the device.
  MAYACHAIN_MEMO_CONFIRMED = 0,
  // Not recognizable mayachain data; nothing was shown and nothing was
  // confirmed. The caller must disclose the raw memo itself, or refuse.
  MAYACHAIN_MEMO_UNPARSED,
  // A confirm screen returned false. On a one-button device that happens only
  // when the host sends Cancel/Initialize, so it is a refusal to sign: the
  // caller must abort, and must never re-ask with a different screen.
  MAYACHAIN_MEMO_CANCELLED,
} MayachainMemoResult;

// Mayachain swap data parse and confirm
//      input:
//          swapStr - candidate mayachain memo bytes; NOT required to be NUL
//                    terminated
//          size - number of bytes at swapStr (must be <= 255)
//      output:
//          see MayachainMemoResult
MayachainMemoResult mayachain_parseConfirmMemo(const char* swapStr,
                                               size_t size);

#endif
