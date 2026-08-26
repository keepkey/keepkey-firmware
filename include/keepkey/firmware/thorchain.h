#ifndef KEEPKEY_FIRMWARE_THORCHAIN_H
#define KEEPKEY_FIRMWARE_THORCHAIN_H

#include "messages.pb.h"
#include "trezor/crypto/bip32.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Suffix width for the deposit confirmation screen, from
 * include/keepkey/transport/messages-thorchain.options:
 * ThorchainMsgDeposit.asset max_size:20 -> 19 visible chars, plus the leading
 * space. Named so the "<amount> <asset>" buffer is sized from the protocol
 * maximum -- bn_format() zeroes its output and returns 0 if it does not fit. */
#define THORCHAIN_ASSET_SUFFIX_LEN 20

typedef struct _ThorchainSignTx ThorchainSignTx;
typedef struct _ThorchainMsgDeposit ThorchainMsgDeposit;

bool thorchain_signTxInit(const HDNode* _node, const ThorchainSignTx* _msg);
bool thorchain_signTxUpdateMsgSend(const uint64_t amount,
                                   const char* to_address);
bool thorchain_signTxUpdateMsgDeposit(const ThorchainMsgDeposit* depmsg);
bool thorchain_signTxFinalize(uint8_t* public_key, uint8_t* signature);
bool thorchain_signingIsInited(void);
bool thorchain_signingIsFinished(void);
void thorchain_signAbort(void);
const ThorchainSignTx* thorchain_getThorchainSignTx(void);

/* Format exactly the amount text used by both THORChain confirmation paths.
 * Returns false instead of allowing bn_format_uint64() to leave a blank
 * confirmation when the caller's buffer cannot hold the protocol maximum. */
bool thorchain_formatAmount(uint64_t amount, const char* asset, char* out,
                            size_t out_len);

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

#endif
