#ifndef KEEPKEY_FIRMWARE_ERC7730_TX_H
#define KEEPKEY_FIRMWARE_ERC7730_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "messages-ethereum.pb.h"

#define ERC7730_TX_CONTINUATION_MAX 512u

typedef struct {
  size_t length;
  uint8_t encoded[ERC7730_TX_CONTINUATION_MAX];
} Erc7730TxContinuation;

/* Active calldata clear signing starts with exactly the selector. Remaining
 * calldata is requested through the ordinary EthereumTxAck stream after the
 * signed definition replay completes. */
bool erc7730_tx_continuation_capture(Erc7730TxContinuation* continuation,
                                     const EthereumSignTx* tx);
bool erc7730_tx_continuation_restore(const Erc7730TxContinuation* continuation,
                                     EthereumSignTx* tx);
void erc7730_tx_continuation_clear(Erc7730TxContinuation* continuation);

#endif
