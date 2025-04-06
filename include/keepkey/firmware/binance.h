#ifndef KEEPKEY_FIRMWARE_BINANCE_H
#define KEEPKEY_FIRMWARE_BINANCE_H

#include "messages.pb.h"
#include "hwcrypto/crypto/bip32.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _BinanceSignTx BinanceSignTx;
typedef struct _BinanceTransferMsg BinanceTransferMsg;
typedef struct _BinanceTransferMsg_BinanceInputOutput BinanceInputOutput;
typedef struct _BinanceTransferMsg_BinanceCoin BinanceCoin;

bool binance_signTxInit(const HDNode *node, const BinanceSignTx *msg);
bool binance_serializeCoin(const BinanceCoin *coin);
bool binance_serializeInputOutput(const BinanceInputOutput *io);
bool binance_signTxUpdateTransfer(const BinanceTransferMsg *msg);
bool binance_signTxUpdateMsgSend(const uint64_t amount, const char *to_address);
bool binance_signTxFinalize(uint8_t *public_key, uint8_t *signature);
bool binance_signingIsInited(void);
bool binance_signingIsFinished(void);
void binance_signAbort(void);
const BinanceSignTx *binance_getBinanceSignTx(void);

#endif
