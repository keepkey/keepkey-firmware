#include "keepkey/firmware/erc7730_tx.h"

#include "trezor/crypto/memzero.h"
#include "pb_decode.h"
#include "pb_encode.h"

bool erc7730_tx_continuation_capture(Erc7730TxContinuation* continuation,
                                     const EthereumSignTx* tx) {
  if (!continuation || !tx) return false;
  memzero(continuation, sizeof(*continuation));
  if (!tx->has_data_length || tx->data_length < 4 ||
      !tx->has_data_initial_chunk || tx->data_initial_chunk.size != 4) {
    return false;
  }

  pb_ostream_t stream = pb_ostream_from_buffer(continuation->encoded,
                                               sizeof(continuation->encoded));
  if (!pb_encode(&stream, EthereumSignTx_fields, tx)) {
    memzero(continuation, sizeof(*continuation));
    return false;
  }
  continuation->length = stream.bytes_written;
  return continuation->length != 0;
}

bool erc7730_tx_continuation_restore(const Erc7730TxContinuation* continuation,
                                     EthereumSignTx* tx) {
  if (!continuation || !tx || continuation->length == 0 ||
      continuation->length > sizeof(continuation->encoded)) {
    return false;
  }
  memzero(tx, sizeof(*tx));
  pb_istream_t stream =
      pb_istream_from_buffer(continuation->encoded, continuation->length);
  if (!pb_decode(&stream, EthereumSignTx_fields, tx) ||
      stream.bytes_left != 0 || !tx->has_data_initial_chunk ||
      tx->data_initial_chunk.size != 4) {
    memzero(tx, sizeof(*tx));
    return false;
  }
  return true;
}

void erc7730_tx_continuation_clear(Erc7730TxContinuation* continuation) {
  if (continuation) memzero(continuation, sizeof(*continuation));
}
