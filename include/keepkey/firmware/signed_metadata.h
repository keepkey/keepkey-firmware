#ifndef KEEPKEY_FIRMWARE_SIGNED_METADATA_H
#define KEEPKEY_FIRMWARE_SIGNED_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct _EthereumSignTx EthereumSignTx;

#define METADATA_MAX_ARGS 8
#define METADATA_MAX_METHOD_LEN 64
#define METADATA_MAX_ARG_NAME_LEN 32
#define METADATA_MAX_ARG_VALUE_LEN 32
#define METADATA_MAX_KEYS 4

typedef enum {
  METADATA_OPAQUE = 0,
  METADATA_VERIFIED = 1,
  METADATA_MALFORMED = 2,
} MetadataClassification;

typedef enum {
  ARG_FORMAT_RAW = 0,
  ARG_FORMAT_ADDRESS = 1,
  ARG_FORMAT_AMOUNT = 2,
  ARG_FORMAT_BYTES = 3,
} ArgFormat;

typedef struct {
  char name[METADATA_MAX_ARG_NAME_LEN + 1];
  ArgFormat format;
  uint8_t value[METADATA_MAX_ARG_VALUE_LEN];
  uint16_t value_len;
} MetadataArg;

typedef struct {
  uint8_t version;
  uint32_t chain_id;
  uint8_t contract_address[20];
  uint8_t selector[4];
  uint8_t tx_hash[32];
  char method_name[METADATA_MAX_METHOD_LEN + 1];
  uint8_t num_args;
  MetadataArg args[METADATA_MAX_ARGS];
  MetadataClassification classification;
  uint32_t timestamp;
  uint8_t key_id;
  uint8_t signature[64];
  uint8_t recovery;
} SignedMetadata;

bool signed_metadata_available(void);
void signed_metadata_clear(void);
MetadataClassification signed_metadata_process(const uint8_t *payload,
                                              size_t payload_len,
                                              uint8_t key_id);
bool signed_metadata_matches_tx(const EthereumSignTx *msg,
                                const uint8_t *tx_hash);
bool signed_metadata_confirm(void);
const SignedMetadata *signed_metadata_get(void);

#endif
