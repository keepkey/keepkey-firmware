#include "keepkey/firmware/cosmos.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/memzero.h"
#include <stdbool.h>
#include <time.h>

static char* signing_template = "{\"account_number\":\"%d\",\"chain_id\":\"%s\",\"fee\":{\"amount\":[{\"amount\":\"%d\",\"denom\":\"uatom\"}],\"gas\":\"%d\"},\"memo\":\"%s\",\"msgs\":[{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{\"amount\":[{\"amount\":\"%d\",\"denom\":\"uatom\"}],\"from_address\":\"%s\",\"to_address\":\"%s\"}}],\"sequence\":\"%d\"}";

/*
 * Starts the signing process and parses the transaction header
 */
bool cosmos_getAddress(const CosmosGetAddress *msg)
{
}

bool cosmos_signTx(const CosmosSignTx *msg)
{
}