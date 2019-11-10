#include "keepkey/firmware/cosmos.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/memzero.h"
#include <stdbool.h>
#include <time.h>

static bool stellar_signing = false;
static StellarTransaction stellar_activeTx;

/*
 * Starts the signing process and parses the transaction header
 */
bool cosmos_getAddress(const CosmosGetAddress *msg)
{
}

bool cosmos_signTx(const CosmosSignTx *msg)
{
}