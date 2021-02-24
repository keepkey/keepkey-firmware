#include "keepkey/firmware/ethereum_tokens.h"

#include "keepkey/firmware/coins.h"

#include <string.h>

const TokenType tokens[] = {
#define X(CHAIN_ID, CONTRACT_ADDR, TICKER, DECIMALS) \
  {(CONTRACT_ADDR), (TICKER), (CHAIN_ID), (DECIMALS)},
#include "keepkey/firmware/uniswap_tokens.def"
#include "keepkey/firmware/ethereum_tokens.def"
};

_Static_assert(sizeof(tokens) / sizeof(tokens[0]) == TOKENS_COUNT,
               "TOKENS_COUNT mismatch");

static const TokenType Unknown = {
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00",
    " UNKN", 1, 0};
const TokenType *UnknownToken = (const TokenType *)&Unknown;

const TokenType *tokenByChainAddress(uint8_t chain_id, const uint8_t *address) {
  if (!address) return 0;
  for (int i = 0; i < TOKENS_COUNT; i++) {
    if (chain_id == tokens[i].chain_id &&
        memcmp(address, tokens[i].address, 20) == 0) {
      return &(tokens[i]);
    }
  }
  return UnknownToken;
}

bool tokenByTicker(uint8_t chain_id, const char *ticker,
                   const TokenType **token) {
  *token = NULL;

  // First look in the legacy table, confirming that the entry also exists in
  // the new table:
  for (int i = 0; i < COINS_COUNT; i++) {
    if (!coins[i].has_contract_address) {
      continue;
    }
    if (strcmp(ticker, coins[i].coin_shortcut) == 0) {
      *token = tokenByChainAddress(1, coins[i].contract_address.bytes);
      if (*token == UnknownToken) return false;
      return true;
    }
  }

  // Then look in the new table:
  for (int i = 0; i < TOKENS_COUNT; i++) {
    if (chain_id == tokens[i].chain_id &&
        strcmp(ticker, tokens[i].ticker + 1) == 0) {
      if (!*token)
        *token = &tokens[i];
      else
        return false;
    }
  }
  return *token;
}

void coinFromToken(CoinType *coin, const TokenType *token) {
  memset(coin, 0, sizeof(*coin));

  coin->has_coin_name = true;
  strncpy(&coin->coin_name[0], token->ticker + 1, sizeof(coin->coin_name));

  coin->has_coin_shortcut = true;
  strncpy(&coin->coin_shortcut[0], token->ticker + 1,
          sizeof(coin->coin_shortcut));

  coin->has_forkid = true;
  coin->forkid = token->chain_id;

  coin->has_maxfee_kb = true;
  coin->maxfee_kb = 100000;

  coin->has_bip44_account_path = true;
  coin->bip44_account_path = 0x8000003C;

  coin->has_decimals = true;
  coin->decimals = token->decimals;

  coin->has_contract_address = true;
  coin->contract_address.size = 20;
  memcpy((char *)&coin->contract_address.bytes[0], token->address, 20);
  _Static_assert(20 <= sizeof(coin->contract_address.bytes),
                 "contract_address is not large enough to hold an ETH address");

  coin->has_curve_name = true;
  strncpy(&coin->curve_name[0], "secp256k1", sizeof(coin->curve_name));
}
