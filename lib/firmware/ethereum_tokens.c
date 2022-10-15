#include "keepkey/firmware/ethereum_tokens.h"

#include "keepkey/firmware/coins.h"
#include "keepkey/board/confirm_sm.h"

#include <string.h>

TokenType tokens[TOKENS_COUNT] = {0};

static const TokenType Unknown = {
    true,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00",
    " UNKN", 1, 0};
const TokenType *UnknownToken = (const TokenType *)&Unknown;

static const TokenType Ethtest = {
    true,
    "\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee"
    "\xee\xee",
    "  ETH", 1, 18};
const TokenType *EthTestToken = (const TokenType *)&Ethtest;

// WETH is hard coded because uniswap needs this token data, see zxappliquid.c
static const TokenType weth = {
    true,
    "\xC0\x2a\xaA\x39\xb2\x23\xFE\x8D\x0A\x0e\x5C\x4F\x27\xeA\xD9\x08\x3C\x75\x6C\xc2",
    " WETH", 1, 18};
const TokenType *wethToken = (const TokenType *)&weth;

// DAI is hard coded because makerDAO contract needs this token data, see makerdao.c
static const TokenType dai = {
    true,
    "\x89\xd2\x4a\x6b\x4c\xcb\x1b\x6f\xaa\x26\x25\xfe\x56\x2b\xdd\x9a\x23\x26\x03\x59",
    // "\x6b\x17\x54\x74\xe8\x90\x94\xc4\x4d\xa9\x8b\x95\x4e\xed\xea\xc4\x95\x27\x1d\x0f",
    " DAI", 1, 18};
const TokenType *daiToken = (const TokenType *)&dai;


const TokenType *tokenIter(int32_t *ctr) {
  // return the next tok in the list.
  // input: *ctr = position of desired token (0 to TOKENS_COUNT)
  // output: returns token at list count *ctr at input for 0 <= *ctr < TOKEN_COUNT
  //         *ctr = position of next token in list, OR -1 for end of list

  if (*ctr < 0 || *ctr >= TOKENS_COUNT) {
    *ctr = -1;
    return UnknownToken;
  }
  
  *ctr+=1;
  return &(tokens[*ctr - 1]);

}

const TokenType *tokenByChainAddress(uint8_t chain_id, const uint8_t *address) {
  if (!address) return 0;
  for (int i = 0; i < TOKENS_COUNT; i++) {
    if (tokens[i].validToken) {
      if (chain_id == tokens[i].chain_id &&
          memcmp(address, tokens[i].address, 20) == 0) {
        return &(tokens[i]);
      }
    }
  }

  // check for special tokens
  if (chain_id == wethToken->chain_id && (memcmp(address, wethToken->address, 20) == 0)) {
    return wethToken;
  }

  if (chain_id == daiToken->chain_id && (memcmp(address, daiToken->address, 20) == 0)) {
    return daiToken;
  }

  if (memcmp(address, Ethtest.address, 20) == 0) {
    return EthTestToken;
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

  // check for special tokens
  if (chain_id == wethToken->chain_id && strcmp(ticker, wethToken->ticker + 1) == 0) {
    *token = wethToken;
    return true;
  }

  if (chain_id == daiToken->chain_id && strcmp(ticker, daiToken->ticker + 1) == 0) {
    *token = daiToken;
    return true;
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
  strlcpy(&coin->coin_name[0], token->ticker + 1, sizeof(coin->coin_name));

  coin->has_coin_shortcut = true;
  strlcpy(&coin->coin_shortcut[0], token->ticker + 1,
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
  strlcpy(&coin->curve_name[0], "secp256k1", sizeof(coin->curve_name));
}
