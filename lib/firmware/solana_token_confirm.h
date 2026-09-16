/* Solana token-transfer screens shared by the signing FSM and screen tests. */
#ifndef KEEPKEY_FIRMWARE_SOLANA_TOKEN_CONFIRM_H
#define KEEPKEY_FIRMWARE_SOLANA_TOKEN_CONFIRM_H

#include <stdio.h>

#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/solana.h"
#include "trezor/crypto/base58.h"

/* Helper: Raw base58 encode (no checksum) for Solana pubkeys/addresses.
 * Uses b58enc() from trezor-crypto, which is the raw base58 encoder.
 * Solana addresses are raw base58-encoded 32-byte Ed25519 public keys. */
static bool solana_base58_encode(const uint8_t* data, size_t data_len,
                                 char* out, size_t* out_len) {
  return b58enc(out, out_len, data, data_len);
}

/* Helper: Base58-encode a 32-byte pubkey for display (full address).
 * Solana base58 addresses are 32-44 chars; out must be >= 45 bytes.
 * Never truncate — truncation is a spoofing vector. */
static void solana_pubkeyToStr(const uint8_t key[SOL_PUBKEY_SIZE], char* out,
                               size_t out_len) {
  size_t enc_len = out_len;
  if (solana_base58_encode(key, SOL_PUBKEY_SIZE, out, &enc_len)) {
    /* b58enc null-terminates and sets enc_len including the NUL */
    return;
  }
  /* Fallback to hex if base58 fails (middle-ellipsis OK for raw hex) */
  snprintf(out, out_len, "%02x%02x...%02x%02x", key[0], key[1], key[30],
           key[31]);
}

static bool solana_confirmTokenTransfer(const SolanaParsedInstruction* pi,
                                        const char* title,
                                        const uint8_t* recipient_owner) {
  char source_str[45];
  solana_pubkeyToStr(pi->from, source_str, sizeof(source_str));
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
               "Source token account\n%s", source_str)) {
    return false;
  }
  char to_str[45];
  solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));

  /* The mint is the only token identity the signed bytes carry, so it is
   * the only one shown. Its own screen, its own hold. */
  if (pi->has_mint) {
    char mint_str[45];
    solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                 "Token mint\n%s", mint_str)) {
      return false;
    }
  }

  /* Scale by the signed instruction's decimals (pi->extra_u8), and label
   * with the generic unit -- never with SolanaSignTx.token_info.symbol.
   *
   * This device has no on-device Solana mint table. The only token tables
   * it carries are tokens.def, ethereum_tokens.def and uniswap_tokens.def,
   * all ERC-20 and keyed by 20-byte Ethereum addresses, so there is
   * nothing here to authenticate a label such as "USDC" against.
   *
   * Requiring the host's claimed decimals to equal the signed ones
   * authenticates the exponent, not the identity: an attacker picks a mint
   * whose decimals already match the ones they declare, and the label then
   * rides through as device-verified fact. Nor can the label be shown with
   * a caveat -- the host controls up to 12 printable-ASCII characters
   * immediately beside it, enough to write its own parenthetical.
   *
   * The mint above plus a plain token count is everything the device can
   * honestly assert. */
  /* UINT64_MAX with a three-digit decimals count needs 54 bytes including
   * the terminator in the exact base-unit fallback. */
  /* PDA derivation proves an address relationship, not current authority:
   * SetAuthority can change control without changing an existing ATA's address.
   * Keep the recognizable derivation wallet, disclose that limitation, and
   * always confirm the actual signed destination below. */
  if (recipient_owner) {
    char owner_str[45];
    solana_pubkeyToStr(recipient_owner, owner_str, sizeof(owner_str));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                 "Address derived for\n%s", owner_str)) {
      return false;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                 "Current token account owner\nnot verified")) {
      return false;
    }
  }

  char amount_str[64];
  solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount, "tokens",
                           pi->extra_u8);
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                 "Send %s to %s?", amount_str, to_str);
}

#endif
