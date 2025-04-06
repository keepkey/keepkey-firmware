#include "keepkey/firmware/nano.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "hwcrypto/crypto/blake2b.h"
#include "hwcrypto/crypto/memzero.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#ifdef EMULATOR
#include <assert.h>
#endif

static ed25519_public_key account_pk;
static bignum256 parent_balance;
static bignum256 balance;
static bignum256 balance_delta;
static uint8_t block_hash[32];
static uint8_t parent_hash[32];
static uint8_t link[32];
static ed25519_public_key representative_pk;
static uint8_t balance_be[16];
static bool is_send = true;
static char representative_address[MAX_NANO_ADDR_SIZE];
static char recipient_address[MAX_NANO_ADDR_SIZE];
static const CoinType *coin = NULL;

static uint8_t const NANO_BLOCK_HASH_PREAMBLE[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
};

bool nano_path_mismatched(const CoinType *_coin, const uint32_t *address_n,
                          const uint32_t address_n_count) {
  // m/44' : BIP44-like path
  // m / purpose' / bip44_account_path' / account'
  bool mismatch = false;
  mismatch |= address_n_count != 3;
  mismatch |= address_n_count > 0 && (address_n[0] != (0x80000000 + 44));
  mismatch |=
      address_n_count > 1 && (address_n[1] != _coin->bip44_account_path);
  mismatch |= address_n_count > 2 && (address_n[2] & 0x80000000) == 0;
  return mismatch;
}

bool nano_bip32_to_string(char *node_str, size_t len, const CoinType *_coin,
                          const uint32_t *address_n,
                          const size_t address_n_count) {
  if (address_n_count != 3) return false;

  if (nano_path_mismatched(_coin, address_n, address_n_count)) return false;

  snprintf(node_str, len, "%s Account #%" PRIu32, _coin->coin_name,
           address_n[2] & 0x7ffffff);
  return true;
}

void nano_hash_block_data(const uint8_t _account_pk[32],
                          const uint8_t _parent_hash[32],
                          const uint8_t _link[32],
                          const uint8_t _representative_pk[32],
                          const uint8_t _balance[16], uint8_t _out_hash[32]) {
  blake2b_state ctx;
  blake2b_Init(&ctx, 32);

  blake2b_Update(&ctx, NANO_BLOCK_HASH_PREAMBLE,
                 sizeof(NANO_BLOCK_HASH_PREAMBLE));
  blake2b_Update(&ctx, _account_pk, 32);
  blake2b_Update(&ctx, _parent_hash, 32);
  blake2b_Update(&ctx, _representative_pk, 32);
  blake2b_Update(&ctx, _balance, 16);
  blake2b_Update(&ctx, _link, 32);

  blake2b_Final(&ctx, _out_hash, 32);
}

const char *nano_getKnownRepName(const char *addr) {
  static const struct {
    const char *name;
    const char *addr;
  } reps[] = {
      {"@meltingice ",
       "xrb_1x7biz69cem95oo7gxkrw6kzhfywq4x5dupw4z1bdzkb74dk9kpxwzjbdhhs"},
      {"@nanovault-rep ",
       "xrb_3rw4un6ys57hrb39sy1qx8qy5wukst1iiponztrz9qiz6qqa55kxzx4491or"},
      {"@nanowallet_rep1 ",
       "xrb_3pczxuorp48td8645bs3m6c3xotxd3idskrenmi65rbrga5zmkemzhwkaznh"},
      {"Binance Rep ",
       "xrb_3jwrszth46rk1mu7rmb4rhm54us8yg1gw3ipodftqtikf5yqdyr7471nsg1k"},
      {"BrainBlocks Rep ",
       "xrb_1brainb3zz81wmhxndsbrjb94hx3fhr1fyydmg6iresyk76f3k7y7jiazoji"},
      {"Genesis ",
       "xrb_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"},
      {"KuCoin 1 ",
       "xrb_1niabkx3gbxit5j5yyqcpas71dkffggbr6zpd3heui8rpoocm5xqbdwq44oh"},
      {"NanoWallet Bot Rep ",
       "xrb_16k5pimotz9zehjk795wa4qcx54mtusk8hc5mdsjgy57gnhbj3hj6zaib4ic"},
      {"Nanode Rep ",
       "xrb_1nanode8ngaakzbck8smq6ru9bethqwyehomf79sae1k7xd47dkidjqzffeg"},
      {"OKEx Rep ",
       "xrb_1tig1rio7iskejqgy6ap75rima35f9mexjazdqqquthmyu48118jiewny7zo"},
      {"Official Rep 1 ",
       "xrb_3arg3asgtigae3xckabaaewkx3bzsh7nwz7jkmjos79ihyaxwphhm6qgjps4"},
      {"Official Rep 2 ",
       "xrb_1stofnrxuz3cai7ze75o174bpm7scwj9jn3nxsn8ntzg784jf1gzn1jjdkou"},
      {"Official Rep 3 ",
       "xrb_1q3hqecaw15cjt7thbtxu3pbzr1eihtzzpzxguoc37bj1wc5ffoh7w74gi6p"},
      {"Official Rep 4 ",
       "xrb_3dmtrrws3pocycmbqwawk6xs7446qxa36fcncush4s1pejk16ksbmakis78m"},
      {"Official Rep 5 ",
       "xrb_3hd4ezdgsp15iemx7h81in7xz5tpxi43b6b41zn3qmwiuypankocw3awes5k"},
      {"Official Rep 6 ",
       "xrb_1awsn43we17c1oshdru4azeqjz9wii41dy8npubm4rg11so7dx3jtqgoeahy"},
      {"Official Rep 7 ",
       "xrb_1anrzcuwe64rwxzcco8dkhpyxpi8kd7zsjc1oeimpc3ppca4mrjtwnqposrs"},
      {"Official Rep 8 ",
       "xrb_1hza3f7wiiqa7ig3jczyxj5yo86yegcmqk3criaz838j91sxcckpfhbhhra1"},
  };

  for (size_t i = 0; i < sizeof(reps) / sizeof(reps[0]); i++) {
    if (strcmp(addr, reps[i].addr) == 0) return reps[i].name;
  }

  return NULL;
}

void nano_truncateAddress(const CoinType *_coin, char *str) {
  const size_t prefix_len = strlen(_coin->nanoaddr_prefix);
  const size_t str_len = strlen(str);

  if (str_len < prefix_len + 12) return;

  memset(&str[prefix_len + 5], '.', 2);
  memmove(&str[prefix_len + 7], &str[str_len - 5], 5);
  str[prefix_len + 12] = '\0';
}

void nano_signingAbort(void) {
  bn_zero(&parent_balance);
  bn_zero(&balance);
  bn_zero(&balance_delta);

  memset(block_hash, 0, sizeof(block_hash));
  memset(parent_hash, 0, sizeof(parent_hash));
  memset(link, 0, sizeof(link));
  memset(representative_pk, 0, sizeof(representative_pk));
  memset(balance_be, 0, sizeof(balance_be));

  memset(recipient_address, 0, sizeof(recipient_address));
  memset(representative_address, 0, sizeof(representative_address));

  is_send = true;
}

bool nano_signingInit(const NanoSignTx *msg, const HDNode *node,
                      const CoinType *_coin) {
  nano_signingAbort();

  memcpy(account_pk, &node->public_key[1], sizeof(account_pk));
  coin = _coin;

  // Validate input data
  bool invalid = false;
  if (msg->has_parent_block) {
    invalid |= msg->parent_block.has_parent_hash &&
               msg->parent_block.parent_hash.size != 32;
    invalid |= msg->parent_block.has_link && msg->parent_block.link.size != 32;
    invalid |= !msg->parent_block.has_representative;
    invalid |=
        !msg->parent_block.has_balance || msg->parent_block.balance.size != 16;
  }
  if (!msg->has_parent_block) {
    invalid |= !msg->has_link_hash;  // first block must be a receive block
  }
  invalid |= (int)msg->has_link_hash + (int)msg->has_link_recipient +
                 (int)(msg->link_recipient_n_count != 0) >
             1;
  invalid |= msg->has_link_hash && msg->link_hash.size != 32;
  invalid |= !msg->has_representative;
  invalid |= !msg->has_balance || msg->balance.size != 16;

  return !invalid;
}

bool nano_parentHash(const NanoSignTx *msg) {
  if (!msg->has_parent_block) return true;

  if (msg->parent_block.has_parent_hash) {
    memcpy(parent_hash, msg->parent_block.parent_hash.bytes,
           sizeof(parent_hash));
  }
  memcpy(link, msg->parent_block.link.bytes, sizeof(link));

  if (!nano_validate_address(
          coin->nanoaddr_prefix, strlen(coin->nanoaddr_prefix),
          msg->parent_block.representative,
          strlen(msg->parent_block.representative), representative_pk))
    return false;

  memcpy(balance_be, msg->parent_block.balance.bytes, sizeof(balance_be));
  bn_from_bytes(balance_be, sizeof(balance_be), &parent_balance);

  nano_hash_block_data(account_pk, parent_hash, link, representative_pk,
                       balance_be, block_hash);

  memcpy(parent_hash, block_hash, sizeof(parent_hash));
  memset(block_hash, 0, sizeof(parent_hash));
  memset(link, 0, sizeof(link));
  memset(representative_pk, 0, sizeof(representative_pk));
  memset(balance_be, 0, sizeof(balance_be));

  return true;
}

bool nano_currentHash(const NanoSignTx *msg, const HDNode *recip) {
  if (msg->has_link_hash) {
    memcpy(link, msg->link_hash.bytes, sizeof(link));
  } else if (msg->link_recipient_n_count > 0) {
    if (!recip) return false;
    memcpy(link, &recip->public_key[1], sizeof(link));
  } else if (msg->has_link_recipient) {
    memcpy(link, msg->link_recipient, sizeof(link));
    if (!nano_validate_address(
            coin->nanoaddr_prefix, strlen(coin->nanoaddr_prefix),
            msg->link_recipient, strlen(msg->link_recipient), link))
      return false;
  }

  if (!nano_validate_address(coin->nanoaddr_prefix,
                             strlen(coin->nanoaddr_prefix), msg->representative,
                             strlen(msg->representative), representative_pk))
    return false;

  memcpy(balance_be, msg->balance.bytes, sizeof(balance_be));
  bn_from_bytes(balance_be, sizeof(balance_be), &balance);

  nano_hash_block_data(account_pk, parent_hash, link, representative_pk,
                       balance_be, block_hash);

  return true;
}

/// Some additional sanity checks now that balance values are known
bool nano_sanityCheck(const NanoSignTx *msg) {
  memset(recipient_address, 0, sizeof(recipient_address));

  strlcpy(representative_address, msg->representative,
          sizeof(representative_address));
  if (msg->has_parent_block) {
    if (!strncmp(representative_address, msg->parent_block.representative,
                 sizeof(representative_address))) {
      // Representative hasn't changed, zero it out
      memset(representative_address, 0, sizeof(representative_address));
    }
  }

  if (bn_is_less(&balance, &parent_balance)) {
    is_send = true;
    bn_subtract(&parent_balance, &balance, &balance_delta);
  } else {
    is_send = false;
    bn_subtract(&balance, &parent_balance, &balance_delta);
  }

  bool invalid = false;
  if (bn_is_zero(&balance_delta)) {
    // Balance can only remain unchanged when the account exists already
    invalid |= !msg->has_parent_block;
  } else if (is_send) {
    // For sends make fill out the link_recipient (or generate it from link
    // bytes)
    if (msg->has_link_recipient) {
      strlcpy(recipient_address, msg->link_recipient,
              sizeof(recipient_address));
    } else {
      nano_get_address(link, coin->nanoaddr_prefix,
                       strlen(coin->nanoaddr_prefix), recipient_address,
                       sizeof(recipient_address));
    }
  } else {
    // For receives make sure that the link_hash was specified and that it's
    invalid |= !msg->has_link_hash;
    uint8_t link_empty[sizeof(link)];
    memset(link_empty, 0, sizeof(link_empty));
    invalid |= !memcmp(link_empty, link, sizeof(link));
  }

  return !invalid;
}

bool nano_signTx(const NanoSignTx *msg, HDNode *node, NanoSignedTx *resp) {
  // Determine what type of prompt to display
  bool needs_confirm = true;
  bool is_transfer = false;
  if (strlen(representative_address) > 0) {
    // always confirm representative change
  } else if (!is_send) {
    // don't bother confirming pure receives
    needs_confirm = false;
  } else if (msg->link_recipient_n_count > 0 &&
             !nano_path_mismatched(coin, msg->link_recipient_n,
                                   msg->link_recipient_n_count)) {
    is_transfer = true;
  }

  if (needs_confirm) {
    if (strlen(representative_address) > 0) {
      const char *rep_name = nano_getKnownRepName(representative_address);
      if (rep_name) nano_truncateAddress(coin, representative_address);
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Representative", "Set account representative to\n%s%s?",
                   rep_name ? rep_name : "", representative_address)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled");
        layoutHome();
        return false;
      }
    }

    char amount_string[60];
    memset(amount_string, 0, sizeof(amount_string));
    bn_format(&balance_delta, NULL, NULL, coin->decimals, 0, false,
              amount_string, sizeof(amount_string));

    if (is_transfer) {
      // Confirm transfer between own accounts
      char account_str[NODE_STRING_LENGTH];
      if (!nano_bip32_to_string(account_str, sizeof(account_str), coin,
                                msg->link_recipient_n,
                                msg->link_recipient_n_count) &&
          !bip32_path_to_string(account_str, sizeof(account_str),
                                msg->link_recipient_n,
                                msg->link_recipient_n_count)) {
        strlcpy(account_str, recipient_address, sizeof(account_str));
      }

      if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Transfer",
                   "Send %s %s to %s?", amount_string, coin->coin_shortcut,
                   account_str)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled");
        layoutHome();
        return false;
      }
    } else if (is_send) {
      // Regular transfer
      if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Send",
                   "Send %s %s to %s?", amount_string, coin->coin_shortcut,
                   recipient_address)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled");
        layoutHome();
        return false;
      }
    }
  }

  resp->has_signature = true;
  resp->signature.size = 64;
  hdnode_sign_digest(node, block_hash, resp->signature.bytes, NULL, NULL);

  resp->has_block_hash = true;
  resp->block_hash.size = sizeof(block_hash);
  memcpy(resp->block_hash.bytes, block_hash, sizeof(block_hash));
  return true;
}
