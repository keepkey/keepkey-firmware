/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "scm_revision.h"
#include "variant.h"
#include "u2f_knownapps.h"

#include "keepkey/board/check_bootloader.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/resources.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/util.h"
#include "keepkey/board/variant.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/bip85.h"
#include "keepkey/rand/rng_health.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/cosmos.h"
#include "keepkey/firmware/binance.h"
#include "keepkey/firmware/crypto.h"
#include "keepkey/firmware/eos.h"
#include "keepkey/firmware/eos-contracts.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/hive.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/nano.h"
#include "keepkey/firmware/osmosis.h"
#include "keepkey/firmware/passphrase_sm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/policy.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/ripple.h"
#include "keepkey/firmware/signed_metadata.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/signtx_tendermint.h"
#include "keepkey/firmware/solana.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/tendermint.h"
#include "keepkey/firmware/thorchain.h"
#include "keepkey/firmware/tron.h"
#include "keepkey/firmware/ton.h"
#include "keepkey/firmware/transaction.h"
#include "keepkey/firmware/zcash.h"
#include "keepkey/firmware/txin_check.h"
#include "keepkey/firmware/u2f.h"
#include "keepkey/rand/rng.h"
#include "trezor/crypto/address.h"
#include "trezor/crypto/aes/aes.h"
#include "trezor/crypto/base58.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/hmac.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/rand.h"
#include "trezor/crypto/ripemd160.h"
#include "trezor/crypto/secp256k1.h"

#include "messages.pb.h"
#include "messages-ethereum.pb.h"
#include "messages-hive.pb.h"
#include "messages-zcash.pb.h"
#include "messages-binance.pb.h"
#include "messages-cosmos.pb.h"
#include "messages-osmosis.pb.h"
#include "messages-eos.pb.h"
#include "messages-nano.pb.h"
#include "messages-ripple.pb.h"
#include "messages-thorchain.pb.h"
#include "messages-mayachain.pb.h"
#include "messages-tron.pb.h"
#include "messages-ton.pb.h"
#include "messages-solana.pb.h"

#include <stdio.h>
/* strnlen: the THORChain memo paths measure fixed arrays rather than
   trusting their capacity. Included explicitly instead of relying on the
   fsm_msg_*.h textual includes below to drag it in by accident. */
#include <string.h>

#define _(X) (X)

static uint8_t msg_resp[MAX_FRAME_SIZE] __attribute__((aligned(4)));
/* Shared scratch returned by fsm_getDerivedNode(). It may hold a root or
 * derived private key after any chain handler, so session revocation scrubs it
 * centrally. */
static HDNode CONFIDENTIAL fsm_derived_node;

void fsm_clearDerivedNode(void) {
  memzero(&fsm_derived_node, sizeof(fsm_derived_node));
}

#if DEBUG_LINK
static FailureType fsm_test_failure_code;

void fsm_test_seedDerivedNode(void) {
  memset(&fsm_derived_node, 0xA5, sizeof(fsm_derived_node));
}

bool fsm_test_derivedNodeIsZero(void) {
  const uint8_t* bytes = (const uint8_t*)&fsm_derived_node;
  uint8_t aggregate = 0;
  for (size_t i = 0; i < sizeof(fsm_derived_node); i++) aggregate |= bytes[i];
  return aggregate == 0;
}

void fsm_test_clearLastFailure(void) { fsm_test_failure_code = (FailureType)0; }

FailureType fsm_test_lastFailureCode(void) { return fsm_test_failure_code; }
#endif

#define CHECK_INITIALIZED                               \
  if (!storage_isInitialized()) {                       \
    fsm_sendFailure(FailureType_Failure_NotInitialized, \
                    "Device not initialized");          \
    return;                                             \
  }

/* A locked bitcoin-only wallet leaves the RAM shadow reset, so handlers that
 * merely PERSIST settings look perfectly ordinary: storage_setPin(),
 * storage_setLabel() and friends update the shadow, storage_commit() then
 * returns without writing (the btc_only_locked backstop in storage.c), and the
 * handler answers Success. The change appears to take effect for the rest of
 * the session and is gone at the next boot.
 *
 * CHECK_NOT_INITIALIZED already refuses this for the ceremonies that CREATE a
 * seed. The same reasoning applies to every handler that expects its write to
 * survive a reboot, and those were missed. Refuse before doing the work rather
 * than reporting a success that did not happen. */
#define CHECK_NOT_BITCOIN_ONLY_LOCKED                                \
  if (storage_isBitcoinOnlyLocked()) {                               \
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,           \
                    "Bitcoin-only wallet present. Use Wipe first."); \
    layoutHome();                                                    \
    return;                                                          \
  }

#define CHECK_NOT_INITIALIZED                                              \
  if (storage_isInitialized()) {                                           \
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,                 \
                    "Device is already initialized. Use Wipe first.");     \
    return;                                                                \
  }                                                                        \
  /* A locked bitcoin-only wallet leaves the device LOOKING uninitialized: \
   * the RAM shadow was reset at boot, so storage_isInitialized() is       \
   * false. Refuse here, loudly, before the user does the work -- a        \
   * ceremony allowed to run would end in storage_commit() declining to    \
   * write and the handler reporting success anyway. */                    \
  if (storage_isBitcoinOnlyLocked()) {                                     \
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,                 \
                    "Bitcoin-only wallet present. Use Wipe first.");       \
    return;                                                                \
  }

/* Only the two ceremony STARTS use this. Every other message that persists
 * anything is handled structurally instead: storage_commit() aborts an armed
 * ceremony, so a handler that writes can never have its write consumed by
 * one -- the worst it can do is end it. */
#define CHECK_NO_CEREMONY                                     \
  if (setup_isArmed()) {                                      \
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,    \
                    "Device is in the middle of setup. Send " \
                    "Initialize or Cancel first.");           \
    layoutHome();                                             \
    return;                                                   \
  }

#define CHECK_PIN              \
  if (!pin_protect_cached()) { \
    layoutHome();              \
    return;                    \
  }

#define CHECK_PIN_UNCACHED       \
  if (!pin_protect_uncached()) { \
    layoutHome();                \
    return;                      \
  }

#define CHECK_PARAM_RET(cond, errormsg, retval)             \
  if (!(cond)) {                                            \
    fsm_sendFailure(FailureType_Failure_Other, (errormsg)); \
    layoutHome();                                           \
    return retval;                                          \
  }

#define CHECK_PARAM(cond, errormsg) CHECK_PARAM_RET(cond, errormsg, )

static const MessagesMap_t MessagesMap[] = {
#include "messagemap.def"
};

#undef MSG_IN
#define MSG_IN(ID, STRUCT_NAME, PROCESS_FUNC) \
  _Static_assert(sizeof(STRUCT_NAME) <= MAX_DECODE_SIZE, "Message too big");

#undef MSG_OUT
#define MSG_OUT(ID, STRUCT_NAME, PROCESS_FUNC)

#undef RAW_IN
#define RAW_IN(ID, STRUCT_NAME, PROCESS_FUNC) \
  _Static_assert(sizeof(STRUCT_NAME) <= MAX_DECODE_SIZE, "Message too big");

#undef DEBUG_IN
#define DEBUG_IN(ID, STRUCT_NAME, PROCESS_FUNC) \
  _Static_assert(sizeof(STRUCT_NAME) <= MAX_DECODE_SIZE, "Message too big");

#undef DEBUG_OUT
#define DEBUG_OUT(ID, STRUCT_NAME, PROCESS_FUNC)

#include "messagemap.def"

extern bool reset_msg_stack;

static const CoinType* fsm_getCoin(bool has_name, const char* name) {
  const CoinType* coin;
  if (has_name) {
    coin = coinByName(name);
  } else {
    coin = coinByName("Bitcoin");
  }
  if (!coin) {
    fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
    layoutHome();
    return 0;
  }

  return coin;
}

static HDNode* fsm_getDerivedNode(const char* curve, const uint32_t* address_n,
                                  size_t address_n_count,
                                  uint32_t* fingerprint) {
  if (fingerprint) {
    *fingerprint = 0;
  }

  /* Every failure below returns NULL, so the caller has no pointer with which
   * to clear this scratch -- only this function can. Leaving it dirty left a
   * root or half-derived private key resident until whatever happened to
   * overwrite it next: storage_getRootNode() may write before it fails, and by
   * the time hdnode_private_ckd_cached() can fail the root is definitely
   * there. Scrub on entry, and on each failure after a possible write. */
  memzero(&fsm_derived_node, sizeof(fsm_derived_node));

  if (!get_curve_by_name(curve)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Unknown ecdsa curve");
    layoutHome();
    return 0;
  }

  if (!storage_getRootNode(curve, true, &fsm_derived_node)) {
    memzero(&fsm_derived_node, sizeof(fsm_derived_node));
    fsm_sendFailure(FailureType_Failure_NotInitialized,
                    "Device not initialized or passphrase request cancelled");
    layoutHome();
    return 0;
  }

  if (!address_n || address_n_count == 0) {
    return &fsm_derived_node;
  }

  if (hdnode_private_ckd_cached(&fsm_derived_node, address_n, address_n_count,
                                fingerprint) == 0) {
    memzero(&fsm_derived_node, sizeof(fsm_derived_node));
    fsm_sendFailure(FailureType_Failure_Other, "Failed to derive private key");
    layoutHome();
    return 0;
  }

  return &fsm_derived_node;
}

/* A transport rejection never reaches the chain handler's abort path. Clear
 * the in-flight SIGNING session before reporting it so a later packet cannot
 * resume one: a malformed EthereumTxAck or TxAck is rejected here, and without
 * this the half-advanced session is still live for the next ack.
 *
 * Recovery advances only through on-device word entry, so unrelated host
 * probes must not destroy it. Reset is different: EntropyAck is a host message
 * and may arrive after a malformed frame. Disarm reset before reporting the
 * transport failure so a stale EntropyAck cannot commit the ceremony. */
static void sendFailureWrapper(FailureType code, const char* text) {
  fsm_abort_signing_workflows();
  if (setup_isArmedAs(SETUP_RECOVERY)) {
    /* Signing aborts may already have replaced the OLED with home. Restore
     * the same recovery cipher, without randomizing its mapping or accepting
     * another character from the unrelated host packet. */
    recovery_cipher_redraw();
  } else {
    setup_abort();
    layoutHome();
  }
  fsm_sendFailure(code, text);
}

void fsm_init(void) {
  msg_map_init(MessagesMap, sizeof(MessagesMap) / sizeof(MessagesMap_t));
  set_msg_failure_handler(&sendFailureWrapper);

  /* set leaving handler for layout to help with determine home state */
  set_leaving_handler(&leave_home);

#if DEBUG_LINK
  set_msg_debug_link_get_state_handler(&fsm_msgDebugLinkGetState);
#endif

  msg_init();

  txin_dgst_initialize();
}

/* Only messages that advance an already established stream, plus bounded
 * read-only polls, may inherit a signing workflow. Every other top-level
 * request ends signing before its handler can block for host or user input.
 * New protocol messages therefore fail closed until classified here. An ACK
 * inherits state only when its own workflow is active; message type alone is
 * not authority to preserve some other signer.
 *
 * Deliberately NOT session_clear(true): that is a LOCK. It would drop the PIN,
 * passphrase and seed cache, disarm AdvancedMode and revoke ClearSign signers
 * on every request, so ApplyPolicies/LoadClearsignSigner could never reach the
 * EthereumSignTx that needs them. Idle locking stays with toggle_screensaver.
 * Metadata loaded before a sign survives: ethereum_signing_abort() only clears
 * it while a stream is active. */
static bool reject_stale_continuation(const char* text) {
  /* A decoded request always gets a terminal response. Silently dropping an
   * inactive ACK leaves the host blocked forever, while dispatching it would
   * let the handler replace an unrelated recovery screen. End signing, keep
   * any setup ceremony armed, and reject on the wire without changing OLED
   * state. */
  fsm_abort_signing_workflows();
  fsm_sendFailure(FailureType_Failure_UnexpectedMessage, text);
  return false;
}

bool keepkey_before_message_dispatch(MessageType msg_id) {
  switch (msg_id) {
    case MessageType_MessageType_GetFeatures:
    case MessageType_MessageType_GetCoinTable:
    case MessageType_MessageType_Ping:
      return true;
    case MessageType_MessageType_TxAck:
      if (!signing_is_active())
        return reject_stale_continuation("Signing not in progress");
      return true;
    case MessageType_MessageType_EntropyAck:
      if (!setup_isArmedAs(SETUP_RESET))
        return reject_stale_continuation("Not in Reset mode");
      return true;
    case MessageType_MessageType_CharacterAck:
      if (!setup_isArmedAs(SETUP_RECOVERY))
        return reject_stale_continuation("Not in Recovery mode");
      return true;
#if !BITCOIN_ONLY
    case MessageType_MessageType_EthereumTxAck:
      if (!ethereum_signing_isInProgress())
        return reject_stale_continuation("Signing not in progress");
      return true;
    case MessageType_MessageType_CosmosMsgAck:
      if (!tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS))
        return reject_stale_continuation("Cosmos signing not in progress");
      return true;
    case MessageType_MessageType_OsmosisMsgAck:
      if (!osmosis_signingIsInited())
        return reject_stale_continuation("Osmosis signing not in progress");
      return true;
    case MessageType_MessageType_BinanceTransferMsg:
      if (!binance_signingIsInited())
        return reject_stale_continuation("Signing not in progress?");
      return true;
    case MessageType_MessageType_EosTxActionAck:
      if (!eos_signingIsInited())
        return reject_stale_continuation("EOS signing not in progress");
      return true;
    case MessageType_MessageType_ThorchainMsgAck:
      if (!thorchain_signingIsInited())
        return reject_stale_continuation("Signing not in progress");
      return true;
    case MessageType_MessageType_MayachainMsgAck:
      if (!mayachain_signingIsInited())
        return reject_stale_continuation("Signing not in progress");
      return true;
#endif
#if ZCASH_PRIVACY
    case MessageType_MessageType_ZcashPCZTAction:
    case MessageType_MessageType_ZcashTransparentOutput:
    case MessageType_MessageType_ZcashTransparentInput:
      if (!zcash_signing_is_active())
        return reject_stale_continuation("Zcash signing not in progress");
      return true;
#endif
    default:
      /* A new signing operation may replace an old signer, but it must never
       * coexist with recovery/reset and borrow that ceremony's progress or
       * blocking screens. Administrative requests still preserve ceremonies. */
      switch (msg_id) {
        case MessageType_MessageType_SignTx:
        case MessageType_MessageType_SignMessage:
        case MessageType_MessageType_SignIdentity:
        case MessageType_MessageType_CipherKeyValue:
#if !BITCOIN_ONLY
        case MessageType_MessageType_EthereumSignTx:
        case MessageType_MessageType_EthereumSignMessage:
        case MessageType_MessageType_EthereumSignTypedHash:
        case MessageType_MessageType_NanoSignTx:
        case MessageType_MessageType_CosmosSignTx:
        case MessageType_MessageType_OsmosisSignTx:
        case MessageType_MessageType_BinanceSignTx:
        case MessageType_MessageType_EosSignTx:
        case MessageType_MessageType_RippleSignTx:
        case MessageType_MessageType_ThorchainSignTx:
        case MessageType_MessageType_MayachainSignTx:
        case MessageType_MessageType_GetBip85Mnemonic:
        case MessageType_MessageType_TronSignTx:
        case MessageType_MessageType_TronSignMessage:
        case MessageType_MessageType_TronSignTypedHash:
        case MessageType_MessageType_TonSignTx:
        case MessageType_MessageType_TonSignMessage:
        case MessageType_MessageType_SolanaSignTx:
        case MessageType_MessageType_SolanaSignMessage:
        case MessageType_MessageType_SolanaSignOffchainMessage:
        case MessageType_MessageType_HiveSignTx:
        case MessageType_MessageType_HiveSignAccountCreate:
        case MessageType_MessageType_HiveSignAccountUpdate:
        case MessageType_MessageType_HiveSignMessage:
        case MessageType_MessageType_HiveSignOperations:
        case MessageType_MessageType_ClearsignAttestorSign:
#endif
#if ZCASH_PRIVACY
        case MessageType_MessageType_ZcashSignPCZT:
#endif
          setup_abort();
          break;
        default:
          break;
      }
      fsm_abort_signing_workflows();
      return true;
  }
}

void keepkey_after_message_dispatch(void) {
  /* fsm_getDerivedNode() returns shared confidential scratch. No handler may
   * leave a private key resident after its response or cancellation. */
  fsm_clearDerivedNode();
}

void fsm_sendSuccess(const char* text) {
  if (reset_msg_stack) {
    fsm_msgInitialize((Initialize*)0);
    reset_msg_stack = false;
    return;
  }

  RESP_INIT(Success);

  if (text) {
    resp->has_message = true;
    strlcpy(resp->message, text, sizeof(resp->message));
  }

  msg_write(MessageType_MessageType_Success, resp);
}

void fsm_sendFailure(FailureType code, const char* text) {
  if (reset_msg_stack) {
    fsm_msgInitialize((Initialize*)0);
    reset_msg_stack = false;
    return;
  }

  RESP_INIT(Failure);
  resp->has_code = true;
  resp->code = code;
#if DEBUG_LINK
  fsm_test_failure_code = code;
#endif

  if (text) {
    resp->has_message = true;
    strlcpy(resp->message, text, sizeof(resp->message));
  }
  msg_write(MessageType_MessageType_Failure, resp);
}

void fsm_abort_workflows(void) {
  setup_abort();
  fsm_abort_signing_workflows();
}

/* The signing half of the above. Clearing PIN authorization revokes retained
 * signing state, but must not discard a setup ceremony: recovery stages its
 * ceremony before prompting for the PIN, and every routine PIN entry clears
 * the session while checking the entered digits against the wipe code. */
void fsm_abort_signing_workflows(void) {
  signing_abort();
#if !BITCOIN_ONLY
  ethereum_signing_abort();
  nano_signingAbort();
  binance_signAbort();
  tendermint_signAbort();
  osmosis_signAbort();
  thorchain_signAbort();
  mayachain_signAbort();
  eos_signingAbort();
  zcash_signing_abort();
#endif
  authenticator_clear_cache();
  memzero(&fsm_derived_node, sizeof(fsm_derived_node));
}

void fsm_msgClearSession(ClearSession* msg) {
  (void)msg;
  fsm_abort_workflows();
  session_clear(/*clear_pin=*/true);
  /* Several abort routines -- Binance, Tendermint, Osmosis, THORChain,
     MAYAChain, EOS, Nano -- only clear state and touch no layout, so without
     this the approval screen of the transaction just cancelled stays on the
     OLED, describing an operation that no longer exists.

     Done here and in fsm_msgCancel() rather than inside fsm_abort_workflows(),
     because that is also called from toggle_screensaver(), which draws the
     screensaver immediately afterwards. */
  layoutHome();
  fsm_sendSuccess("Session cleared");
}

// Always-on handlers: Bitcoin and common device messages (fsm_msg_coin,
// fsm_msg_common), CipherKeyValue/identity (fsm_msg_crypto) and debug-link.
// None of these is a coin engine.
#include "fsm_msg_common.h"
#include "fsm_msg_coin.h"
#include "fsm_msg_crypto.h"
#include "fsm_msg_debug.h"
#if !BITCOIN_ONLY
// BIP-85 derives child mnemonics for OTHER wallets -- a multi-chain feature.
// It must be gated in step with messagemap.def: a handler compiled with no
// entry referencing it is an unused function, which -Werror turns into a
// build failure.
#include "fsm_msg_bip85.h"
#include "fsm_msg_ethereum.h"
#include "fsm_msg_nano.h"
#include "fsm_msg_eos.h"
#include "fsm_msg_cosmos.h"
#include "fsm_msg_osmosis.h"
#include "fsm_msg_binance.h"
#include "fsm_msg_ripple.h"
#include "fsm_msg_tendermint.h"
#include "fsm_msg_thorchain.h"
#include "fsm_msg_mayachain.h"
#include "fsm_msg_tron.h"
#include "fsm_msg_ton.h"
#include "fsm_msg_solana.h"
#include "fsm_msg_hive.h"
/* After fsm_msg_solana.h: reuses its base58 helper and the KKSOLSC1 parser. */
#include "fsm_msg_clearsign_attestor.h"
#else
// Bitcoin-only: the coin engines above are compiled out, but the always-on
// Initialize/ClearSession/Cancel handlers still call their *_abort() hooks,
// and factory-reset calls signed_metadata_clear_signers() (EVM clearsign).
// With no state to reset, no-ops are the correct definitions -- and defining
// them here keeps those handlers free of build-variant branches.
void ethereum_signing_abort(void) {}
void tendermint_signAbort(void) {}
void eos_signingAbort(void) {}
void signed_metadata_clear_signers(void) {}
#endif  // !BITCOIN_ONLY
#if ZCASH_PRIVACY
#include "fsm_msg_zcash.h"
#else
// Zcash shielded/Orchard engine compiled out. The always-on
// Initialize/ClearSession/Cancel handlers still call zcash_signing_abort();
// with no privacy state to reset, a no-op is correct. (Bitcoin-only forces
// privacy off, so this stub also covers the bitcoin-only image.)
void zcash_signing_abort(void) {}
#endif
