/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 KeepKey
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

/* Confirm a single parsed instruction */
static bool solana_confirmInstruction(const SolanaParsedInstruction* pi,
                                      const SolanaSignTx* msg, uint8_t idx,
                                      uint8_t total) {
  char title[32];
  snprintf(title, sizeof(title), "Instr %d/%d", idx + 1, total);

  switch (pi->type) {
    case SOL_INSTR_SYSTEM_TRANSFER: {
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Send %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_SYSTEM_CREATE_ACCOUNT: {
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Create account with %s?", amount_str);
    }

    case SOL_INSTR_SYSTEM_ADVANCE_NONCE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Advance nonce account?");

    case SOL_INSTR_SYSTEM_WITHDRAW_NONCE: {
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw nonce %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_SYSTEM_INITIALIZE_NONCE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Initialize nonce account?");

    case SOL_INSTR_SYSTEM_AUTHORIZE_NONCE: {
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize nonce to %s?", auth_str);
    }

    case SOL_INSTR_SYSTEM_ASSIGN: {
      char prog_str[45];
      solana_pubkeyToStr(pi->extra, prog_str, sizeof(prog_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Assign account to %s?", prog_str);
    }

    case SOL_INSTR_SYSTEM_ALLOCATE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Allocate %llu bytes?",
                     (unsigned long long)pi->extra_value);

    case SOL_INSTR_TOKEN_TRANSFER: {
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));

      const SolanaTokenInfo* ti = NULL;
      if (pi->has_mint && msg) {
        ti = solana_findTokenInfo(msg, pi->mint);
      }

      if (ti && ti->has_symbol && ti->has_decimals) {
        char amount_str[48];
        solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount,
                                 ti->symbol, (uint8_t)ti->decimals);
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                       "Send %s to %s?", amount_str, to_str);
      } else {
        char amount_str[32];
        snprintf(amount_str, sizeof(amount_str), "%llu tokens",
                 (unsigned long long)pi->amount);
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                       "Send %s to %s?", amount_str, to_str);
      }
    }

    case SOL_INSTR_TOKEN_TRANSFER_CHECKED: {
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));

      /* For TransferChecked, decimals come from the signed instruction
       * bytes (pi->extra_u8) — host-supplied ti->decimals is untrusted. */
      const SolanaTokenInfo* ti = NULL;
      if (pi->has_mint && msg) {
        ti = solana_findTokenInfo(msg, pi->mint);
      }

      const char* symbol = (ti && ti->has_symbol) ? ti->symbol : NULL;
      if (symbol) {
        char amount_str[48];
        solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount,
                                 symbol, pi->extra_u8);
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                       "Send %s to %s?", amount_str, to_str);
      } else {
        char amount_str[32];
        snprintf(amount_str, sizeof(amount_str), "%llu tokens",
                 (unsigned long long)pi->amount);
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                       "Send %s to %s?", amount_str, to_str);
      }
    }

    case SOL_INSTR_TOKEN_APPROVE: {
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Approve %llu tokens to %s?",
                     (unsigned long long)pi->amount, to_str);
    }

    case SOL_INSTR_TOKEN_REVOKE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Revoke token approval?");

    case SOL_INSTR_TOKEN_SET_AUTHORITY: {
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set token authority to %s?", auth_str);
    }

    case SOL_INSTR_TOKEN_MINT_TO:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Mint %llu tokens?", (unsigned long long)pi->amount);

    case SOL_INSTR_TOKEN_BURN:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Burn %llu tokens?", (unsigned long long)pi->amount);

    case SOL_INSTR_TOKEN_CLOSE_ACCOUNT: {
      /* Closing a (wrapped-SOL) token account sweeps its lamports to the
       * destination — show it, or an attacker routes the rent elsewhere. */
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Close token account, send balance to %s?", to_str);
    }

    case SOL_INSTR_TOKEN_FREEZE_ACCOUNT:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Freeze token account?");

    case SOL_INSTR_TOKEN_THAW_ACCOUNT:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Thaw token account?");

    case SOL_INSTR_TOKEN_SYNC_NATIVE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Sync wrapped SOL?");

    case SOL_INSTR_STAKE_DELEGATE: {
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Delegate stake?");
    }

    case SOL_INSTR_STAKE_WITHDRAW: {
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw %s from stake?", amount_str);
    }

    case SOL_INSTR_STAKE_AUTHORIZE: {
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize stake to %s?", auth_str);
    }

    case SOL_INSTR_STAKE_SPLIT: {
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Split stake by %s?", amount_str);
    }

    case SOL_INSTR_STAKE_DEACTIVATE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Deactivate stake?");

    case SOL_INSTR_STAKE_MERGE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Merge stake accounts?");

    case SOL_INSTR_VOTE_AUTHORIZE: {
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize vote to %s?", auth_str);
    }

    case SOL_INSTR_VOTE_WITHDRAW: {
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw vote %s?", amount_str);
    }

    case SOL_INSTR_VOTE_UPDATE_VALIDATOR: {
      char validator_str[45];
      solana_pubkeyToStr(pi->extra, validator_str, sizeof(validator_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Update validator to %s?", validator_str);
    }

    case SOL_INSTR_VOTE_UPDATE_COMMISSION:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set vote commission to %u%%?", pi->extra_u8);

    case SOL_INSTR_ATA_CREATE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Create associated token account?");

    case SOL_INSTR_COMPUTE_BUDGET_HEAP_FRAME:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set heap frame to %llu bytes?",
                     (unsigned long long)pi->extra_value);

    case SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set compute unit limit to %llu?",
                     (unsigned long long)pi->extra_value);

    case SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set compute unit price to %llu?",
                     (unsigned long long)pi->extra_value);

    case SOL_INSTR_COMPUTE_BUDGET_LOADED_ACCOUNTS_SIZE:
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set loaded account data to %llu bytes?",
                     (unsigned long long)pi->extra_value);

    case SOL_INSTR_MEMO: {
      /* Show the memo body — swap intents (e.g. THORChain '=:ETH.ETH:...')
       * ride in the memo, so hiding it hides where the funds go next. */
      bool printable = pi->data_len > 0;
      for (uint16_t i = 0; i < pi->data_len; i++) {
        if (pi->data[i] < 0x20 || pi->data[i] > 0x7e) {
          printable = false;
          break;
        }
      }
      if (printable && pi->data_len <= 114) {
        return confirm(ButtonRequestType_ButtonRequest_ConfirmMemo, title,
                       "Memo: %.*s", (int)pi->data_len, pi->data);
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmMemo, title,
                     "Memo attached (%u bytes)", (unsigned)pi->data_len);
    }

    case SOL_INSTR_UNKNOWN:
    default: {
      char prog_str[45];
      solana_pubkeyToStr(pi->program_id, prog_str, sizeof(prog_str));
      return confirm(ButtonRequestType_ButtonRequest_SignTx, title,
                     "Unknown instruction to program %s. "
                     "Cannot verify contents.",
                     prog_str);
    }
  }
}

/* Validate Solana derivation path: m/44'/501'/account'[/change'] */
static bool solana_pathIsStandard(const uint32_t* path, size_t count) {
  if (count < 3 || count > 4) return false;
  if (path[0] != (0x80000000 | 44)) return false;  /* 44' */
  if (path[1] != (0x80000000 | 501)) return false; /* 501' */
  for (size_t i = 2; i < count; i++) {
    if (!(path[i] & 0x80000000)) return false; /* must be hardened */
  }
  return true;
}

/* Verify derived pubkey appears in tx accounts[0..num_required_sigs) */
static bool solana_signerInTx(const uint8_t* pubkey, const SolanaParsedTx* tx) {
  for (uint8_t i = 0; i < tx->num_required_sigs && i < tx->num_accounts; i++) {
    if (memcmp(pubkey, tx->accounts[i], SOL_PUBKEY_SIZE) == 0) return true;
  }
  return false;
}

void fsm_msgSolanaGetAddress(const SolanaGetAddress* msg) {
  RESP_INIT(SolanaAddress);

  CHECK_INITIALIZED
  CHECK_PIN

  /* Path validation: warn on non-standard derivation */
  if (!solana_pathIsStandard(msg->address_n, msg->address_n_count)) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING",
                 "Non-standard Solana derivation path. Continue?")) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  /* Solana address = raw Base58 of the 32-byte Ed25519 public key.
   * node->public_key is 33 bytes (0x00 prefix + 32 bytes for Ed25519).
   * Use b58enc() for raw base58 encoding (no checksum). */
  char address[45];
  size_t addr_len = sizeof(address);
  if (solana_base58_encode(node->public_key + 1, SOL_PUBKEY_SIZE, address,
                           &addr_len)) {
    resp->has_address = true;
    strncpy(resp->address, address, sizeof(resp->address) - 1);
  } else {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Address encoding failed"));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    if (!confirm_ethereum_address("Solana", resp->address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show address cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_SolanaAddress, resp);
  layoutHome();
}

void fsm_msgSolanaSignTx(const SolanaSignTx* msg) {
  RESP_INIT(SolanaSignedTx);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_raw_tx || msg->raw_tx.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing raw_tx"));
    layoutHome();
    return;
  }

  /* Path validation: warn on non-standard derivation */
  if (!solana_pathIsStandard(msg->address_n, msg->address_n_count)) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING",
                 "Non-standard Solana derivation path. Continue?")) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  /* Classify transaction for verified vs opaque signing UX */
  SolanaParsedTx parsed;
  SolanaTxReview tx_review =
      solana_inspectTx(msg->raw_tx.bytes, msg->raw_tx.size, &parsed);

  /* Signer verification: derived key must be a required signer.
   * For verified txs this is mandatory. For opaque txs we still check
   * when we were able to parse the header (num_accounts > 0). */
  if (tx_review == SOL_TX_REVIEW_VERIFIED ||
      (tx_review == SOL_TX_REVIEW_OPAQUE && parsed.num_accounts > 0)) {
    if (!solana_signerInTx(node->public_key + 1, &parsed)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Derived key is not a signer for this tx"));
      layoutHome();
      return;
    }
  }

  if (tx_review == SOL_TX_REVIEW_VERIFIED) {
    /* Per-instruction confirmation for fully verified messages */
    for (uint8_t i = 0; i < parsed.num_instructions; i++) {
      if (!solana_confirmInstruction(&parsed.instructions[i], msg, i,
                                     parsed.num_instructions)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
    }
  } else if (tx_review == SOL_TX_REVIEW_OPAQUE) {
    /* Unsupported or opaque message: allow explicit blind-sign only. */
    if (!storage_isPolicyEnabled("AdvancedMode")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Enable AdvancedMode to blind-sign"));
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Blind Sign",
                 "Sign unverified Solana transaction? "
                 "The device cannot fully verify the contents.")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Malformed Solana transaction"));
    layoutHome();
    return;
  }

  /* Final confirmation */
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Solana",
               "Sign this Solana transaction?")) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
    layoutHome();
    return;
  }

  if (!solana_signTx(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_SolanaSignedTx, resp);
  layoutHome();
}

void fsm_msgSolanaSignMessage(const SolanaSignMessage* msg) {
  RESP_INIT(SolanaMessageSignature);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_message || msg->message.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing message"));
    layoutHome();
    return;
  }

  /* Solana "message" signing has no domain separation: the signed bytes
   * are indistinguishable from a transaction message on the network.
   * If the payload actually parses as a fully-verifiable Solana
   * transaction, treat it as one — clear-sign it per instruction instead
   * of blind-signing a hex blob. Wallet integrations sign versioned (v0)
   * swap transactions through this message, so this is the path that
   * turns swap blind-signing into clear-signing. */
  /* Note: solana_inspectTx tolerates a 0x00 signature-count prefix, but
   * here the signature covers the exact message bytes — only a payload
   * that IS a tx message from byte 0 may be displayed as one. */
  SolanaParsedTx parsed;
  bool is_verified_tx =
      msg->message.bytes[0] != 0 &&
      solana_inspectTx(msg->message.bytes, msg->message.size, &parsed) ==
          SOL_TX_REVIEW_VERIFIED;

  /* AdvancedMode gate for anything we cannot verify: a malicious dApp
   * could craft a "message" that is also a valid tx.
   * See: https://github.com/trezor/trezor-firmware/issues/4371
   * Same gate as ETH blind-signing. Fully verified transactions are
   * clear-signed below and need no gate — the user sees the contents. */
  if (!is_verified_tx && !storage_isPolicyEnabled("AdvancedMode")) {
    (void)review(ButtonRequestType_ButtonRequest_Other, "Blocked",
                 "Solana message signing is experimental. "
                 "Enable AdvancedMode in device settings.");
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Message signing disabled by policy"));
    layoutHome();
    return;
  }

  /* Path validation: warn on non-standard derivation */
  if (!solana_pathIsStandard(msg->address_n, msg->address_n_count)) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING",
                 "Non-standard Solana derivation path. Continue?")) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  if (is_verified_tx) {
    /* Clear-sign path: same rules as SolanaSignTx. */
    if (!solana_signerInTx(node->public_key + 1, &parsed)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Derived key is not a signer for this tx"));
      layoutHome();
      return;
    }
    for (uint8_t i = 0; i < parsed.num_instructions; i++) {
      if (!solana_confirmInstruction(&parsed.instructions[i], NULL, i,
                                     parsed.num_instructions)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
    }
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Solana",
                 "Sign this Solana transaction?")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else /* blind message path */
  /* Always require on-device confirmation (matches Ethereum behavior).
   * Display message content if printable, hex preview otherwise. */
  {
    char msgBuf[129] = {0};
    const char* typeLabel;
    bool printable = true;
    for (unsigned i = 0; i < msg->message.size; i++) {
      if (msg->message.bytes[i] < 0x20 || msg->message.bytes[i] > 0x7e) {
        printable = false;
        break;
      }
    }
    if (printable && msg->message.size <= sizeof(msgBuf) - 1) {
      typeLabel = "Sign Message";
      memcpy(msgBuf, msg->message.bytes, msg->message.size);
      msgBuf[msg->message.size] = '\0';
    } else {
      typeLabel = "Sign Bytes";
      /* Show hex preview (up to 64 hex chars = 32 bytes) */
      unsigned show = msg->message.size;
      if (show > 32) show = 32;
      for (unsigned i = 0; i < show; i++) {
        snprintf(&msgBuf[2 * i], 3, "%02x", msg->message.bytes[i]);
      }
      msgBuf[2 * show] = '\0';
      if (msg->message.size > 32) {
        snprintf(&msgBuf[64], sizeof(msgBuf) - 64, "... (%u bytes)",
                 (unsigned)msg->message.size);
      }
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _(typeLabel),
                 "%s", msgBuf)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  }

  /* Ed25519 sign */
  uint8_t sig[SOL_SIG_SIZE];
  ed25519_sign(msg->message.bytes, msg->message.size, node->private_key,
               node->public_key + 1, sig);

  resp->has_signature = true;
  resp->signature.size = SOL_SIG_SIZE;
  memcpy(resp->signature.bytes, sig, SOL_SIG_SIZE);

  resp->has_public_key = true;
  resp->public_key.size = SOL_PUBKEY_SIZE;
  memcpy(resp->public_key.bytes, node->public_key + 1, SOL_PUBKEY_SIZE);

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_SolanaMessageSignature, resp);
  layoutHome();
}

void fsm_msgSolanaSignOffchainMessage(const SolanaSignOffchainMessage* msg) {
  RESP_INIT(SolanaOffchainMessageSignature);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_message || msg->message.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing message"));
    layoutHome();
    return;
  }

  /* Validate format upfront so the user sees a meaningful error rather
   * than a generic signing failure. The envelope's 0xFF prefix provides
   * the domain separation that bare SolanaSignMessage lacks, so NO
   * AdvancedMode gate is required here — that fence was a band-aid for
   * the missing envelope. */
  uint32_t format = msg->has_message_format ? msg->message_format : 0;
  if (format != 0 && format != 1) {
    fsm_sendFailure(
        FailureType_Failure_Other,
        _("Off-chain format 2 (extended UTF-8) not supported on device"));
    layoutHome();
    return;
  }

  uint32_t version = msg->has_version ? msg->version : 0;
  if (version != 0) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Unsupported off-chain message version"));
    layoutHome();
    return;
  }

  if (msg->message.size > 1212) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Off-chain message exceeds 1212-byte limit"));
    layoutHome();
    return;
  }

  /* Path validation: warn on non-standard derivation, mirroring the
   * existing SolanaSignMessage handler. */
  if (!solana_pathIsStandard(msg->address_n, msg->address_n_count)) {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING",
                 "Non-standard Solana derivation path. Continue?")) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  HDNode* node = fsm_getDerivedNode(ED25519_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  /* Confirm dialog. Format 0 (ASCII) is always renderable; format 1
   * (UTF-8 limited) we render as printable bytes only — non-printable
   * sequences fall through to a hex preview to avoid encoding
   * surprises on the OLED. */
  {
    char msgBuf[129] = {0};
    const char* typeLabel;
    bool printable = true;
    for (unsigned i = 0; i < msg->message.size; i++) {
      if (msg->message.bytes[i] < 0x20 || msg->message.bytes[i] > 0x7e) {
        printable = false;
        break;
      }
    }
    if (printable && msg->message.size <= sizeof(msgBuf) - 1) {
      typeLabel = "Off-chain Message";
      memcpy(msgBuf, msg->message.bytes, msg->message.size);
      msgBuf[msg->message.size] = '\0';
    } else {
      typeLabel = "Off-chain Bytes";
      unsigned show = msg->message.size;
      if (show > 32) show = 32;
      for (unsigned i = 0; i < show; i++) {
        snprintf(&msgBuf[2 * i], 3, "%02x", msg->message.bytes[i]);
      }
      msgBuf[2 * show] = '\0';
      if (msg->message.size > 32) {
        snprintf(&msgBuf[64], sizeof(msgBuf) - 64, "... (%u bytes)",
                 (unsigned)msg->message.size);
      }
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _(typeLabel),
                 "%s", msgBuf)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  }

  if (!solana_offchain_message_sign(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Off-chain message signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_SolanaOffchainMessageSignature, resp);
  layoutHome();
}
