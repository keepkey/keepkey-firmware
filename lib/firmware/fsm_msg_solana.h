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

/* Confirm one labelled account address on its own screen. Factoring this keeps
 * the many "which account is being acted on" disclosures small (ROM matters on
 * the zcash-privacy variant). Returns false if the user rejects. */
static bool solana_confirm_account(const char* title, const char* label,
                                   const uint8_t key[SOL_PUBKEY_SIZE]) {
  char s[45];
  solana_pubkeyToStr(key, s, sizeof(s));
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title, "%s\n%s",
                 label, s);
}

/* A host-supplied token symbol is untrusted and only length-capped by the
 * proto. Reject anything but printable ASCII so it cannot inject newlines or
 * control bytes that push the mint or recipient off the confirm screen. */
static bool solana_symbol_is_safe(const char* sym) {
  if (!sym || sym[0] == '\0') return false;
  for (const char* p = sym; *p; p++) {
    if ((uint8_t)*p < 0x20 || (uint8_t)*p > 0x7e) return false;
  }
  return true;
}

static bool solana_confirm_memo(const char* title, const uint8_t* s,
                                uint16_t len) {
  return confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo, title, s,
                       len);
}

/* Priority fee = ceil(cu_price_micro_lamports * cu_limit / 1e6) lamports, and
 * it is charged even if the transaction fails. Compute-budget instructions show
 * only raw CU price/limit with no units, so a malicious host could bury a large
 * SOL loss there. When the tx sets a CU price, show the fee payer and the
 * MAXIMUM priority fee in SOL (using the 1.4M-CU protocol cap when no explicit
 * limit is set, so the figure is never an understatement). Returns false on
 * user reject. */
static bool solana_confirm_priority_fee(const SolanaParsedTx* tx,
                                        const uint8_t* fee_payer) {
  uint64_t price = 0;
  bool have_price = false;
  uint64_t cu_limit = 0;
  bool have_limit = false;
  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* pi = &tx->instructions[i];
    if (pi->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE) {
      price = pi->extra_value;
      have_price = true;
    } else if (pi->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT) {
      cu_limit = pi->extra_value;
      have_limit = true;
    }
  }
  if (!have_price || price == 0) {
    return true; /* no priority fee to disclose */
  }
  const uint64_t kMaxCuLimit = 1400000u; /* Solana per-tx CU cap */
  uint64_t limit = have_limit ? cu_limit : kMaxCuLimit;

  /* Overflow-safe ceil(price*limit/1e6); false => the fee exceeds u64 lamports
   * (>1.8e10 SOL) — refuse to sign rather than display a wrapped/zero figure.
   */
  uint64_t lamports = 0;
  if (!solana_priority_fee_lamports(price, limit, &lamports)) {
    (void)confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Fee",
                  "Priority fee too large to display. Refusing to sign.");
    return false;
  }
  char fee_str[40];
  solana_formatAmount(fee_str, sizeof(fee_str), lamports);
  if (fee_payer) {
    char payer_str[45];
    solana_pubkeyToStr(fee_payer, payer_str, sizeof(payer_str));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Fee",
                 "Fee payer\n%s", payer_str)) {
      return false;
    }
  }
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Fee",
                 "Max priority fee\n%s", fee_str);
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
      return solana_confirm_account(title, "Advance nonce account", pi->from);

    case SOL_INSTR_SYSTEM_WITHDRAW_NONCE: {
      /* Withdrawing the full balance can destroy the nonce account — show it.
       */
      if (!solana_confirm_account(title, "Nonce account", pi->from)) {
        return false;
      }
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw nonce %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_SYSTEM_INITIALIZE_NONCE: {
      if (!solana_confirm_account(title, "Initialize nonce account",
                                  pi->from)) {
        return false;
      }
      /* Show the nonce authority being set — it can later advance/withdraw. */
      char auth_str[45];
      solana_pubkeyToStr(pi->authority, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Nonce authority %s?", auth_str);
    }

    case SOL_INSTR_SYSTEM_AUTHORIZE_NONCE: {
      /* Show WHICH nonce account is rekeyed, not just the new authority. */
      if (!solana_confirm_account(title, "Nonce account", pi->from)) {
        return false;
      }
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize nonce to %s?", auth_str);
    }

    case SOL_INSTR_SYSTEM_ASSIGN: {
      /* Assign hands control of an account to a program — show WHICH account,
       * not just the new owner. */
      if (!solana_confirm_account(title, "Assign account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "to owner program", pi->extra);
    }

    case SOL_INSTR_SYSTEM_ALLOCATE: {
      if (!solana_confirm_account(title, "Allocate for account", pi->from)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Allocate %llu bytes?",
                     (unsigned long long)pi->extra_value);
    }

    case SOL_INSTR_TOKEN_TRANSFER: {
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));

      const SolanaTokenInfo* ti = NULL;
      if (pi->has_mint && msg) {
        ti = solana_findTokenInfo(msg, pi->mint);
      }

      /* The mint is the only authenticated token identity. Show it on its own
       * screen — a host-controlled symbol shares no line with it, so it cannot
       * push the mint off-view. */
      if (pi->has_mint) {
        char mint_str[45];
        solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Token mint\n%s", mint_str)) {
          return false;
        }
      }

      /* Use the claimed symbol only when it is safe printable text; otherwise a
       * raw token count, so an unvalidated symbol cannot manipulate the amount
       * screen (the mint above still identifies the token). */
      if (ti && ti->has_symbol && ti->has_decimals &&
          solana_symbol_is_safe(ti->symbol)) {
        char amount_str[48];
        solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount,
                                 ti->symbol, (uint8_t)ti->decimals);
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                       "Send %s to %s?", amount_str, to_str);
      }
      char amount_str[32];
      snprintf(amount_str, sizeof(amount_str), "%llu tokens",
               (unsigned long long)pi->amount);
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Send %s to %s?", amount_str, to_str);
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

      /* Decide symbol trust before drawing the mint screen so its label can say
       * whether the symbol is attested. Trust rules:
       *  - attestation present + verifies against a loaded signer -> trusted;
       *  - attestation present + INVALID -> reject the symbol entirely (an
       *    attacker offered a bad signature; never fall back to the claim);
       *  - no attestation (today's hosts) -> show the symbol next to the
       *    always-authenticated mint (unchanged behavior). */
      const char* symbol = NULL;
      bool symbol_verified = false;
      if (ti && ti->has_symbol && solana_symbol_is_safe(ti->symbol)) {
        if (ti->has_signature) {
          /* Trust the symbol only if the attestation verifies AND the attested
           * decimals equal the signed instruction's decimals (pi->extra_u8) —
           * otherwise the attested (mint,decimals,symbol) tuple disagrees with
           * the transaction being signed and must not earn "verified". */
          if (solana_token_info_trusted(ti) && ti->decimals == pi->extra_u8) {
            symbol = ti->symbol;
            symbol_verified = true;
          }
        } else {
          symbol = ti->symbol;
        }
      }

      /* Mint on its own screen (see TOKEN_TRANSFER): the authenticated identity
       * cannot be pushed off-view by a host-controlled symbol. */
      if (pi->has_mint) {
        char mint_str[45];
        solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Token mint\n%s", mint_str)) {
          return false;
        }
      }

      /* Name WHO attested the symbol, with the signer's fingerprint — aliases
       * are host-chosen and not unique, so the fingerprint is what actually
       * identifies the key. symbol_verified implies a signer is loaded for this
       * key_id (solana_token_info_trusted verified against it), so both
       * resolve; there is no "unknown" verified case. */
      if (symbol_verified) {
        const char* alias = signed_metadata_signer_alias(ti->signer_key_id);
        char fp[METADATA_FINGERPRINT_LEN] = {0};
        signed_metadata_signer_fingerprint((uint8_t)ti->signer_key_id, fp);
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Token \"%s\"\nby %s %s", symbol, alias ? alias : "",
                     fp)) {
          return false;
        }
      }

      if (symbol) {
        char amount_str[48];
        solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount,
                                 symbol, pi->extra_u8);
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                       "Send %s to %s?", amount_str, to_str);
      }
      char amount_str[32];
      snprintf(amount_str, sizeof(amount_str), "%llu tokens",
               (unsigned long long)pi->amount);
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Send %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_TOKEN_APPROVE: {
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Approve %llu tokens to %s?",
                     (unsigned long long)pi->amount, to_str);
    }

    case SOL_INSTR_TOKEN_REVOKE:
      return solana_confirm_account(title, "Revoke approval on account",
                                    pi->from);

    case SOL_INSTR_TOKEN_SET_AUTHORITY: {
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set token authority to %s?", auth_str);
    }

    case SOL_INSTR_TOKEN_MINT_TO: {
      /* Show the mint (which token) and the recipient, not just the amount. */
      char mint_str[45];
      char to_str[45];
      solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                   "Mint token\n%s", mint_str)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Mint %llu\nto %s?", (unsigned long long)pi->amount,
                     to_str);
    }

    case SOL_INSTR_TOKEN_BURN: {
      /* Show the mint (which token) and the source account burned from. */
      char mint_str[45];
      char from_str[45];
      solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
      solana_pubkeyToStr(pi->from, from_str, sizeof(from_str));
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                   "Burn token\n%s", mint_str)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Burn %llu\nfrom %s?", (unsigned long long)pi->amount,
                     from_str);
    }

    case SOL_INSTR_TOKEN_CLOSE_ACCOUNT: {
      /* Closing sweeps the account's ENTIRE lamport balance (which the device
       * cannot see, e.g. wrapped SOL) to the destination — show both the
       * account being closed and where its balance goes. */
      if (!solana_confirm_account(title, "Close token account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "send balance to", pi->to);
    }

    case SOL_INSTR_TOKEN_FREEZE_ACCOUNT: {
      /* Show the account frozen AND its mint (freeze authority is per-mint). */
      if (!solana_confirm_account(title, "Freeze token account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "of mint", pi->mint);
    }

    case SOL_INSTR_TOKEN_THAW_ACCOUNT: {
      if (!solana_confirm_account(title, "Thaw token account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "of mint", pi->mint);
    }

    case SOL_INSTR_TOKEN_SYNC_NATIVE:
      return solana_confirm_account(title, "Sync wrapped SOL account",
                                    pi->from);

    case SOL_INSTR_STAKE_DELEGATE: {
      /* Show which stake account is delegated, not just the vote account — a
       * host could delegate a different stake account of the same authority. */
      if (!solana_confirm_account(title, "Delegate stake account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "to vote account", pi->to);
    }

    case SOL_INSTR_STAKE_WITHDRAW: {
      /* Show WHICH stake account is drained (a host could substitute another of
       * the same authority) and the recipient. */
      if (!solana_confirm_account(title, "Withdraw from stake", pi->from)) {
        return false;
      }
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw %s\nto %s?", amount_str, to_str);
    }

    case SOL_INSTR_STAKE_AUTHORIZE: {
      /* Show WHICH stake account is rekeyed (a host could substitute another of
       * the same signer) and which power is handed over (staker vs withdrawer).
       */
      if (!solana_confirm_account(title, "Stake account", pi->from)) {
        return false;
      }
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      const char* role = pi->extra_u8 == 0 ? "staker" : "withdrawer";
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize %s\nto %s?", role, auth_str);
    }

    case SOL_INSTR_STAKE_SPLIT: {
      /* Show the source stake account being split, and the destination. */
      if (!solana_confirm_account(title, "Split from stake", pi->from)) {
        return false;
      }
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Split %s\nto %s?", amount_str, to_str);
    }

    case SOL_INSTR_STAKE_DEACTIVATE:
      return solana_confirm_account(title, "Deactivate stake account",
                                    pi->from);

    case SOL_INSTR_STAKE_MERGE: {
      /* Show source and destination — merge moves the source's stake into the
       * destination account. */
      char from_str[45];
      char to_str[45];
      solana_pubkeyToStr(pi->from, from_str, sizeof(from_str));
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                   "Merge stake from\n%s", from_str)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Merge stake into\n%s?", to_str);
    }

    case SOL_INSTR_VOTE_AUTHORIZE: {
      /* Show WHICH vote account is rekeyed; Voter vs Withdrawer both matter
       * (the withdrawer can move the vote account's SOL). */
      if (!solana_confirm_account(title, "Vote account", pi->from)) {
        return false;
      }
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      const char* role = pi->extra_u8 == 0 ? "voter" : "withdrawer";
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize vote %s\nto %s?", role, auth_str);
    }

    case SOL_INSTR_VOTE_WITHDRAW: {
      /* Show the source vote account and the recipient. */
      if (!solana_confirm_account(title, "Withdraw from vote", pi->from)) {
        return false;
      }
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw vote %s\nto %s?", amount_str, to_str);
    }

    case SOL_INSTR_VOTE_UPDATE_VALIDATOR: {
      /* The new validator is the account (pi->extra now holds account index 1,
       * not fabricated instruction bytes); show the vote account too. */
      if (!solana_confirm_account(title, "Vote account", pi->from)) {
        return false;
      }
      return solana_confirm_account(title, "New validator identity", pi->extra);
    }

    case SOL_INSTR_VOTE_UPDATE_COMMISSION: {
      if (!solana_confirm_account(title, "Vote account", pi->from)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set vote commission to %u%%?", pi->extra_u8);
    }

    case SOL_INSTR_ATA_CREATE: {
      /* Show the wallet owner and the token mint the new account is for. */
      char owner_str[45];
      char mint_str[45];
      solana_pubkeyToStr(pi->authority, owner_str, sizeof(owner_str));
      solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                   "Create token account\nfor %s", owner_str)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Token account mint\n%s?", mint_str);
    }

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

    case SOL_INSTR_MEMO:
      /* Page the FULL memo — swap intents (e.g. THORChain '=:ETH.ETH:...') ride
       * in the memo, so a byte-count summary would hide where the funds go.
       * Printable memos page as text, binary memos page as hex; nothing is
       * hidden and the tx stays clear-signable regardless of length. */
      return solana_confirm_memo(title, pi->data, pi->data_len);

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

/* The single verified-transaction confirmation flow shared by BOTH
 * SolanaSignTx and SolanaSignMessage (transaction-shaped messages are equally
 * broadcastable), so their security screens — per-instruction disclosure AND
 * the priority-fee screen — cannot drift apart. `msg` is NULL on the
 * SignMessage path (host token symbols are unavailable there). Returns false if
 * the user rejects any screen. */
static bool solana_confirm_verified_tx(const SolanaParsedTx* parsed,
                                       const SolanaSignTx* msg) {
  for (uint8_t i = 0; i < parsed->num_instructions; i++) {
    if (!solana_confirmInstruction(&parsed->instructions[i], msg, i,
                                   parsed->num_instructions)) {
      return false;
    }
  }
  return solana_confirm_priority_fee(
      parsed, parsed->num_accounts > 0 ? parsed->accounts[0] : NULL);
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
    /* Per-instruction disclosure + priority fee, shared with SignMessage. */
    if (!solana_confirm_verified_tx(&parsed, msg)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
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
  bool is_verified_tx = msg->message.bytes[0] != 0 &&
                        solana_inspectTx(msg->message.bytes, msg->message.size,
                                         &parsed) == SOL_TX_REVIEW_VERIFIED;

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
    /* Same verified-tx flow as SolanaSignTx (incl. the priority-fee screen), so
     * a broadcastable transaction-shaped message can't dodge a security screen.
     * msg=NULL: host token symbols aren't provided on the message path. */
    if (!solana_confirm_verified_tx(&parsed, NULL)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Solana",
                 "Sign this Solana transaction?")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else if (!confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                            "Sign Solana Message", msg->message.bytes,
                            msg->message.size)) {
    /* AdvancedMode permits the opaque primitive, but every signed byte still
     * has to be reviewable; previews recreate the hidden-suffix bug. */
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
    layoutHome();
    return;
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

  if (!confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                     "Sign Solana Off-chain Message", msg->message.bytes,
                     msg->message.size)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
    layoutHome();
    return;
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
