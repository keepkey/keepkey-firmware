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

/* Put each signed identity on its own confirmation screen. Combining two
 * full Base58 keys into an action sentence makes truncation much harder to
 * notice and can render distinct instructions identically. */
static bool solana_confirmPubkey(const char* title, const char* label,
                                 const uint8_t key[SOL_PUBKEY_SIZE]) {
  char key_str[45];
  solana_pubkeyToStr(key, key_str, sizeof(key_str));
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title, "%s\n%s",
                 label, key_str);
}

/* Compute-budget prices are micro-lamports per compute unit. Raw price/limit
 * screens do not tell the user the SOL at risk, and the fee is charged even
 * when execution fails. Show the fee payer and a non-understated maximum,
 * using Solana's 1.4M-CU transaction cap when no explicit limit is present. */
static bool solana_confirmPriorityFee(const SolanaParsedTx* tx) {
  uint64_t price = 0;
  uint64_t limit = 1400000u;
  bool have_price = false;

  for (uint8_t i = 0; i < tx->num_instructions; i++) {
    const SolanaParsedInstruction* pi = &tx->instructions[i];
    if (pi->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_PRICE) {
      price = pi->extra_value;
      have_price = true;
    } else if (pi->type == SOL_INSTR_COMPUTE_BUDGET_UNIT_LIMIT) {
      limit = pi->extra_value;
    }
  }
  if (!have_price || price == 0) return true;

  uint64_t lamports = 0;
  if (!solana_priority_fee_lamports(price, limit, &lamports)) {
    (void)confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Fee",
                  "Priority fee too large to display. Refusing to sign.");
    return false;
  }

  if (tx->num_accounts > 0 &&
      !solana_confirmPubkey("Fee", "Fee payer", tx->accounts[0])) {
    return false;
  }

  char fee_str[40];
  solana_formatAmount(fee_str, sizeof(fee_str), lamports);
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Fee",
                 "Max priority fee\n%s", fee_str);
}

/* Confirm a single parsed instruction.
 *
 * Takes no SolanaSignTx on purpose: every value on these screens is decoded
 * from the bytes being signed. Nothing the host merely asserts is displayed,
 * so there is no untrusted string left to sanitise.
 *
 * recipient_owner is the one exception, and it is not an exception to the
 * rule: the caller accepts it only after re-deriving the associated-token
 * address from it ON DEVICE and finding that it equals the destination in the
 * signed bytes. A wrong owner cannot survive that derivation, so what is shown
 * is proven, not asserted. NULL when the host supplied nothing that matches. */
static bool solana_confirmInstruction(const SolanaParsedInstruction* pi,
                                      uint8_t idx, uint8_t total,
                                      const uint8_t* recipient_owner) {
  char title[32];
  snprintf(title, sizeof(title), "Instr %d/%d", idx + 1, total);

  switch (pi->type) {
    case SOL_INSTR_SYSTEM_TRANSFER: {
      if (!solana_confirmPubkey(title, "Funding account", pi->from)) {
        return false;
      }
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
      if (!solana_confirmPubkey(title, "Nonce account", pi->from)) return false;
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Advance nonce account?");

    case SOL_INSTR_SYSTEM_WITHDRAW_NONCE: {
      if (!solana_confirmPubkey(title, "Nonce account", pi->from)) return false;
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw nonce %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_SYSTEM_INITIALIZE_NONCE:
      if (!solana_confirmPubkey(title, "Nonce account", pi->from)) return false;
      if (!solana_confirmPubkey(title, "Nonce authority", pi->authority)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Initialize nonce account?");

    case SOL_INSTR_SYSTEM_AUTHORIZE_NONCE: {
      if (!solana_confirmPubkey(title, "Nonce account", pi->from)) return false;
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize nonce to %s?", auth_str);
    }

    case SOL_INSTR_SYSTEM_ASSIGN: {
      if (!solana_confirmPubkey(title, "Affected account", pi->from)) {
        return false;
      }
      char prog_str[45];
      solana_pubkeyToStr(pi->extra, prog_str, sizeof(prog_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Assign account to %s?", prog_str);
    }

    case SOL_INSTR_SYSTEM_ALLOCATE:
      if (!solana_confirmPubkey(title, "Affected account", pi->from)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Allocate %llu bytes?",
                     (unsigned long long)pi->extra_value);

    case SOL_INSTR_TOKEN_TRANSFER:
    case SOL_INSTR_TOKEN_TRANSFER_CHECKED: {
      if (!solana_confirmPubkey(title, "Source token account", pi->from)) {
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
      /* The destination in the signed bytes is a program-derived token
       * account, which the owner cannot recognise. When the host supplies the
       * wallet it belongs to AND that wallet re-derives to this exact account
       * on device, name it: the screen then carries the address the user
       * actually knows, beside the one being signed. */
      if (recipient_owner) {
        char owner_str[45];
        solana_pubkeyToStr(recipient_owner, owner_str, sizeof(owner_str));
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Token account of\n%s", owner_str)) {
          return false;
        }
      }

      char amount_str[64];
      solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount,
                               "tokens", pi->extra_u8);
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
      if (!solana_confirmPubkey(title, "Token account", pi->from)) return false;
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Revoke token approval?");

    case SOL_INSTR_TOKEN_SET_AUTHORITY: {
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set token authority to %s?", auth_str);
    }

    case SOL_INSTR_TOKEN_MINT_TO: {
      /* Same disclosure requirement as TOKEN_TRANSFER above: the mint and
       * recipient are the signed instruction's only identity, and both are
       * parsed -- show both, not just the raw amount. */
      if (pi->has_mint) {
        char mint_str[45];
        solana_pubkeyToStr(pi->mint, mint_str, sizeof(mint_str));
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Token mint\n%s", mint_str)) {
          return false;
        }
      }
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      char amount_str[64];
      if (pi->has_token_decimals) {
        solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount,
                                 "tokens", pi->extra_u8);
      } else {
        snprintf(amount_str, sizeof(amount_str), "%llu base units",
                 (unsigned long long)pi->amount);
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Mint %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_TOKEN_BURN: {
      if (!solana_confirmPubkey(title, "Source token account", pi->from)) {
        return false;
      }
      if (!solana_confirmPubkey(title, "Token mint", pi->mint)) return false;
      char amount_str[64];
      if (pi->has_token_decimals) {
        solana_formatTokenAmount(amount_str, sizeof(amount_str), pi->amount,
                                 "tokens", pi->extra_u8);
      } else {
        snprintf(amount_str, sizeof(amount_str), "%llu base units",
                 (unsigned long long)pi->amount);
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Burn %s?", amount_str);
    }

    case SOL_INSTR_TOKEN_CLOSE_ACCOUNT:
      if (!solana_confirmPubkey(title, "Close token account", pi->from)) {
        return false;
      }
      if (!solana_confirmPubkey(title, "Refund destination", pi->to)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Close token account?");

    case SOL_INSTR_TOKEN_FREEZE_ACCOUNT:
      if (!solana_confirmPubkey(title, "Freeze token account", pi->from)) {
        return false;
      }
      if (!solana_confirmPubkey(title, "Token mint", pi->mint)) return false;
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Freeze token account?");

    case SOL_INSTR_TOKEN_THAW_ACCOUNT:
      if (!solana_confirmPubkey(title, "Thaw token account", pi->from)) {
        return false;
      }
      if (!solana_confirmPubkey(title, "Token mint", pi->mint)) return false;
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Thaw token account?");

    case SOL_INSTR_TOKEN_SYNC_NATIVE:
      if (!solana_confirmPubkey(title, "Wrapped SOL account", pi->from)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Sync wrapped SOL?");

    case SOL_INSTR_STAKE_DELEGATE: {
      if (!solana_confirmPubkey(title, "Stake account", pi->from)) return false;
      if (!solana_confirmPubkey(title, "Validator vote account", pi->to)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Delegate stake?");
    }

    case SOL_INSTR_STAKE_WITHDRAW: {
      if (!solana_confirmPubkey(title, "Stake account", pi->from)) return false;
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw %s from stake to %s?", amount_str, to_str);
    }

    case SOL_INSTR_STAKE_AUTHORIZE: {
      if (!solana_confirmPubkey(title, "Stake account", pi->from)) return false;
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      /* StakeAuthorize enum: 0=Staker (can only redirect delegation),
         1=Withdrawer (can drain the entire stake balance) -- the two are not
         interchangeable risk, so the type must be disclosed. */
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize stake %s to %s?",
                     pi->extra_u8 == 1 ? "WITHDRAWER" : "staker", auth_str);
    }

    case SOL_INSTR_STAKE_SPLIT: {
      if (!solana_confirmPubkey(title, "Source stake account", pi->from)) {
        return false;
      }
      if (!solana_confirmPubkey(title, "Split destination", pi->to)) {
        return false;
      }
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Split stake by %s?", amount_str);
    }

    case SOL_INSTR_STAKE_DEACTIVATE:
      if (!solana_confirmPubkey(title, "Stake account", pi->from)) return false;
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Deactivate stake?");

    case SOL_INSTR_STAKE_MERGE:
      if (!solana_confirmPubkey(title, "Source stake account", pi->from)) {
        return false;
      }
      if (!solana_confirmPubkey(title, "Merge destination", pi->to)) {
        return false;
      }
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Merge stake accounts?");

    case SOL_INSTR_VOTE_AUTHORIZE: {
      if (!solana_confirmPubkey(title, "Vote account", pi->from)) return false;
      char auth_str[45];
      solana_pubkeyToStr(pi->extra, auth_str, sizeof(auth_str));
      /* VoteAuthorize enum: 0=Voter (can only redirect voting), 1=Withdrawer
         (can drain the vote account's balance) -- disclose which. */
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Authorize vote %s to %s?",
                     pi->extra_u8 == 1 ? "WITHDRAWER" : "voter", auth_str);
    }

    case SOL_INSTR_VOTE_WITHDRAW: {
      if (!solana_confirmPubkey(title, "Vote account", pi->from)) return false;
      char amount_str[32];
      solana_formatAmount(amount_str, sizeof(amount_str), pi->lamports);
      char to_str[45];
      solana_pubkeyToStr(pi->to, to_str, sizeof(to_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Withdraw vote %s to %s?", amount_str, to_str);
    }

    case SOL_INSTR_VOTE_UPDATE_VALIDATOR: {
      if (!solana_confirmPubkey(title, "Vote account", pi->from)) return false;
      char validator_str[45];
      solana_pubkeyToStr(pi->extra, validator_str, sizeof(validator_str));
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Update validator to %s?", validator_str);
    }

    case SOL_INSTR_VOTE_UPDATE_COMMISSION:
      if (!solana_confirmPubkey(title, "Vote account", pi->from)) return false;
      return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                     "Set vote commission to %u%%?", pi->extra_u8);

    case SOL_INSTR_ATA_CREATE:
      if (!solana_confirmPubkey(title, "Funding account", pi->from)) {
        return false;
      }
      if (!solana_confirmPubkey(title, "Associated token acct", pi->to)) {
        return false;
      }
      if (!solana_confirmPubkey(title, "Token owner", pi->authority)) {
        return false;
      }
      if (!solana_confirmPubkey(title, "Token mint", pi->mint)) return false;
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

    case SOL_INSTR_MEMO:
      /* The memo is signed instruction data. Page the exact retained slice so
       * two memos with the same prefix cannot produce the same review. */
      return confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo,
                           "Solana Memo", pi->data, pi->data_len);

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

/* Render one structurally-complete schema instruction. Every value below is
 * read from the transaction bytes (or from the certified canonical LUT list
 * already installed in parsed.accounts); alias/fingerprint come from the root
 * certificate and are shown before the description. */
static bool solana_confirmSchemaInstruction(
    const SolanaInstrSchema* schema, const SolanaParsedTx* parsed,
    uint8_t ix_index, const char* alias,
    const char fingerprint[METADATA_FINGERPRINT_LEN]) {
  const SolanaParsedInstruction* ix = &parsed->instructions[ix_index];

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               "KeepKey ClearSign", "%s\nSigner %s", alias, fingerprint)) {
    return false;
  }
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               schema->program_name, "%s", schema->instruction_name)) {
    return false;
  }

  uint16_t off = schema->disc_len;
  for (uint8_t a = 0; a < schema->num_args; a++) {
    const SolanaSchemaArg* arg = &schema->args[a];
    char value[64] = {0};
    switch (arg->type) {
      case SOL_SCHEMA_ARG_U64:
      case SOL_SCHEMA_ARG_LAMPORTS: {
        uint64_t v = 0;
        for (uint8_t b = 0; b < 8; b++) {
          v |= ((uint64_t)ix->data[off + b]) << (8 * b);
        }
        if (arg->type == SOL_SCHEMA_ARG_LAMPORTS) {
          solana_formatAmount(value, sizeof(value), v);
        } else {
          snprintf(value, sizeof(value), "%llu", (unsigned long long)v);
        }
        break;
      }
      case SOL_SCHEMA_ARG_U8:
        snprintf(value, sizeof(value), "%u", (unsigned)ix->data[off]);
        break;
      case SOL_SCHEMA_ARG_PUBKEY: {
        size_t enc = sizeof(value);
        if (!solana_base58_encode(ix->data + off, SOL_PUBKEY_SIZE, value,
                                  &enc)) {
          return false;
        }
        break;
      }
      case SOL_SCHEMA_ARG_OPAQUE32:
        snprintf(value, sizeof(value), "%02x%02x%02x%02x...%02x%02x%02x%02x",
                 ix->data[off], ix->data[off + 1], ix->data[off + 2],
                 ix->data[off + 3], ix->data[off + 28], ix->data[off + 29],
                 ix->data[off + 30], ix->data[off + 31]);
        break;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, arg->label,
                 "%s", value)) {
      return false;
    }
    off += solana_schemaArgWidth(arg->type);
  }

  for (uint8_t a = 0; a < schema->num_accounts; a++) {
    const SolanaSchemaAccount* account = &schema->accounts[a];
    const uint8_t account_index = ix->acct_indices[account->index];
    char address[64];
    size_t enc = sizeof(address);
    if (account_index >= parsed->num_accounts ||
        !solana_base58_encode(parsed->accounts[account_index], SOL_PUBKEY_SIZE,
                              address, &enc) ||
        !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, account->label,
                 "%s", address)) {
      return false;
    }
  }
  return true;
}

static bool solana_confirmSchemaTransaction(
    const SolanaInstrSchema* schema, const SolanaParsedTx* parsed,
    uint8_t schema_ix, const char* alias,
    const char fingerprint[METADATA_FINGERPRINT_LEN]) {
  for (uint8_t i = 0; i < parsed->num_instructions; i++) {
    const bool ok = i == schema_ix ? solana_confirmSchemaInstruction(
                                         schema, parsed, i, alias, fingerprint)
                                   : solana_confirmInstruction(
                                         &parsed->instructions[i], i,
                                         parsed->num_instructions, NULL);
    if (!ok) return false;
  }
  return true;
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

typedef enum {
  SOL_SCHEMA_REVIEW_NONE = 0,
  SOL_SCHEMA_REVIEW_APPROVED,
  SOL_SCHEMA_REVIEW_CANCELLED,
} SolanaSchemaReviewResult;

/* Review an opaque instruction through a signed KKSOLSC1 descriptor. This is
 * annotation only: invalid or inapplicable metadata produces no screens, and
 * the caller still presents the ordinary blind-sign warning after an approved
 * schema review. */
static SolanaSchemaReviewResult solana_confirmAttestedSchema(
    const SolanaSignTx* msg, const SolanaParsedTx* tx) {
  if (!msg->has_schema_payload || msg->schema_payload.size == 0 ||
      !msg->has_schema_signature || msg->schema_signature.size != 64 ||
      !msg->has_schema_signer_key_id ||
      msg->schema_signer_key_id >= METADATA_MAX_KEYS) {
    return SOL_SCHEMA_REVIEW_NONE;
  }

  const uint8_t key_id = (uint8_t)msg->schema_signer_key_id;
  if (!signed_metadata_verify_attestation(
          key_id, msg->schema_payload.bytes, msg->schema_payload.size,
          msg->schema_signature.bytes, msg->schema_signature.size)) {
    return SOL_SCHEMA_REVIEW_NONE;
  }

  SolanaInstrSchema schema;
  uint8_t instruction_index = 0;
  if (!solana_parseInstrSchema(msg->schema_payload.bytes,
                               msg->schema_payload.size, &schema) ||
      !solana_schemaApplies(&schema, tx, &instruction_index)) {
    memzero(&schema, sizeof(schema));
    return SOL_SCHEMA_REVIEW_NONE;
  }

  const SolanaParsedInstruction* ix = &tx->instructions[instruction_index];
  for (uint8_t i = 0; i < schema.num_accounts; i++) {
    const uint8_t instruction_account = schema.accounts[i].index;
    if (!ix->acct_indices || instruction_account >= ix->num_acct_indices ||
        ix->acct_indices[instruction_account] >= tx->num_accounts) {
      memzero(&schema, sizeof(schema));
      return SOL_SCHEMA_REVIEW_NONE;
    }
  }

  char fingerprint[METADATA_FINGERPRINT_LEN];
  if (!signed_metadata_signer_fingerprint(key_id, fingerprint)) {
    fingerprint[0] = '\0';
  }
  const char* alias = signed_metadata_signer_alias(key_id);
  bool approved =
      confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Schema Source",
              "%s (%s) describes this instruction.\nNOT verified by KeepKey.",
              alias ? alias : "Unknown signer", fingerprint);

  if (approved) {
    approved =
        confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Instruction",
                "%s\n%s", schema.program_name, schema.instruction_name);
  }

  char program_id[45];
  solana_pubkeyToStr(schema.program_id, program_id, sizeof(program_id));
  if (approved) {
    approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                       "Program ID", "%s", program_id);
  }

  char discriminator[2 * SOL_SCHEMA_DISC_MAX + 1] = {0};
  for (uint8_t i = 0; i < schema.disc_len; i++) {
    snprintf(discriminator + 2 * i, sizeof(discriminator) - 2 * i, "%02x",
             schema.disc[i]);
  }
  if (approved) {
    approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                       "Discriminator", "%s", discriminator);
  }

  const uint8_t* arg = ix->data + schema.disc_len;
  for (uint8_t i = 0; approved && i < schema.num_args; i++) {
    switch (schema.args[i].type) {
      case SOL_SCHEMA_ARG_U64:
      case SOL_SCHEMA_ARG_LAMPORTS: {
        uint64_t value = 0;
        for (uint8_t j = 0; j < 8; j++) {
          value |= ((uint64_t)arg[j]) << (8 * j);
        }
        if (schema.args[i].type == SOL_SCHEMA_ARG_LAMPORTS) {
          char amount[32];
          solana_formatAmount(amount, sizeof(amount), value);
          approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                             schema.args[i].label, "%s", amount);
        } else {
          approved =
              confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                      schema.args[i].label, "%llu", (unsigned long long)value);
        }
        arg += 8;
        break;
      }
      case SOL_SCHEMA_ARG_U8:
        approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           schema.args[i].label, "%u", (unsigned)*arg);
        arg++;
        break;
      case SOL_SCHEMA_ARG_PUBKEY: {
        char pubkey[45];
        solana_pubkeyToStr(arg, pubkey, sizeof(pubkey));
        approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                           schema.args[i].label, "%s", pubkey);
        arg += SOL_PUBKEY_SIZE;
        break;
      }
      case SOL_SCHEMA_ARG_OPAQUE32:
        approved = confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmOutput,
                                 schema.args[i].label, arg, 32);
        arg += 32;
        break;
    }
  }

  for (uint8_t i = 0; approved && i < schema.num_accounts; i++) {
    const uint8_t account_index = ix->acct_indices[schema.accounts[i].index];
    char account[45];
    solana_pubkeyToStr(tx->accounts[account_index], account, sizeof(account));
    approved = confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                       schema.accounts[i].label, "%s", account);
  }

  memzero(&schema, sizeof(schema));
  return approved ? SOL_SCHEMA_REVIEW_APPROVED : SOL_SCHEMA_REVIEW_CANCELLED;
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

  SolanaParsedTx parsed;
  SolanaInstrSchema schema;
  memset(&schema, 0, sizeof(schema));
  uint8_t schema_ix = 0;
  bool certified = false;
  bool runtime_schema = false;
  char signer_alias[CLEARSIGN_ALIAS_LEN + 1] = {0};
  char signer_fp[METADATA_FINGERPRINT_LEN] = {0};
  uint8_t lut_keys[SOL_MAX_LUT_ACCOUNTS][SOL_PUBKEY_SIZE];
  size_t lut_n = 0;

  const bool has_lut_material = msg->lut_account_count > 0 ||
                                msg->has_lut_signature ||
                                msg->has_lut_signer_key_id;
  const bool has_schema_material = msg->has_schema_payload ||
                                   msg->has_schema_signature ||
                                   msg->has_schema_signer_key_id;
  const bool has_certified_material =
      msg->has_clearsign_certificate ||
      (msg->has_lut_signer_key_id &&
       msg->lut_signer_key_id == METADATA_KEYID_DELEGATE) ||
      (msg->has_schema_signer_key_id &&
       msg->schema_signer_key_id == METADATA_KEYID_DELEGATE);

  /* Flatten nanopb repeated bytes once. Every caller hashes real 32-byte keys,
   * never the nanopb {size,bytes} wrapper. */
  bool lut_well_formed = msg->lut_account_count <= SOL_MAX_LUT_ACCOUNTS;
  for (size_t i = 0; lut_well_formed && i < msg->lut_account_count; i++) {
    if (msg->lut_account[i].size != SOL_PUBKEY_SIZE) {
      lut_well_formed = false;
      break;
    }
    memcpy(lut_keys[lut_n++], msg->lut_account[i].bytes, SOL_PUBKEY_SIZE);
  }

  SolanaTxReview tx_review = SOL_TX_REVIEW_MALFORMED;
  if (has_certified_material) {
    /* Certified ClearSign always requires one certificate-authorized schema.
     * A transaction-bound LUT proof is additionally mandatory exactly when
     * the signed v0 message contains lookup-table entries. Self-contained
     * legacy/v0 messages commit every account directly and therefore carry no
     * LUT material. Partial material, mixed runtime slots, bad scope/signature,
     * or a shape/proof mismatch is a hard failure; none may silently downgrade
     * to blind sign. */
    uint8_t delegate_pub[CLEARSIGN_PUBKEY_LEN];
    if (!msg->has_clearsign_certificate ||
        msg->clearsign_certificate.size != CLEARSIGN_CERT_LEN ||
        !has_schema_material || !msg->has_schema_payload ||
        !msg->has_schema_signature || !msg->has_schema_signer_key_id ||
        msg->schema_signer_key_id != METADATA_KEYID_DELEGATE) {
      memzero(node, sizeof(*node));
      memzero(delegate_pub, sizeof(delegate_pub));
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Incomplete certified Solana ClearSign proof"));
      layoutHome();
      return;
    }
    if (!clearsign_root_cert_delegate(msg->clearsign_certificate.bytes,
                                      msg->clearsign_certificate.size, 501,
                                      delegate_pub, signer_alias)) {
      memzero(node, sizeof(*node));
      memzero(delegate_pub, sizeof(delegate_pub));
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Invalid certified Solana certificate"));
      layoutHome();
      return;
    }
    signed_metadata_pubkey_fingerprint(delegate_pub, signer_fp);
    memzero(delegate_pub, sizeof(delegate_pub));

    if (has_lut_material) {
      if (!lut_well_formed || lut_n == 0 || !msg->has_lut_signature ||
          !msg->has_lut_signer_key_id ||
          msg->lut_signer_key_id != METADATA_KEYID_DELEGATE ||
          !solana_lut_accounts_certified(
              msg->raw_tx.bytes, msg->raw_tx.size,
              (const uint8_t (*)[32])lut_keys, lut_n,
              msg->clearsign_certificate.bytes, msg->clearsign_certificate.size,
              msg->lut_signature.bytes, msg->lut_signature.size)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid certified Solana LUT proof"));
        layoutHome();
        return;
      }
      tx_review = solana_inspectTxWithTrustedLut(
          msg->raw_tx.bytes, msg->raw_tx.size,
          (const uint8_t (*)[SOL_PUBKEY_SIZE])lut_keys, lut_n, &parsed);
    } else {
      tx_review =
          solana_inspectTx(msg->raw_tx.bytes, msg->raw_tx.size, &parsed);
    }

    if (tx_review == SOL_TX_REVIEW_MALFORMED ||
        /* A proof is required if and only if the message reaches outside its
         * signed static account list. This rejects both a schema-only request
         * for an ALT transaction and an unnecessary/suspicious LUT proof for
         * a self-contained transaction. */
        !solana_certifiedLutShapeMatches(&parsed, lut_n) ||
        !solana_parseInstrSchema(msg->schema_payload.bytes,
                                 msg->schema_payload.size, &schema) ||
        !clearsign_root_verify_delegate_attestation(
            msg->clearsign_certificate.bytes, msg->clearsign_certificate.size,
            501, msg->schema_payload.bytes, msg->schema_payload.size,
            msg->schema_signature.bytes, msg->schema_signature.size) ||
        !solana_schemaApplies(&schema, &parsed, &schema_ix)) {
      memzero(node, sizeof(*node));
      memzero(&schema, sizeof(schema));
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Certified Solana schema does not match transaction"));
      layoutHome();
      return;
    }
    certified = true;
  } else {
    tx_review = solana_inspectTx(msg->raw_tx.bytes, msg->raw_tx.size, &parsed);
    if (tx_review == SOL_TX_REVIEW_MALFORMED) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Malformed Solana transaction"));
      layoutHome();
      return;
    }

    /* Runtime schemas remain an explicit Advanced Mode developer facility.
     * They are structurally checked and shown, but never inherit the root
     * certificate's authority and never suppress the blind-sign warning. */
    if (has_schema_material) {
      if (!msg->has_schema_payload || !msg->has_schema_signature ||
          !msg->has_schema_signer_key_id ||
          msg->schema_signer_key_id >= METADATA_MAX_KEYS ||
          !solana_parseInstrSchema(msg->schema_payload.bytes,
                                   msg->schema_payload.size, &schema) ||
          !signed_metadata_verify_attestation(
              (uint8_t)msg->schema_signer_key_id, msg->schema_payload.bytes,
              msg->schema_payload.size, msg->schema_signature.bytes,
              msg->schema_signature.size) ||
          !solana_schemaApplies(&schema, &parsed, &schema_ix)) {
        memzero(node, sizeof(*node));
        memzero(&schema, sizeof(schema));
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid Solana instruction schema"));
        layoutHome();
        return;
      }
      const char* alias =
          signed_metadata_signer_alias((uint8_t)msg->schema_signer_key_id);
      if (!alias || !signed_metadata_signer_fingerprint(
                        (uint8_t)msg->schema_signer_key_id, signer_fp)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Missing Solana schema signer"));
        layoutHome();
        return;
      }
      strncpy(signer_alias, alias, sizeof(signer_alias) - 1);
      runtime_schema = true;
    }
  }

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

  if (certified) {
    if (!solana_confirmSchemaTransaction(&schema, &parsed, schema_ix,
                                         signer_alias, signer_fp)) {
      memzero(node, sizeof(*node));
      memzero(&schema, sizeof(schema));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  } else if (tx_review == SOL_TX_REVIEW_VERIFIED) {
    /* Per-instruction confirmation for fully verified messages */
    for (uint8_t i = 0; i < parsed.num_instructions; i++) {
      /* Resolve the recipient's wallet for token transfers, by re-deriving the
       * associated-token address from each owner the host offered and keeping
       * the one that equals the destination being signed. Nothing is displayed
       * unless that derivation matches, so a wrong or invented owner is
       * dropped rather than shown. */
      const SolanaParsedInstruction* pi = &parsed.instructions[i];
      uint8_t owner[SOL_PUBKEY_SIZE];
      const uint8_t* owner_ptr = NULL;
      if ((pi->type == SOL_INSTR_TOKEN_TRANSFER_CHECKED ||
           pi->type == SOL_INSTR_TOKEN_TRANSFER) &&
          pi->has_mint &&
          solana_findTokenRecipientOwner(msg, pi->program_id, pi->mint, pi->to,
                                         owner)) {
        owner_ptr = owner;
      }
      if (!solana_confirmInstruction(&parsed.instructions[i], i,
                                     parsed.num_instructions, owner_ptr)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
    }
  } else if (runtime_schema) {
    if (!storage_isPolicyEnabled("AdvancedMode") ||
        !solana_confirmSchemaTransaction(&schema, &parsed, schema_ix,
                                         signer_alias, signer_fp) ||
        !confirm(ButtonRequestType_ButtonRequest_SignTx, "Advanced Mode",
                 "Sign provider-described Solana transaction?")) {
      memzero(node, sizeof(*node));
      memzero(&schema, sizeof(schema));
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

    const SolanaSchemaReviewResult schema_review =
        solana_confirmAttestedSchema(msg, &parsed);
    if (schema_review == SOL_SCHEMA_REVIEW_CANCELLED) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }

    /* KKSOLSW1: a provider may attest the accounts this message resolves
       through a lookup table -- the ones the device cannot derive, and the
       reason it went opaque at all. Showing them turns a blind sign into a
       described one.

       Strictly additive, and deliberately BEFORE the blind-sign warning rather
       than instead of it: a runtime signer is annotation, never authority, so
       the user still sees "the device cannot fully verify the contents" and
       still has to approve it. If the attestation is absent, malformed, or
       fails to verify, nothing extra is drawn and the flow is byte-for-byte
       what it was. */
    /* nanopb gives each repeated `bytes` element as a {size, bytes[32]}
       struct, NOT a bare 32-byte array -- casting the array to
       (uint8_t(*)[32]) would hash the size word plus 28 bytes of the first
       key. Flatten explicitly, and require every element to be a full
       SOL_PUBKEY_SIZE key so a short one cannot silently hash as zero-padded.
     */
    if (lut_well_formed && lut_n > 0 && msg->has_lut_signature &&
        msg->has_lut_signer_key_id &&
        solana_lut_accounts_trusted(
            msg->raw_tx.bytes, msg->raw_tx.size,
            (const uint8_t (*)[32])lut_keys, lut_n, msg->lut_signer_key_id,
            msg->lut_signature.bytes, msg->lut_signature.size)) {
      char fp[METADATA_FINGERPRINT_LEN];
      const char* alias =
          signed_metadata_signer_alias((uint8_t)msg->lut_signer_key_id);
      if (!signed_metadata_signer_fingerprint((uint8_t)msg->lut_signer_key_id,
                                              fp)) {
        fp[0] = '\0';
      }
      /* Name WHO is describing these accounts before showing what they say.
         The user is being asked to trust a third party, and the tier never
         claims KeepKey verified it. */
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Lookup Accounts",
                   "%s (%s) describes %u account(s).\nNOT verified by KeepKey.",
                   alias ? alias : "Unknown signer", fp,
                   (unsigned)msg->lut_account_count)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
      for (size_t li = 0; li < lut_n; li++) {
        char b58[64];
        size_t b58_len = sizeof(b58);
        if (!solana_base58_encode(lut_keys[li], SOL_PUBKEY_SIZE, b58,
                                  &b58_len)) {
          continue;
        }
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Lookup Account", "%u/%u\n%s", (unsigned)(li + 1),
                     (unsigned)lut_n, b58)) {
          memzero(node, sizeof(*node));
          fsm_sendFailure(FailureType_Failure_ActionCancelled,
                          _("Signing cancelled"));
          layoutHome();
          return;
        }
      }
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

  /* Bind the raw compute-budget fields above to the actual SOL at risk. This
   * is required for every fully verified path, including certified schemas. */
  if (tx_review == SOL_TX_REVIEW_VERIFIED &&
      !solana_confirmPriorityFee(&parsed)) {
    memzero(node, sizeof(*node));
    memzero(&schema, sizeof(schema));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
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

  memzero(&schema, sizeof(schema));
  memzero(lut_keys, sizeof(lut_keys));
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

  /* AdvancedMode gate: Solana message signing has no domain separation.
   * A signed message is indistinguishable from a signed transaction on
   * the Solana network (both are raw Ed25519 over arbitrary bytes).
   * A malicious dApp could craft a message that is also a valid tx.
   * See: https://github.com/trezor/trezor-firmware/issues/4371
   * Require AdvancedMode to proceed — same gate as ETH blind-signing. */
  if (!storage_isPolicyEnabled("AdvancedMode")) {
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

  /* Raw Ed25519 has no version or domain separator. Bind that fact to consent,
   * then page every signed byte; a prefix-plus-length preview is insufficient.
   */
  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, "Solana Message",
               "Format: raw Ed25519. Version: none. Domain: none.") ||
      !confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall, "Raw Message",
                     msg->message.bytes, msg->message.size)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Signing cancelled"));
    layoutHome();
    return;
  }

  /* Ed25519 sign */
  uint8_t sig[SOL_SIG_SIZE];
  ed25519_sign(msg->message.bytes, msg->message.size, node->private_key, sig);

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

  /* The off-chain envelope signs its version, format, and every message byte.
   * Show the envelope fields explicitly and page the complete payload. */
  const char* format_label = format == 0 ? "ASCII" : "UTF-8 limited";
  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, "Solana Off-chain",
               "Version: 0. Format: %s.", format_label) ||
      !confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                     "Off-chain Message", msg->message.bytes,
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
