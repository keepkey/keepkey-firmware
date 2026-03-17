void fsm_msgInitialize(Initialize *msg) {
  (void)msg;
  recovery_cipher_abort();
  signing_abort();
#ifndef  BITCOIN_ONLY
  ethereum_signing_abort();
  tendermint_signAbort();
  eos_signingAbort();
#endif
  session_clear(false);  // do not clear PIN
  layoutHome();
  fsm_msgGetFeatures(0);
}

static const char *model(void) {
  const char *ret = flash_getModel();
  if (ret) return ret;
  return "Unknown";
}

void fsm_msgGetFeatures(GetFeatures *msg) {
  (void)msg;
  RESP_INIT(Features);

  /* Vendor */
  resp->has_vendor = true;
  strlcpy(resp->vendor, "keepkey.com", sizeof(resp->vendor));

  /* Version */
  resp->has_major_version = true;
  resp->major_version = MAJOR_VERSION;
  resp->has_minor_version = true;
  resp->minor_version = MINOR_VERSION;
  resp->has_patch_version = true;
  resp->patch_version = PATCH_VERSION;

  /* Device ID */
  resp->has_device_id = true;
  strlcpy(resp->device_id, storage_getUuidStr(), sizeof(resp->device_id));

  /* Model */
  resp->has_model = true;
  strlcpy(resp->model, model(), sizeof(resp->model));

  /* Variant Name */
  resp->has_firmware_variant = true;
  strlcpy(resp->firmware_variant, variant_getName(),
          sizeof(resp->firmware_variant));

  /* Security settings */
  resp->has_pin_protection = true;
  resp->pin_protection = storage_hasPin();
  resp->has_passphrase_protection = true;
  resp->passphrase_protection = storage_getPassphraseProtected();
  resp->has_wipe_code_protection = storage_hasWipeCode();

#ifdef SCM_REVISION
  int len = sizeof(SCM_REVISION) - 1;
  resp->has_revision = true;
  memcpy(resp->revision.bytes, SCM_REVISION, len);
  resp->revision.size = len;
#endif

  /* Bootloader hash */
#ifndef EMULATOR
  resp->has_bootloader_hash = true;
  resp->bootloader_hash.size =
      memory_bootloader_hash(resp->bootloader_hash.bytes, false);
#else
  resp->has_bootloader_hash = false;
#endif

  /* Firmware hash */
#ifndef EMULATOR
  resp->has_firmware_hash = true;
  resp->firmware_hash.size = memory_firmware_hash(resp->firmware_hash.bytes);
#else
  resp->has_firmware_hash = false;
#endif

  /* Settings for device */
  if (storage_getLanguage()) {
    resp->has_language = true;
    strlcpy(resp->language, storage_getLanguage(), sizeof(resp->language));
  }

  if (storage_getLabel()) {
    resp->has_label = true;
    strlcpy(resp->label, storage_getLabel(), sizeof(resp->label));
  }

  /* Is device initialized? */
  resp->has_initialized = true;
  resp->initialized = storage_isInitialized();

  /* Are private keys imported */
  resp->has_imported = true;
  resp->imported = storage_getImported();

  /* Are private keys known to no-one? */
  resp->has_no_backup = true;
  resp->no_backup = storage_noBackup();

  /* Cached pin and passphrase status */
  resp->has_pin_cached = true;
  resp->pin_cached = session_isPinCached();
  resp->has_passphrase_cached = true;
  resp->passphrase_cached = session_isPassphraseCached();

  /* Policies */
  resp->policies_count = POLICY_COUNT;
  storage_getPolicies(resp->policies);
  _Static_assert(
      sizeof(resp->policies) / sizeof(resp->policies[0]) == POLICY_COUNT,
      "update messages.options to match POLICY_COUNT");

  /* Auto-lock delay */
  uint32_t auto_lock_delay = storage_getAutoLockDelayMs();
  resp->has_auto_lock_delay_ms = auto_lock_delay ? true : false;
  resp->auto_lock_delay_ms = auto_lock_delay;

  msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgGetCoinTable(GetCoinTable *msg) {
  RESP_INIT(CoinTable);

  CHECK_PARAM(msg->has_start == msg->has_end,
              "Incorrect GetCoinTable parameters");

  resp->has_chunk_size = true;
  resp->chunk_size = sizeof(resp->table) / sizeof(resp->table[0]);

  if (msg->has_start && msg->has_end) {
    if (COINS_COUNT + TOKENS_COUNT <= msg->start ||
        COINS_COUNT + TOKENS_COUNT < msg->end || msg->end < msg->start ||
        resp->chunk_size < msg->end - msg->start) {
      fsm_sendFailure(FailureType_Failure_Other,
                      "Incorrect GetCoinTable parameters");
      layoutHome();
      return;
    }
  }

  resp->has_num_coins = true;
  resp->num_coins = COINS_COUNT + TOKENS_COUNT;

  if (msg->has_start && msg->has_end) {
    resp->table_count = msg->end - msg->start;

    for (size_t i = 0; i < msg->end - msg->start; i++) {
      if (msg->start + i < COINS_COUNT) {
        resp->table[i] = coins[msg->start + i];
      }
#ifndef BITCOIN_ONLY
      else if (msg->start + i - COINS_COUNT < TOKENS_COUNT) {
        coinFromToken(&resp->table[i], &tokens[msg->start + i - COINS_COUNT]);
      }
#endif // BITCOIN_ONLY
    }
  }

  msg_write(MessageType_MessageType_CoinTable, resp);
}

static bool isValidModelNumber(const char *model) {
#define MODEL_ENTRY(STRING, ENUM) \
  if (!strcmp(model, STRING)) return true;
#include "keepkey/board/models.def"
  return false;
}

void checkPassphrase(void) {
  if (!passphrase_protect()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "authenticator needs passphrase");
    layoutHome();
    return;
  }
}

void fsm_msgPing(Ping *msg) {
  RESP_INIT(Success);

  // If device is in manufacture mode, turn if off, lock it, and program the
  // model number into OTP flash.
  if (is_mfg_mode() && msg->has_message && isValidModelNumber(msg->message)) {
    set_mfg_mode_off();
    char message[32];
    strlcpy(message, msg->message, sizeof(message));
    message[31] = 0;
    flash_setModel(&message);
  }

  const char *errMsgStr[NUM_AUTHERRS] = {
    "noerr",
    "Authenticator secret storage full",                                
    "Authenticator secret can't be decoded",                            
    "Account name missing or too long, or seed/message string missing", 
    "Account not found",                                                
    "Slot request out of range",
    "Authenticator secret seed too large",                              
    "passphrase incorrect for authdata",                                
    "Auth secret unknown error",
};

  typedef enum _AUTH_MSG_TYPE {
    INITAUTH = 0,
    GENOTP,
    GETACC,
    REMACC,
    WIPEADATA,
    NUM_AUTHMESSAGES
  } AUTH_MSG_TYPE;


  const char * const authMesStr[NUM_AUTHMESSAGES] = {
    "\x15" "initializeAuth:",
    "\x16" "generateOTPFrom:",
    "\x17" "getAccount:",
    "\x18" "removeAccount:",
    "\x19" "wipeAuthdata:",
  };

  AUTH_MSG_TYPE authMsg;
  for (authMsg=INITAUTH; authMsg<NUM_AUTHMESSAGES; authMsg++) {
    if (msg->has_message && 0 == strncmp(msg->message, authMesStr[authMsg], strlen(authMesStr[authMsg]))) {
      break;
    }
  }

  if (authMsg < NUM_AUTHMESSAGES) {
    // this is an authenticator message
    unsigned errcode;
    char otp[9] = {0};    // allow room for an 8 digit otp
    char acc[DOMAIN_SIZE+ACCOUNT_SIZE+2] = {0};    // allow room for domain + ":" + account

    CHECK_PIN
    checkPassphrase();

    switch (authMsg) {

      case INITAUTH:
        //DEBUG_DISPLAY("secret %s", &msg->message[strlen(authMesStr[authMsg])])
        errcode = addAuthAccount(&msg->message[strlen(authMesStr[authMsg])]);
        resp->has_message = false;
        break;

      case GENOTP:
        //DEBUG_DISPLAY("genotp %s", &msg->message[strlen(authMesStr[authMsg])])
        errcode = generateOTP(&msg->message[strlen(authMesStr[authMsg])], otp);
      #if DEBUG_LINK
        char authSlot[128] = {0};  // debug link only
        getAuthSlot(authSlot);
        resp->has_message = true;
        strlcpy(resp->message, otp, 9);
        strcat(resp->message, ":");
        strcat(resp->message, authSlot);
      #else
        resp->has_message = false;
      #endif        
        break;

      case GETACC:
        errcode = getAuthAccount(&msg->message[strlen(authMesStr[authMsg])], acc);
        resp->has_message = true;
        strlcpy(resp->message, acc, DOMAIN_SIZE+ACCOUNT_SIZE+2);
        break;

      case REMACC:
        errcode = removeAuthAccount(&msg->message[strlen(authMesStr[authMsg])]);
        resp->has_message = false;
        break;

      case WIPEADATA:
        wipeAuthData();
        errcode = NOERR;
        resp->has_message = false;
        break;

      default:
        // should not be able to reach this default.
        errcode = NOERR;
        break;
    }

    if (errcode != NOERR) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, errMsgStr[errcode]);
      layoutHome();
      return;
    }

  } else {

    if (msg->has_button_protection && msg->button_protection)
      if (!confirm(ButtonRequestType_ButtonRequest_Ping, "Ping", "%s",
                   msg->message)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Ping cancelled");
        layoutHome();
        return;
      }

    if (msg->has_pin_protection && msg->pin_protection) {
      CHECK_PIN
    }

    if (msg->has_passphrase_protection && msg->passphrase_protection) {
      if (!passphrase_protect()) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Ping cancelled");
        layoutHome();
        return;
      }
    }
    if (msg->has_message) {
      resp->has_message = true;
      memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
    }
  }

  msg_write(MessageType_MessageType_Success, resp);
  layoutHome();
}

void fsm_msgChangePin(ChangePin *msg) {
  bool removal = msg->has_remove && msg->remove;
  bool confirmed = false;

  if (removal) {
    if (storage_hasPin()) {
      confirmed =
          confirm(ButtonRequestType_ButtonRequest_RemovePin, "Remove PIN",
                  "Do you want to remove PIN protection?");
    } else {
      fsm_sendSuccess("PIN removed");
      return;
    }
  } else {
    if (storage_hasPin())
      confirmed = confirm(ButtonRequestType_ButtonRequest_ChangePin,
                          "Change PIN", "Do you want to change your PIN?");
    else
      confirmed = confirm(ButtonRequestType_ButtonRequest_CreatePin,
                          "Create PIN", "Do you want to add PIN protection?");
  }

  if (!confirmed) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    removal ? "PIN removal cancelled" : "PIN change cancelled");
    layoutHome();
    return;
  }

  CHECK_PIN_UNCACHED

  if (removal) {
    storage_setPin("");
    storage_commit();
    fsm_sendSuccess("PIN removed");
    layoutHome();
    return;
  }

  if (!change_pin()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "PINs do not match");
    layoutHome();
    return;
  }

  storage_commit();
  fsm_sendSuccess("PIN changed");
  layoutHome();
}

void fsm_msgChangeWipeCode(ChangeWipeCode *msg) {
  bool removal = msg->has_remove && msg->remove;
  bool confirmed = false;

#ifdef ENABLE_WIPECODE  // disable until oled-vuln and automated test is in place
  if (removal) {
    if (storage_hasWipeCode()) {
      confirmed = confirm(ButtonRequestType_ButtonRequest_RemoveWipeCode,
                          "Remove Wipe Code",
                          "Do you want to remove wipe code protection?");
    } else {
      fsm_sendSuccess("Wipe code removed");
      return;
    }
  } else {
    if (!storage_hasPin()) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "PIN must be set before setting wipe code");
      layoutHome();
      return;
    }

    if (storage_hasWipeCode())
      confirmed =
          confirm(ButtonRequestType_ButtonRequest_ChangeWipeCode,
                  "Change Wipe Code", "Do you want to change your wipe code?");
    else
      confirmed = confirm(ButtonRequestType_ButtonRequest_CreateWipeCode,
                          "Create Wipe Code",
                          "Do you want to add wipe code protection?");
  }

  if (!confirmed) {
    fsm_sendFailure(
        FailureType_Failure_ActionCancelled,
        removal ? "Wipe code removal cancelled" : "Wipe code change cancelled");
    layoutHome();
    return;
  }

  CHECK_PIN_UNCACHED

  if (removal) {
    storage_setWipeCode("");
    storage_commit();
    fsm_sendSuccess("Wipe code removed");
    layoutHome();
    return;
  }

  if (!change_wipe_code()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Wipe codes do not match");
    layoutHome();
    return;
  }

  storage_commit();
  fsm_sendSuccess("Wipe code changed");
  layoutHome();

#else   // ENABLE_WIPECODE
  (void)removal;
  (void)confirmed;

  fsm_sendSuccess("Wipe code function not available for this device");
  layoutHome();
#endif

}

void fsm_msgWipeDevice(WipeDevice *msg) {
  (void)msg;

  if (!confirm(ButtonRequestType_ButtonRequest_WipeDevice, "Wipe Device",
               "Do you want to erase your private keys and settings?")) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Wipe cancelled");
    layoutHome();
    return;
  }

  /* Wipe device */
  storage_wipe();
  storage_reset();
  storage_resetUuid();
  storage_commit();

  fsm_sendSuccess("Device wiped");
  layoutHome();
}

void fsm_msgFirmwareErase(FirmwareErase *msg) {
  (void)msg;
  fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                  "Not in bootloader mode");
}

void fsm_msgFirmwareUpload(FirmwareUpload *msg) {
  (void)msg;
  fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                  "Not in bootloader mode");
}

void fsm_msgGetEntropy(GetEntropy *msg) {
  if (!confirm(ButtonRequestType_ButtonRequest_GetEntropy, "Generate Entropy",
               "Do you want to generate and return entropy using the hardware "
               "RNG?")) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Entropy cancelled");
    layoutHome();
    return;
  }

  RESP_INIT(Entropy);
  uint32_t len = msg->size;

  if (len > ENTROPY_BUF) {
    len = ENTROPY_BUF;
  }

  resp->entropy.size = len;
  random_buffer(resp->entropy.bytes, len);
  msg_write(MessageType_MessageType_Entropy, resp);
  layoutHome();
}

void fsm_msgLoadDevice(LoadDevice *msg) {
  CHECK_NOT_INITIALIZED

  if (!confirm_load_device(msg->has_node)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Load cancelled");
    layoutHome();
    return;
  }

  if (msg->has_mnemonic && !(msg->has_skip_checksum && msg->skip_checksum)) {
    if (!mnemonic_check(msg->mnemonic)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Mnemonic with wrong checksum provided");
      layoutHome();
      return;
    }
  }

  storage_loadDevice(msg);

  storage_commit();

  txin_dgst_initialize();  // reset tx tracking if seed words are loaded

  fsm_sendSuccess("Device loaded");
  layoutHome();
}

void fsm_msgResetDevice(ResetDevice *msg) {
  CHECK_NOT_INITIALIZED

  reset_init(msg->has_display_random && msg->display_random,
             msg->has_strength ? msg->strength : 128,
             msg->has_passphrase_protection && msg->passphrase_protection,
             msg->has_pin_protection && msg->pin_protection,
             msg->has_language ? msg->language : 0,
             msg->has_label ? msg->label : 0,
             msg->has_no_backup ? msg->no_backup : false,
             msg->has_auto_lock_delay_ms ? msg->auto_lock_delay_ms
                                         : STORAGE_DEFAULT_SCREENSAVER_TIMEOUT,
             msg->has_u2f_counter ? msg->u2f_counter : 0);
}

void fsm_msgEntropyAck(EntropyAck *msg) {
  if (msg->has_entropy) {
    reset_entropy(msg->entropy.bytes, msg->entropy.size);
  } else {
    reset_entropy(0, 0);
  }
}

void fsm_msgCancel(Cancel *msg) {
  (void)msg;
  recovery_cipher_abort();
  signing_abort();
#ifndef BITCOIN_ONLY
  ethereum_signing_abort();
  tendermint_signAbort();
  eos_signingAbort();
#endif // BITCOIN_ONLY
  fsm_sendFailure(FailureType_Failure_ActionCancelled, "Aborted");
}

void fsm_msgApplySettings(ApplySettings *msg) {
  if (msg->has_label) {
    if (!confirm(ButtonRequestType_ButtonRequest_ChangeLabel, "Change Label",
                 "Do you want to change the label to \"%s\"?", msg->label)) {
      goto apply_settings_cancelled;
    }
  }

  if (msg->has_language) {
    if (!confirm(ButtonRequestType_ButtonRequest_ChangeLanguage,
                 "Change Language", "Do you want to change the language to %s?",
                 msg->language)) {
      goto apply_settings_cancelled;
    }
  }

  if (msg->has_use_passphrase) {
    if (msg->use_passphrase) {
      if (!confirm(ButtonRequestType_ButtonRequest_EnablePassphrase,
                   "Enable Passphrase",
                   "Do you want to enable BIP39 passphrases?")) {
        goto apply_settings_cancelled;
      }
    } else {
      if (!confirm(ButtonRequestType_ButtonRequest_DisablePassphrase,
                   "Disable Passphrase",
                   "Do you want to disable BIP39 passphrases?")) {
        goto apply_settings_cancelled;
      }
    }
  }

  if (msg->has_auto_lock_delay_ms) {
    if (!confirm(ButtonRequestType_ButtonRequest_AutoLockDelayMs,
                 "Change auto-lock delay",
                 "Do you want to set the auto-lock delay to %" PRIu32
                 " seconds?",
                 msg->auto_lock_delay_ms / 1000)) {
      goto apply_settings_cancelled;
    }
  }

  if (msg->has_u2f_counter) {
    if (!confirm(ButtonRequestType_ButtonRequest_U2FCounter, "Set U2F Counter",
                 "Do you want to set the U2F Counter?")) {
      goto apply_settings_cancelled;
    }
  }

  if (!msg->has_label && !msg->has_language && !msg->has_use_passphrase &&
      !msg->has_auto_lock_delay_ms && !msg->has_u2f_counter) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, "No setting provided");
    return;
  }

  CHECK_PIN_UNCACHED

  if (msg->has_label) {
    storage_setLabel(msg->label);
  }

  if (msg->has_language) {
    storage_setLanguage(msg->language);
  }

  if (msg->has_use_passphrase) {
    storage_setPassphraseProtected(msg->use_passphrase);
  }

  if (msg->has_auto_lock_delay_ms) {
    storage_setAutoLockDelayMs(msg->auto_lock_delay_ms);
  }

  if (msg->has_u2f_counter) {
    storage_setU2FCounter(msg->u2f_counter);
  }

  storage_commit();

  fsm_sendSuccess("Settings applied");
  layoutHome();
  return;

apply_settings_cancelled:
  fsm_sendFailure(FailureType_Failure_ActionCancelled,
                  "Apply settings cancelled");
  layoutHome();
  return;
}

void fsm_msgRecoveryDevice(RecoveryDevice *msg) {
  if (msg->has_dry_run && msg->dry_run) {
    CHECK_INITIALIZED
  } else {
    CHECK_NOT_INITIALIZED
  }

  recovery_cipher_init(
      msg->has_word_count ? msg->word_count : 0,
      msg->has_passphrase_protection && msg->passphrase_protection,
      msg->has_pin_protection && msg->pin_protection,
      msg->has_language ? msg->language : 0, msg->has_label ? msg->label : 0,
      msg->has_enforce_wordlist ? msg->enforce_wordlist : false,
      msg->has_auto_lock_delay_ms ? msg->auto_lock_delay_ms
                                  : STORAGE_DEFAULT_SCREENSAVER_TIMEOUT,
      msg->has_u2f_counter ? msg->u2f_counter : 0,
      msg->has_dry_run ? msg->dry_run : false);
}

void fsm_msgCharacterAck(CharacterAck *msg) {
  if (msg->has_delete && msg->del) {
    recovery_delete_character();
  } else if (msg->has_done && msg->done) {
    recovery_cipher_finalize();
  } else {
    msg->character[1] = '\0';
    recovery_character(msg->character);
  }
}

void fsm_msgApplyPolicies(ApplyPolicies *msg) {
  CHECK_PARAM(msg->policy_count > 0, "No policies provided");

  for (size_t i = 0; i < msg->policy_count; ++i) {
    CHECK_PARAM(msg->policy[i].has_policy_name,
                "Incorrect ApplyPolicies parameters");
    CHECK_PARAM(msg->policy[i].has_enabled,
                "Incorrect ApplyPolicies parameters");
  }

  for (size_t i = 0; i < msg->policy_count; ++i) {
    RESP_INIT(ButtonRequest);
    resp->has_code = true;
    resp->code = ButtonRequestType_ButtonRequest_ApplyPolicies;
    resp->has_data = true;

    strlcpy(resp->data, msg->policy[i].policy_name, sizeof(resp->data));

    bool enabled = msg->policy[i].enabled;
    strlcat(resp->data, enabled ? ":Enable" : ":Disable", sizeof(resp->data));

    // ShapeShift policy is always disabled.
    if (strcmp(msg->policy[i].policy_name, "ShapeShift") == 0) continue;

    if (!confirm_with_custom_button_request(
            resp, enabled ? "Enable Policy" : "Disable Policy",
            "Do you want to %s %s policy?", enabled ? "enable" : "disable",
            msg->policy[i].policy_name)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Apply policies cancelled");
      layoutHome();
      return;
    }
  }

  CHECK_PIN_UNCACHED

  for (size_t i = 0; i < msg->policy_count; ++i) {
    // ShapeShift policy is always disabled.
    if (strcmp(msg->policy[i].policy_name, "ShapeShift") == 0) continue;

    if (!storage_setPolicy(msg->policy[i].policy_name,
                           msg->policy[i].enabled)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Policies could not be applied");
      layoutHome();
      return;
    }
  }

  storage_commit();

  fsm_sendSuccess("Policies applied");
  layoutHome();
}
