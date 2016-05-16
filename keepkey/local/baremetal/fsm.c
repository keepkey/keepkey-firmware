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

/* === Includes ============================================================ */

#include <stdio.h>

#include <ecdsa.h>
#include <aes.h>
#include <hmac.h>
#include <bip32.h>
#include <bip39.h>
#include <base58.h>
#include <ripemd160.h>
#include <secp256k1.h>
#include <nist256p1.h>
#include <layout.h>
#include <confirm_sm.h>
#include <msg_dispatch.h>
#include <rand.h>
#include <memory.h>
#include <resources.h>
#include <timer.h>
#include <keepkey_board.h>
#include <keepkey_flash.h>

#include "home_sm.h"
#include "app_layout.h"
#include "app_confirm.h"
#include "pin_sm.h"
#include "passphrase_sm.h"
#include "fsm.h"
#include "storage.h"
#include "coins.h"
#include "transaction.h"
#include "crypto.h"
#include "util.h"
#include "signing.h"
#include "reset.h"
#include "recovery.h"
#include "recovery_cipher.h"

/* === Private Variables =================================================== */

static uint8_t msg_resp[MAX_FRAME_SIZE];

static const MessagesMap_t MessagesMap[] =
{
    /* Normal Messages */
    MSG_IN(MessageType_MessageType_Initialize,          Initialize_fields, (void (*)(void *))fsm_msgInitialize)
    MSG_IN(MessageType_MessageType_GetFeatures,         GetFeatures_fields, (void (*)(void *))fsm_msgGetFeatures)
    MSG_IN(MessageType_MessageType_Ping,                Ping_fields, (void (*)(void *))fsm_msgPing)
    MSG_IN(MessageType_MessageType_ChangePin,           ChangePin_fields, (void (*)(void *))fsm_msgChangePin)
    MSG_IN(MessageType_MessageType_WipeDevice,          WipeDevice_fields, (void (*)(void *))fsm_msgWipeDevice)
    MSG_IN(MessageType_MessageType_FirmwareErase,       FirmwareErase_fields, (void (*)(void *))fsm_msgFirmwareErase)
    MSG_IN(MessageType_MessageType_FirmwareUpload,      FirmwareUpload_fields, (void (*)(void *))fsm_msgFirmwareUpload)
    MSG_IN(MessageType_MessageType_GetEntropy,          GetEntropy_fields, (void (*)(void *))fsm_msgGetEntropy)
    MSG_IN(MessageType_MessageType_GetPublicKey,        GetPublicKey_fields, (void (*)(void *))fsm_msgGetPublicKey)
    MSG_IN(MessageType_MessageType_LoadDevice,          LoadDevice_fields, (void (*)(void *))fsm_msgLoadDevice)
    MSG_IN(MessageType_MessageType_ResetDevice,         ResetDevice_fields, (void (*)(void *))fsm_msgResetDevice)
    MSG_IN(MessageType_MessageType_SignTx,              SignTx_fields, (void (*)(void *))fsm_msgSignTx)
    MSG_IN(MessageType_MessageType_PinMatrixAck,        PinMatrixAck_fields,        NO_PROCESS_FUNC)
    MSG_IN(MessageType_MessageType_Cancel,              Cancel_fields, (void (*)(void *))fsm_msgCancel)
    MSG_IN(MessageType_MessageType_TxAck,               TxAck_fields, (void (*)(void *))fsm_msgTxAck)
    MSG_IN(MessageType_MessageType_CipherKeyValue,      CipherKeyValue_fields, (void (*)(void *))fsm_msgCipherKeyValue)
    MSG_IN(MessageType_MessageType_ClearSession,        ClearSession_fields, (void (*)(void *))fsm_msgClearSession)
    MSG_IN(MessageType_MessageType_ApplySettings,       ApplySettings_fields, (void (*)(void *))fsm_msgApplySettings)
    MSG_IN(MessageType_MessageType_ButtonAck,           ButtonAck_fields,           NO_PROCESS_FUNC)
    MSG_IN(MessageType_MessageType_GetAddress,          GetAddress_fields, (void (*)(void *))fsm_msgGetAddress)
    MSG_IN(MessageType_MessageType_EntropyAck,          EntropyAck_fields, (void (*)(void *))fsm_msgEntropyAck)
    MSG_IN(MessageType_MessageType_SignMessage,         SignMessage_fields, (void (*)(void *))fsm_msgSignMessage)
    MSG_IN(MessageType_MessageType_SignIdentity,        SignIdentity_fields, (void (*)(void *))fsm_msgSignIdentity)
    MSG_IN(MessageType_MessageType_VerifyMessage,       VerifyMessage_fields, (void (*)(void *))fsm_msgVerifyMessage)
    MSG_IN(MessageType_MessageType_EncryptMessage,      EncryptMessage_fields, (void (*)(void *))fsm_msgEncryptMessage)
    MSG_IN(MessageType_MessageType_DecryptMessage,      DecryptMessage_fields, (void (*)(void *))fsm_msgDecryptMessage)
    MSG_IN(MessageType_MessageType_PassphraseAck,       PassphraseAck_fields,       NO_PROCESS_FUNC)
    MSG_IN(MessageType_MessageType_EstimateTxSize,      EstimateTxSize_fields, (void (*)(void *))fsm_msgEstimateTxSize)
    MSG_IN(MessageType_MessageType_RecoveryDevice,      RecoveryDevice_fields, (void (*)(void *))fsm_msgRecoveryDevice)
    MSG_IN(MessageType_MessageType_WordAck,             WordAck_fields, (void (*)(void *))fsm_msgWordAck)
    MSG_IN(MessageType_MessageType_CharacterAck,        CharacterAck_fields, (void (*)(void *))fsm_msgCharacterAck)

    /* Normal Out Messages */
    MSG_OUT(MessageType_MessageType_Success,            Success_fields,             NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_Failure,            Failure_fields,             NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_Entropy,            Entropy_fields,             NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_PublicKey,          PublicKey_fields,           NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_Features,           Features_fields,            NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_PinMatrixRequest,   PinMatrixRequest_fields,    NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_TxRequest,          TxRequest_fields,           NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_CipheredKeyValue,   CipheredKeyValue_fields,    NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_ButtonRequest,      ButtonRequest_fields,       NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_Address,            Address_fields,             NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_EntropyRequest,     EntropyRequest_fields,      NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_MessageSignature,   MessageSignature_fields,    NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_SignedIdentity,     SignedIdentity_fields,      NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_EncryptedMessage,   EncryptedMessage_fields,    NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_DecryptedMessage,   DecryptedMessage_fields,    NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_PassphraseRequest,  PassphraseRequest_fields,   NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_TxSize,             TxSize_fields,              NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_WordRequest,        WordRequest_fields,         NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_CharacterRequest,   CharacterRequest_fields,    NO_PROCESS_FUNC)

#if DEBUG_LINK
    /* Debug Messages */
    DEBUG_IN(MessageType_MessageType_DebugLinkDecision, DebugLinkDecision_fields,   NO_PROCESS_FUNC)
    DEBUG_IN(MessageType_MessageType_DebugLinkGetState, DebugLinkGetState_fields, (void (*)(void *))fsm_msgDebugLinkGetState)
    DEBUG_IN(MessageType_MessageType_DebugLinkStop,     DebugLinkStop_fields, (void (*)(void *))fsm_msgDebugLinkStop)

    /* Debug Out Messages */
    DEBUG_OUT(MessageType_MessageType_DebugLinkState, DebugLinkState_fields,        NO_PROCESS_FUNC)
    DEBUG_OUT(MessageType_MessageType_DebugLinkLog, DebugLinkLog_fields,            NO_PROCESS_FUNC)
#endif
};

/* === Variables =========================================================== */

extern bool reset_msg_stack;

/* === Functions =========================================================== */

void fsm_init(void)
{
    msg_map_init(MessagesMap, sizeof(MessagesMap) / sizeof(MessagesMap_t));
    set_msg_failure_handler(&fsm_sendFailure);

    /* set leaving handler for layout to help with determine home state */
    set_leaving_handler(&leave_home);

#if DEBUG_LINK
    set_msg_debug_link_get_state_handler(&fsm_msgDebugLinkGetState);
#endif

    msg_init();
}

/* --- Message Handlers ---------------------------------------------------- */

void fsm_sendSuccess(const char *text)
{
    if(reset_msg_stack)
    {
        fsm_msgInitialize((Initialize *)0);
        reset_msg_stack = false;
        return;
    }

    RESP_INIT(Success);

    if(text)
    {
        resp->has_message = true;
        strlcpy(resp->message, text, sizeof(resp->message));
    }

    msg_write(MessageType_MessageType_Success, resp);
}

void fsm_sendFailure(FailureType code, const char *text)
{
    if(reset_msg_stack)
    {
        fsm_msgInitialize((Initialize *)0);
        reset_msg_stack = false;
        return;
    }

    RESP_INIT(Failure);
    resp->has_code = true;
    resp->code = code;

    if(text)
    {
        resp->has_message = true;
        strlcpy(resp->message, text, sizeof(resp->message));
    }

    msg_write(MessageType_MessageType_Failure, resp);
}

const CoinType *fsm_getCoin(const char *name)
{
    const CoinType *coin = coinByName(name);

    if(!coin)
    {
        fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
        go_home();
        return 0;
    }

    return coin;
}

const HDNode *fsm_getDerivedNode(uint32_t *address_n, size_t address_n_count)
{
    static HDNode node;

    if(!storage_get_root_node(&node))
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized,
                        "Device not initialized or passphrase request cancelled");
        go_home();
        return 0;
    }

    if(!address_n || address_n_count == 0)
    {
        return &node;
    }

    if(hdnode_private_ckd_cached(&node, address_n, address_n_count) == 0)
    {
        fsm_sendFailure(FailureType_Failure_Other, "Failed to derive private key");
        go_home();
        return 0;
    }

    return &node;
}

void fsm_msgInitialize(Initialize *msg)
{
    (void)msg;

    /* If device is in manufacture mode, turn if off and lock it */
    if(is_mfg_mode())
    {
        set_mfg_mode_off();
        go_home_forced();
    }

    recovery_abort(false);
    signing_abort();
    session_clear(false); // do not clear PIN
    go_home();
    fsm_msgGetFeatures(0);
}

void fsm_msgGetFeatures(GetFeatures *msg)
{
    (void)msg;
    RESP_INIT(Features);

    /* Vendor */
    resp->has_vendor = true;
    strlcpy(resp->vendor, "keepkey.com", sizeof(resp->vendor));

    /* Version */
    resp->has_major_version = true;  resp->major_version = MAJOR_VERSION;
    resp->has_minor_version = true;  resp->minor_version = MINOR_VERSION;
    resp->has_patch_version = true;  resp->patch_version = PATCH_VERSION;

    /* Device ID */
    resp->has_device_id = true;
    strlcpy(resp->device_id, storage_get_uuid_str(), sizeof(resp->device_id));

    /* Security settings */
    resp->has_pin_protection = true; resp->pin_protection = storage_has_pin();
    resp->has_passphrase_protection = true;
    resp->passphrase_protection = storage_get_passphrase_protected();

#ifdef SCM_REVISION
    int len = sizeof(SCM_REVISION) - 1;
    resp->has_revision = true; memcpy(resp->revision.bytes, SCM_REVISION, len);
    resp->revision.size = len;
#endif

    /* Bootloader hash */
    resp->has_bootloader_hash = true;
    resp->bootloader_hash.size = memory_bootloader_hash(
                                     resp->bootloader_hash.bytes);

    /* Settings for device */
    if(storage_get_language())
    {
        resp->has_language = true;
        strlcpy(resp->language, storage_get_language(), sizeof(resp->language));
    }

    if(storage_get_label())
    {
        resp->has_label = true;
        strlcpy(resp->label, storage_get_label(), sizeof(resp->label));
    }

    /* Coin type support */
    resp->coins_count = COINS_COUNT;
    memcpy(resp->coins, coins, COINS_COUNT * sizeof(CoinType));

    /* Is device initialized? */
    resp->has_initialized = true;  resp->initialized = storage_is_initialized();

    /* Are private keys imported */
    resp->has_imported = true; resp->imported = storage_get_imported();

    /* Cached pin and passphrase status */
    resp->has_pin_cached = true; resp->pin_cached = session_is_pin_cached();
    resp->has_passphrase_cached = true;
    resp->passphrase_cached = session_is_passphrase_cached();

    msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgPing(Ping *msg)
{
    RESP_INIT(Success);

    if(msg->has_button_protection && msg->button_protection)
        if(!confirm(ButtonRequestType_ButtonRequest_ProtectCall, "Ping", msg->message))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Ping cancelled");
            go_home();
            return;
        }

    if(msg->has_pin_protection && msg->pin_protection)
    {
        if(!pin_protect_cached())
        {
            go_home();
            return;
        }
    }

    if(msg->has_passphrase_protection && msg->passphrase_protection)
    {
        if(!passphrase_protect())
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Ping cancelled");
            go_home();
            return;
        }
    }

    if(msg->has_message)
    {
        resp->has_message = true;
        memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
    }

    msg_write(MessageType_MessageType_Success, resp);
    go_home();
}

void fsm_msgChangePin(ChangePin *msg)
{
    bool removal = msg->has_remove && msg->remove;
    bool confirmed = false;

    if(removal)
    {
        if(storage_has_pin())
        {
            confirmed = confirm(ButtonRequestType_ButtonRequest_ProtectCall,
                                "Remove PIN", "Do you want to remove PIN protection?");
        }
        else
        {
            fsm_sendSuccess("PIN removed");
            return;
        }
    }
    else
    {
        if(storage_has_pin())
            confirmed = confirm(ButtonRequestType_ButtonRequest_ProtectCall,
                                "Change PIN", "Do you want to change your PIN?");
        else
            confirmed = confirm(ButtonRequestType_ButtonRequest_ProtectCall,
                                "Create PIN", "Do you want to add PIN protection?");
    }

    if(!confirmed)
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        removal ? "PIN removal cancelled" : "PIN change cancelled");
        go_home();
        return;
    }

    if(!pin_protect("Enter Current PIN"))
    {
        go_home();
        return;
    }

    if(removal)
    {
        storage_set_pin(0);
        storage_commit();
        fsm_sendSuccess("PIN removed");
    }
    else
    {
        if(change_pin())
        {
            storage_commit();
            fsm_sendSuccess("PIN changed");
        }
    }

    go_home();
}

void fsm_msgWipeDevice(WipeDevice *msg)
{
    (void)msg;

    if(!confirm(ButtonRequestType_ButtonRequest_WipeDevice, "Wipe Device",
                "Do you want to erase your private keys and settings?"))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Wipe cancelled");
        go_home();
        return;
    }

    /* Wipe device */
    storage_reset();
    storage_reset_uuid();
    storage_commit();

    fsm_sendSuccess("Device wiped");
    go_home();
}

void fsm_msgFirmwareErase(FirmwareErase *msg)
{
    (void)msg;
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in bootloader mode");
}

void fsm_msgFirmwareUpload(FirmwareUpload *msg)
{
    (void)msg;
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in bootloader mode");
}

void fsm_msgGetEntropy(GetEntropy *msg)
{
    if(!confirm(ButtonRequestType_ButtonRequest_ProtectCall,
                "Generate Entropy",
                "Do you want to generate and return entropy using the hardware RNG?"))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Entropy cancelled");
        go_home();
        return;
    }

    RESP_INIT(Entropy);
    uint32_t len = msg->size;

    if(len > ENTROPY_BUF)
    {
        len = ENTROPY_BUF;
    }

    resp->entropy.size = len;
    random_buffer(resp->entropy.bytes, len);
    msg_write(MessageType_MessageType_Entropy, resp);
    go_home();
}

void fsm_msgGetPublicKey(GetPublicKey *msg)
{
    RESP_INIT(PublicKey);

    if (!storage_is_initialized()) 
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    const HDNode *node = fsm_getDerivedNode(msg->address_n, msg->address_n_count);

    if(!node) { return; }

    uint8_t public_key[33];  // copy public key to temporary buffer
    memcpy(public_key, node->public_key, sizeof(public_key));

    if(msg->has_ecdsa_curve_name)
    {
        const ecdsa_curve *curve = get_curve_by_name(msg->ecdsa_curve_name);

        if(curve)
        {
            // correct public key (since fsm_getDerivedNode uses secp256k1 curve)
            ecdsa_get_public_key33(curve, node->private_key, public_key);
        }
    }

    resp->node.depth = node->depth;
    resp->node.fingerprint = node->fingerprint;
    resp->node.child_num = node->child_num;
    resp->node.chain_code.size = 32;
    memcpy(resp->node.chain_code.bytes, node->chain_code, 32);
    resp->node.has_private_key = false;
    resp->node.has_public_key = true;
    resp->node.public_key.size = 33;
    memcpy(resp->node.public_key.bytes, public_key, 33);
    resp->has_xpub = true;
    hdnode_serialize_public(node, resp->xpub, sizeof(resp->xpub));

    if(msg->has_show_display && msg->show_display)
    {
        if(!confirm_xpub(resp->xpub))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show extended public key cancelled");
            go_home();
            return;
        }
    }

    msg_write(MessageType_MessageType_PublicKey, resp);
    go_home();
}

void fsm_msgLoadDevice(LoadDevice *msg)
{
    if(storage_is_initialized())
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        "Device is already initialized. Use Wipe first.");
        return;
    }

    if(!confirm_load_device(msg->has_node))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Load cancelled");
        go_home();
        return;
    }

    if(msg->has_mnemonic && !(msg->has_skip_checksum && msg->skip_checksum))
    {
        if(!mnemonic_check(msg->mnemonic))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Mnemonic with wrong checksum provided");
            go_home();
            return;
        }
    }

    storage_load_device(msg);

    storage_commit();
    fsm_sendSuccess("Device loaded");
    go_home();
}

void fsm_msgResetDevice(ResetDevice *msg)
{
    if(storage_is_initialized())
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        "Device is already initialized. Use Wipe first.");
        return;
    }

    reset_init(
        msg->has_display_random && msg->display_random,
        msg->has_strength ? msg->strength : 128,
        msg->has_passphrase_protection && msg->passphrase_protection,
        msg->has_pin_protection && msg->pin_protection,
        msg->has_language ? msg->language : 0,
        msg->has_label ? msg->label : 0
    );
}

void fsm_msgSignTx(SignTx *msg)
{

    if (!storage_is_initialized()) 
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(msg->inputs_count < 1)
    {
        fsm_sendFailure(FailureType_Failure_Other,
                        "Transaction must have at least one input");
        go_home();
        return;
    }

    if(msg->outputs_count < 1)
    {
        fsm_sendFailure(FailureType_Failure_Other,
                        "Transaction must have at least one output");
        go_home();
        return;
    }

    if(!pin_protect("Enter Current PIN"))
    {
        go_home();
        return;
    }

    const CoinType *coin = fsm_getCoin(msg->coin_name);

    if(!coin) { return; }

    /* master node */
    const HDNode *node = fsm_getDerivedNode(0, 0);

    if(!node) { return; }

    signing_init(msg->inputs_count, msg->outputs_count, coin, node);
}

void fsm_msgCancel(Cancel *msg)
{
    (void)msg;
    recovery_abort(true);
    signing_abort();
}

void fsm_msgTxAck(TxAck *msg)
{
    if(msg->has_tx)
    {
        signing_txack(&(msg->tx));
    }
    else
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No transaction provided");
    }
}

void fsm_msgApplySettings(ApplySettings *msg)
{
    if(msg->has_label)
    {
        if(!confirm(ButtonRequestType_ButtonRequest_ProtectCall,
                    "Change Label", "Do you want to change the label to \"%s\"?", msg->label))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Apply settings cancelled");
            go_home();
            return;
        }
    }

    if(msg->has_language)
    {
        if(!confirm(ButtonRequestType_ButtonRequest_ProtectCall,
                    "Change Language", "Do you want to change the language to %s?", msg->language))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "Apply settings cancelled");
            go_home();
            return;
        }
    }

    if(msg->has_use_passphrase)
    {
        if(msg->use_passphrase)
        {
            if(!confirm(ButtonRequestType_ButtonRequest_ProtectCall,
                        "Enable Passphrase", "Do you want to enable passphrase encryption?",
                        msg->language))
            {
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                "Apply settings cancelled");
                go_home();
                return;
            }
        }
        else
        {
            if(!confirm(ButtonRequestType_ButtonRequest_ProtectCall,
                        "Disable Passphrase", "Do you want to disable passphrase encryption?",
                        msg->language))
            {
                fsm_sendFailure(FailureType_Failure_ActionCancelled,
                                "Apply settings cancelled");
                go_home();
                return;
            }
        }
    }

    if(!msg->has_label && !msg->has_language && !msg->has_use_passphrase)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No setting provided");
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    if(msg->has_label)
    {
        storage_set_label(msg->label);
    }

    if(msg->has_language)
    {
        storage_set_language(msg->language);
    }

    if(msg->has_use_passphrase)
    {
        storage_set_passphrase_protected(msg->use_passphrase);
    }

    storage_commit();

    fsm_sendSuccess("Settings applied");
    go_home();
}

void fsm_msgCipherKeyValue(CipherKeyValue *msg)
{

	if (!storage_is_initialized()) 
    {
		fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
		return;
	}

    if(!msg->has_key)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No key provided");
        return;
    }

    if(!msg->has_value)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No value provided");
        return;
    }

    if(msg->value.size % 16)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        "Value length must be a multiple of 16");
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    const HDNode *node = fsm_getDerivedNode(msg->address_n, msg->address_n_count);

    if(!node) { return; }

    bool encrypt = msg->has_encrypt && msg->encrypt;
    bool ask_on_encrypt = msg->has_ask_on_encrypt && msg->ask_on_encrypt;
    bool ask_on_decrypt = msg->has_ask_on_decrypt && msg->ask_on_decrypt;

    if((encrypt && ask_on_encrypt) || (!encrypt && ask_on_decrypt))
    {
        if(!confirm_cipher(encrypt, msg->key))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "CipherKeyValue cancelled");
            go_home();
            return;
        }
    }

    uint8_t data[256 + 4];
    strlcpy((char *)data, msg->key, sizeof(data));
    strlcat((char *)data, ask_on_encrypt ? "E1" : "E0", sizeof(data));
    strlcat((char *)data, ask_on_decrypt ? "D1" : "D0", sizeof(data));

    hmac_sha512(node->private_key, 32, data, strlen((char *)data), data);

    RESP_INIT(CipheredKeyValue);

    if(encrypt)
    {
        aes_encrypt_ctx ctx;
        aes_encrypt_key256(data, &ctx);
        aes_cbc_encrypt(msg->value.bytes, resp->value.bytes, msg->value.size,
                        ((msg->iv.size == 16) ? (msg->iv.bytes) : (data + 32)), &ctx);
    }
    else
    {
        aes_decrypt_ctx ctx;
        aes_decrypt_key256(data, &ctx);
        aes_cbc_decrypt(msg->value.bytes, resp->value.bytes, msg->value.size,
                        ((msg->iv.size == 16) ? (msg->iv.bytes) : (data + 32)), &ctx);
    }

    resp->has_value = true;
    resp->value.size = msg->value.size;
    msg_write(MessageType_MessageType_CipheredKeyValue, resp);
    go_home();
}

void fsm_msgClearSession(ClearSession *msg)
{
    (void)msg;
    session_clear(true);
    fsm_sendSuccess("Session cleared");
}

void fsm_msgGetAddress(GetAddress *msg)
{
    RESP_INIT(Address);

    if (!storage_is_initialized()) 
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    const CoinType *coin = fsm_getCoin(msg->coin_name);

    if(!coin) { return; }

    const HDNode *node = fsm_getDerivedNode(msg->address_n, msg->address_n_count);

    if(!node) { return; }

    if(coin->network_type == NetworkType_BITCOIN)
    {
        if(msg->has_multisig)
        {

            if(cryptoMultisigPubkeyIndex(&(msg->multisig), node->public_key) < 0)
            {
                fsm_sendFailure(FailureType_Failure_Other,
                                "Pubkey not found in multisig script");
                go_home();
                return;
            }

            uint8_t buf[32];

            if(compile_script_multisig_hash(&(msg->multisig), buf) == 0)
            {
                fsm_sendFailure(FailureType_Failure_Other, "Invalid multisig script");
                go_home();
                return;
            }

            ripemd160(buf, 32, buf + 1);
            buf[0] = coin->address_type_p2sh; // multisig cointype
            base58_encode_check(buf, 21, resp->address, sizeof(resp->address));
        }
        else
        {
            ecdsa_get_address(node->public_key, coin->address_type, resp->address,
                              sizeof(resp->address));
        }
    }
    else if(coin->network_type == NetworkType_ETHEREUM)
    {
        ecdsa_get_ethereum_address(node->public_key, resp->address, sizeof(resp->address));
    }

    if(msg->has_show_display && msg->show_display)
    {
        char desc[MEDIUM_STR_BUF] = "";

        if(msg->has_multisig)
        {
            const uint32_t m = msg->multisig.m;
            const uint32_t n = msg->multisig.pubkeys_count;

            /* snprintf: 22 + 10 (%lu) + 10 (%lu) + 1 (NULL) = 43 */
            snprintf(desc, MEDIUM_STR_BUF, "(Multi-Signature %lu of %lu)", (unsigned long)m,
                     (unsigned long)n);
        }

        if(!confirm_address(desc, resp->address))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show address cancelled");
            go_home();
            return;
        }
    }

    msg_write(MessageType_MessageType_Address, resp);
    go_home();
}

void fsm_msgEntropyAck(EntropyAck *msg)
{
    if(msg->has_entropy)
    {
        reset_entropy(msg->entropy.bytes, msg->entropy.size);
    }
    else
    {
        reset_entropy(0, 0);
    }
}

void fsm_msgSignMessage(SignMessage *msg)
{
    RESP_INIT(MessageSignature);

	if (!storage_is_initialized()) 
    {
		fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
		return;
	}

    if(!confirm(ButtonRequestType_ButtonRequest_ProtectCall, "Sign Message",
                (char *)msg->message.bytes))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Sign message cancelled");
        go_home();
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    const CoinType *coin = fsm_getCoin(msg->coin_name);

    if(!coin) { return; }

    const HDNode *node = fsm_getDerivedNode(msg->address_n, msg->address_n_count);

    if(!node) { return; }

    if(cryptoMessageSign(msg->message.bytes, msg->message.size, node->private_key,
                         resp->signature.bytes) == 0)
    {
        resp->has_address = true;
        uint8_t addr_raw[21];
        ecdsa_get_address_raw(node->public_key, coin->address_type, addr_raw);
        base58_encode_check(addr_raw, 21, resp->address, sizeof(resp->address));
        resp->has_signature = true;
        resp->signature.size = 65;
        msg_write(MessageType_MessageType_MessageSignature, resp);
    }
    else
    {
        fsm_sendFailure(FailureType_Failure_Other, "Error signing message");
    }

    go_home();
}

void fsm_msgVerifyMessage(VerifyMessage *msg)
{
    if(!msg->has_address)
    {
        fsm_sendFailure(FailureType_Failure_Other, "No address provided");
        return;
    }

    if(!msg->has_message)
    {
        fsm_sendFailure(FailureType_Failure_Other, "No message provided");
        return;
    }

    layout_simple_message("Verifying Message...");

    uint8_t addr_raw[21];

    if(!ecdsa_address_decode(msg->address, addr_raw))
    {
        fsm_sendFailure(FailureType_Failure_InvalidSignature, "Invalid address");
    }

    if(msg->signature.size == 65 &&
            cryptoMessageVerify(msg->message.bytes, msg->message.size, addr_raw,
                                msg->signature.bytes) == 0)
    {
        if(review(ButtonRequestType_ButtonRequest_Other, "Message Verified",
                  (char *)msg->message.bytes))
        {
            fsm_sendSuccess("Message verified");
        }
    }
    else
    {
        fsm_sendFailure(FailureType_Failure_InvalidSignature, "Invalid signature");
    }

    go_home();
}

void fsm_msgSignIdentity(SignIdentity *msg)
{
    RESP_INIT(SignedIdentity);

    if (!storage_is_initialized()) 
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(!confirm_sign_identity(&(msg->identity),
                              msg->has_challenge_visual ? msg->challenge_visual : 0))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Sign identity cancelled");
        go_home();
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    uint8_t hash[32];

    if(!msg->has_identity || cryptoIdentityFingerprint(&(msg->identity), hash) == 0)
    {
        fsm_sendFailure(FailureType_Failure_Other, "Invalid identity");
        go_home();
        return;
    }

    uint32_t address_n[5];
    address_n[0] = 0x80000000 | 13;
    address_n[1] = 0x80000000 | hash[ 0] | (hash[ 1] << 8) | (hash[ 2] << 16) |
                   (hash[ 3] << 24);
    address_n[2] = 0x80000000 | hash[ 4] | (hash[ 5] << 8) | (hash[ 6] << 16) |
                   (hash[ 7] << 24);
    address_n[3] = 0x80000000 | hash[ 8] | (hash[ 9] << 8) | (hash[10] << 16) |
                   (hash[11] << 24);
    address_n[4] = 0x80000000 | hash[12] | (hash[13] << 8) | (hash[14] << 16) |
                   (hash[15] << 24);

    const HDNode *node = fsm_getDerivedNode(address_n, 5);

    if(!node) { return; }

    uint8_t public_key[33];  // copy public key to temporary buffer
    memcpy(public_key, node->public_key, sizeof(public_key));

    if(msg->has_ecdsa_curve_name)
    {
        const ecdsa_curve *curve = get_curve_by_name(msg->ecdsa_curve_name);

        if(curve)
        {
            // correct public key (since fsm_getDerivedNode uses secp256k1 curve)
            ecdsa_get_public_key33(curve, node->private_key, public_key);
        }
    }

    bool sign_ssh = msg->identity.has_proto && (strcmp(msg->identity.proto, "ssh") == 0);

    int result = 0;
    layout_simple_message("Signing Identity...");

    if(sign_ssh)    // SSH does not sign visual challenge
    {
        result = sshMessageSign(msg->challenge_hidden.bytes, msg->challenge_hidden.size,
                                node->private_key, resp->signature.bytes);
    }
    else
    {
        uint8_t digest[64];
        sha256_Raw(msg->challenge_hidden.bytes, msg->challenge_hidden.size, digest);
        sha256_Raw((const uint8_t *)msg->challenge_visual, strlen(msg->challenge_visual),
                   digest + 32);
        result = cryptoMessageSign(digest, 64, node->private_key, resp->signature.bytes);
    }

    if(result == 0)
    {
        if(sign_ssh)
        {
            resp->has_address = false;
        }
        else
        {
            resp->has_address = true;
            uint8_t addr_raw[21];
            ecdsa_get_address_raw(node->public_key, 0x00, addr_raw); // hardcoded Bitcoin address type
            base58_encode_check(addr_raw, 21, resp->address, sizeof(resp->address));
        }

        resp->has_public_key = true;
        resp->public_key.size = 33;
        memcpy(resp->public_key.bytes, public_key, 33);
        resp->has_signature = true;
        resp->signature.size = 65;
        msg_write(MessageType_MessageType_SignedIdentity, resp);
    }
    else
    {
        fsm_sendFailure(FailureType_Failure_Other, "Error signing identity");
    }

    go_home();
}

void fsm_msgEncryptMessage(EncryptMessage *msg)
{

    if (!storage_is_initialized()) 
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(!msg->has_pubkey)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No public key provided");
        return;
    }

    if(!msg->has_message)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No message provided");
        return;
    }

    curve_point pubkey;

    if(msg->pubkey.size != 33 ||
            ecdsa_read_pubkey(&secp256k1, msg->pubkey.bytes, &pubkey) == 0)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid public key provided");
        return;
    }

    bool display_only = msg->has_display_only && msg->display_only;
    bool signing = msg->address_n_count > 0;
    RESP_INIT(EncryptedMessage);
    const CoinType *coin = 0;
    const HDNode *node = 0;
    uint8_t address_raw[21];

    if(signing)
    {
        coin = coinByName(msg->coin_name);

        if(!coin)
        {
            fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
            return;
        }

        if(!pin_protect_cached())
        {
            go_home();
            return;
        }

        node = fsm_getDerivedNode(msg->address_n, msg->address_n_count);

        if(!node) { return; }

        uint8_t public_key[33];
        ecdsa_get_public_key33(&secp256k1, node->private_key, public_key);
        ecdsa_get_address_raw(public_key, coin->address_type, address_raw);
    }

    if(!confirm_encrypt_msg((char *)msg->message.bytes, signing))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Encrypt message cancelled");
        go_home();
        return;
    }

    layout_simple_message("Encrypting Message...");

    if(cryptoMessageEncrypt(&pubkey, msg->message.bytes, msg->message.size,
                            display_only,
                            resp->nonce.bytes, &(resp->nonce.size), resp->message.bytes,
                            &(resp->message.size),
                            resp->hmac.bytes, &(resp->hmac.size), signing ? node->private_key : 0,
                            signing ? address_raw : 0) != 0)
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Error encrypting message");
        go_home();
        return;
    }

    resp->has_nonce = true;
    resp->has_message = true;
    resp->has_hmac = true;
    msg_write(MessageType_MessageType_EncryptedMessage, resp);
    go_home();
}

void fsm_msgDecryptMessage(DecryptMessage *msg)
{

    if (!storage_is_initialized()) 
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(!msg->has_nonce)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No nonce provided");
        return;
    }

    if(!msg->has_message)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No message provided");
        return;
    }

    if(!msg->has_hmac)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No message hmac provided");
        return;
    }

    curve_point nonce_pubkey;

    if(msg->nonce.size != 33 ||
            ecdsa_read_pubkey(&secp256k1, msg->nonce.bytes, &nonce_pubkey) == 0)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid nonce provided");
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    const HDNode *node = fsm_getDerivedNode(msg->address_n, msg->address_n_count);

    if(!node) { return; }

    layout_simple_message("Decrypting Message...");

    RESP_INIT(DecryptedMessage);
    bool display_only = false;
    bool signing = false;
    uint8_t address_raw[21];

    if(cryptoMessageDecrypt(&nonce_pubkey, msg->message.bytes, msg->message.size,
                            msg->hmac.bytes, msg->hmac.size, node->private_key, resp->message.bytes,
                            &(resp->message.size), &display_only, &signing, address_raw) != 0)
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Error decrypting message");
        go_home();
        return;
    }

    if(signing)
    {
        base58_encode_check(address_raw, 21, resp->address, sizeof(resp->address));
    }

    if(!confirm_decrypt_msg((char *)resp->message.bytes,
                            signing ? resp->address : 0))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Decrypt message cancelled");
        go_home();
        return;
    }

    if(display_only)
    {
        resp->has_address = false;
        resp->has_message = false;
        memset(resp->address, 0, sizeof(resp->address));
        memset(&(resp->message), 0, sizeof(resp->message));
    }
    else
    {
        resp->has_address = signing;
        resp->has_message = true;
    }

    msg_write(MessageType_MessageType_DecryptedMessage, resp);
    go_home();
}

void fsm_msgEstimateTxSize(EstimateTxSize *msg)
{
    RESP_INIT(TxSize);
    resp->has_tx_size = true;
    resp->tx_size = transactionEstimateSize(msg->inputs_count, msg->outputs_count);
    msg_write(MessageType_MessageType_TxSize, resp);
}

void fsm_msgRecoveryDevice(RecoveryDevice *msg)
{
    if(storage_is_initialized())
    {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                        "Device is already initialized. Use Wipe first.");
        return;
    }

    if(msg->has_use_character_cipher &&
            msg->use_character_cipher == true)   // recovery via character cipher
    {
        recovery_cipher_init(
            msg->has_passphrase_protection && msg->passphrase_protection,
            msg->has_pin_protection && msg->pin_protection,
            msg->has_language ? msg->language : 0,
            msg->has_label ? msg->label : 0,
            msg->has_enforce_wordlist ? msg->enforce_wordlist : false
        );
    }
    else                                                                     // legacy way of recovery
    {
        recovery_init(
            msg->has_word_count ? msg->word_count : 12,
            msg->has_passphrase_protection && msg->passphrase_protection,
            msg->has_pin_protection && msg->pin_protection,
            msg->has_language ? msg->language : 0,
            msg->has_label ? msg->label : 0,
            msg->has_enforce_wordlist ? msg->enforce_wordlist : false
        );
    }
}

void fsm_msgWordAck(WordAck *msg)
{
    recovery_word(msg->word);
}

void fsm_msgCharacterAck(CharacterAck *msg)
{
    if(msg->has_delete && msg->delete)
    {
        recovery_delete_character();
    }
    else if(msg->has_done && msg->done)
    {
        recovery_cipher_finalize();
    }
    else
    {
        recovery_character(msg->character);
    }
}

/* --- Debug Message Handlers ---------------------------------------------- */

#if DEBUG_LINK
void fsm_msgDebugLinkGetState(DebugLinkGetState *msg)
{
    (void)msg;
    RESP_INIT(DebugLinkState);

    if(storage_has_pin())
    {
        resp->has_pin = true;
        strlcpy(resp->pin, storage_get_pin(), sizeof(resp->pin));
    }

    resp->has_matrix = true;
    strlcpy(resp->matrix, get_pin_matrix(), sizeof(resp->matrix));

    resp->has_reset_entropy = true;
    resp->reset_entropy.size = reset_get_int_entropy(resp->reset_entropy.bytes);

    resp->has_reset_word = true;
    strlcpy(resp->reset_word, reset_get_word(), sizeof(resp->reset_word));

    resp->has_recovery_fake_word = true;
    strlcpy(resp->recovery_fake_word, recovery_get_fake_word(),
            sizeof(resp->recovery_fake_word));

    resp->has_recovery_word_pos = true;
    resp->recovery_word_pos = recovery_get_word_pos();

    if(storage_has_mnemonic())
    {
        resp->has_mnemonic = true;
        strlcpy(resp->mnemonic, storage_get_mnemonic(), sizeof(resp->mnemonic));
    }

    if(storage_has_node())
    {
        resp->has_node = true;
        memcpy(&(resp->node), storage_get_node(), sizeof(HDNode));
    }

    resp->has_passphrase_protection = true;
    resp->passphrase_protection = storage_get_passphrase_protected();

    resp->has_recovery_cipher = true;
    strlcpy(resp->recovery_cipher, recovery_get_cipher(),
            sizeof(resp->recovery_cipher));

    resp->has_recovery_auto_completed_word = true;
    strlcpy(resp->recovery_auto_completed_word, recovery_get_auto_completed_word(),
            sizeof(resp->recovery_auto_completed_word));

    resp->has_firmware_hash = true;
    resp->firmware_hash.size = memory_firmware_hash(resp->firmware_hash.bytes);

    resp->has_storage_hash = true;
    resp->storage_hash.size = memory_storage_hash(resp->storage_hash.bytes,
                              get_storage_location());

    msg_debug_write(MessageType_MessageType_DebugLinkState, resp);
}

void fsm_msgDebugLinkStop(DebugLinkStop *msg)
{
    (void)msg;
}
#endif
