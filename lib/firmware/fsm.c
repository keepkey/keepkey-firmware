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

#include "scm_revision.h"
#include "variant.h"

#include "keepkey/board/check_bootloader.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/msg_dispatch.h"
#include "keepkey/board/resources.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/variant.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/crypto.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/exchange.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/passphrase_sm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/policy.h"
#include "keepkey/firmware/recovery.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/transaction.h"
#include "keepkey/firmware/util.h"
#include "keepkey/rand/rng.h"
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

#include <stdio.h>

static uint8_t msg_resp[MAX_FRAME_SIZE] __attribute__((aligned(4)));

#define CHECK_INITIALIZED \
    if (!storage_isInitialized()) { \
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized"); \
        return; \
    }

#define CHECK_NOT_INITIALIZED \
    if (storage_isInitialized()) { \
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Device is already initialized. Use Wipe first."); \
        return; \
    }

#define CHECK_PIN \
    if (!pin_protect_cached()) { \
        layoutHome(); \
        return; \
    }

#define CHECK_PIN_UNCACHED \
    if (!pin_protect("Enter Current PIN")) { \
        layoutHome(); \
        return; \
    }


#define CHECK_PARAM(cond, errormsg) \
    if (!(cond)) { \
        fsm_sendFailure(FailureType_Failure_Other, (errormsg)); \
        layoutHome(); \
        return; \
    }

static const MessagesMap_t MessagesMap[] =
{
    /* Normal Messages */
    MSG_IN(MessageType_MessageType_Initialize,          Initialize_fields, (void (*)(void *))fsm_msgInitialize, AnyVariant)
    MSG_IN(MessageType_MessageType_GetFeatures,         GetFeatures_fields, (void (*)(void *))fsm_msgGetFeatures, AnyVariant)
    MSG_IN(MessageType_MessageType_GetCoinTable,        GetCoinTable_fields, (void (*)(void *))fsm_msgGetCoinTable, AnyVariant)
    MSG_IN(MessageType_MessageType_Ping,                Ping_fields, (void (*)(void *))fsm_msgPing, AnyVariant)
    MSG_IN(MessageType_MessageType_ChangePin,           ChangePin_fields, (void (*)(void *))fsm_msgChangePin, MFRProhibited)
    MSG_IN(MessageType_MessageType_WipeDevice,          WipeDevice_fields, (void (*)(void *))fsm_msgWipeDevice, MFRProhibited)
    MSG_IN(MessageType_MessageType_FirmwareErase,       FirmwareErase_fields, (void (*)(void *))fsm_msgFirmwareErase, AnyVariant)
    MSG_IN(MessageType_MessageType_FirmwareUpload,      FirmwareUpload_fields, (void (*)(void *))fsm_msgFirmwareUpload, AnyVariant)
    MSG_IN(MessageType_MessageType_GetEntropy,          GetEntropy_fields, (void (*)(void *))fsm_msgGetEntropy, AnyVariant)
    MSG_IN(MessageType_MessageType_GetPublicKey,        GetPublicKey_fields, (void (*)(void *))fsm_msgGetPublicKey, MFRProhibited)
    MSG_IN(MessageType_MessageType_LoadDevice,          LoadDevice_fields, (void (*)(void *))fsm_msgLoadDevice, MFRProhibited)
    MSG_IN(MessageType_MessageType_ResetDevice,         ResetDevice_fields, (void (*)(void *))fsm_msgResetDevice, MFRProhibited)
    MSG_IN(MessageType_MessageType_SignTx,              SignTx_fields, (void (*)(void *))fsm_msgSignTx, MFRProhibited)
    MSG_IN(MessageType_MessageType_PinMatrixAck,        PinMatrixAck_fields,        NO_PROCESS_FUNC, MFRProhibited)
    MSG_IN(MessageType_MessageType_Cancel,              Cancel_fields, (void (*)(void *))fsm_msgCancel, AnyVariant)
    MSG_IN(MessageType_MessageType_TxAck,               TxAck_fields, (void (*)(void *))fsm_msgTxAck, MFRProhibited)
    MSG_IN(MessageType_MessageType_CipherKeyValue,      CipherKeyValue_fields, (void (*)(void *))fsm_msgCipherKeyValue, MFRProhibited)
    MSG_IN(MessageType_MessageType_ClearSession,        ClearSession_fields, (void (*)(void *))fsm_msgClearSession, AnyVariant)
    MSG_IN(MessageType_MessageType_ApplySettings,       ApplySettings_fields, (void (*)(void *))fsm_msgApplySettings, MFRProhibited)
    MSG_IN(MessageType_MessageType_ButtonAck,           ButtonAck_fields,           NO_PROCESS_FUNC, AnyVariant)
    MSG_IN(MessageType_MessageType_GetAddress,          GetAddress_fields, (void (*)(void *))fsm_msgGetAddress, MFRProhibited)
    MSG_IN(MessageType_MessageType_EntropyAck,          EntropyAck_fields, (void (*)(void *))fsm_msgEntropyAck, AnyVariant)
    MSG_IN(MessageType_MessageType_SignMessage,         SignMessage_fields, (void (*)(void *))fsm_msgSignMessage, MFRProhibited)
    MSG_IN(MessageType_MessageType_SignIdentity,        SignIdentity_fields, (void (*)(void *))fsm_msgSignIdentity, MFRProhibited)
    MSG_IN(MessageType_MessageType_VerifyMessage,       VerifyMessage_fields, (void (*)(void *))fsm_msgVerifyMessage, MFRProhibited)
/* ECIES disabled
    MSG_IN(MessageType_MessageType_EncryptMessage,      EncryptMessage_fields, (void (*)(void *))fsm_msgEncryptMessage, MFRProhibited)
    MSG_IN(MessageType_MessageType_DecryptMessage,      DecryptMessage_fields, (void (*)(void *))fsm_msgDecryptMessage, MFRProhibited)
*/
    MSG_IN(MessageType_MessageType_PassphraseAck,       PassphraseAck_fields,       NO_PROCESS_FUNC, MFRProhibited)
    MSG_IN(MessageType_MessageType_EstimateTxSize,      EstimateTxSize_fields, (void (*)(void *))fsm_msgEstimateTxSize, MFRProhibited)
    MSG_IN(MessageType_MessageType_RecoveryDevice,      RecoveryDevice_fields, (void (*)(void *))fsm_msgRecoveryDevice, MFRProhibited)
    MSG_IN(MessageType_MessageType_WordAck,             WordAck_fields, (void (*)(void *))fsm_msgWordAck, MFRProhibited)
    MSG_IN(MessageType_MessageType_CharacterAck,        CharacterAck_fields, (void (*)(void *))fsm_msgCharacterAck, MFRProhibited)
    MSG_IN(MessageType_MessageType_ApplyPolicies,       ApplyPolicies_fields, (void (*)(void *))fsm_msgApplyPolicies, MFRProhibited)
    MSG_IN(MessageType_MessageType_EthereumGetAddress,	EthereumGetAddress_fields, (void (*)(void *))fsm_msgEthereumGetAddress, MFRProhibited)
    MSG_IN(MessageType_MessageType_EthereumSignTx,      EthereumSignTx_fields, (void (*)(void *))fsm_msgEthereumSignTx, MFRProhibited)
    MSG_IN(MessageType_MessageType_EthereumTxAck,       EthereumTxAck_fields, (void (*)(void *))fsm_msgEthereumTxAck, MFRProhibited)

    /* Normal Raw Messages */
    RAW_IN(MessageType_MessageType_RawTxAck,            RawTxAck_fields,            (void (*)(void *))fsm_msgRawTxAck, AnyVariant)

    MSG_IN(MessageType_MessageType_FlashWrite,          FlashWrite_fields, (void (*)(void *))fsm_msgFlashWrite, MFROnly)
    MSG_IN(MessageType_MessageType_FlashHash,           FlashHash_fields, (void (*)(void *))fsm_msgFlashHash, MFROnly)
    MSG_IN(MessageType_MessageType_SoftReset,           SoftReset_fields, (void (*)(void *))fsm_msgSoftReset, MFROnly)

    /* Normal Out Messages */
    MSG_OUT(MessageType_MessageType_Success,            Success_fields,             NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_Failure,            Failure_fields,             NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_Entropy,            Entropy_fields,             NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_PublicKey,          PublicKey_fields,           NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_Features,           Features_fields,            NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_CoinTable,          CoinTable_fields,           NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_PinMatrixRequest,   PinMatrixRequest_fields,    NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_TxRequest,          TxRequest_fields,           NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_CipheredKeyValue,   CipheredKeyValue_fields,    NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_ButtonRequest,      ButtonRequest_fields,       NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_Address,            Address_fields,             NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_EntropyRequest,     EntropyRequest_fields,      NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_MessageSignature,   MessageSignature_fields,    NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_SignedIdentity,     SignedIdentity_fields,      NO_PROCESS_FUNC, AnyVariant)
/* ECIES disabled
    MSG_OUT(MessageType_MessageType_EncryptedMessage,   EncryptedMessage_fields,    NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_DecryptedMessage,   DecryptedMessage_fields,    NO_PROCESS_FUNC, AnyVariant)
*/
    MSG_OUT(MessageType_MessageType_PassphraseRequest,  PassphraseRequest_fields,   NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_TxSize,             TxSize_fields,              NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_WordRequest,        WordRequest_fields,         NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_CharacterRequest,   CharacterRequest_fields,    NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_EthereumAddress,    EthereumAddress_fields,     NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_EthereumTxRequest,  EthereumTxRequest_fields,   NO_PROCESS_FUNC, AnyVariant)

#if DEBUG_LINK
    /* Debug Messages */
    DEBUG_IN(MessageType_MessageType_DebugLinkDecision, DebugLinkDecision_fields,   NO_PROCESS_FUNC, AnyVariant)
    DEBUG_IN(MessageType_MessageType_DebugLinkGetState, DebugLinkGetState_fields, (void (*)(void *))fsm_msgDebugLinkGetState, AnyVariant)
    DEBUG_IN(MessageType_MessageType_DebugLinkStop,     DebugLinkStop_fields, (void (*)(void *))fsm_msgDebugLinkStop, AnyVariant)
#endif

    MSG_IN(MessageType_MessageType_DebugLinkFlashDump,         DebugLinkFlashDump_fields, (void (*)(void *))fsm_msgDebugLinkFlashDump, MFROnly)

#if DEBUG_LINK
    /* Debug Out Messages */
    DEBUG_OUT(MessageType_MessageType_DebugLinkState, DebugLinkState_fields,        NO_PROCESS_FUNC, AnyVariant)
    DEBUG_OUT(MessageType_MessageType_DebugLinkLog, DebugLinkLog_fields,            NO_PROCESS_FUNC, AnyVariant)
#endif

    MSG_OUT(MessageType_MessageType_DebugLinkFlashDumpResponse, DebugLinkFlashDumpResponse_fields,    NO_PROCESS_FUNC, AnyVariant)
    MSG_OUT(MessageType_MessageType_FlashHashResponse, FlashHashResponse_fields,    NO_PROCESS_FUNC, AnyVariant)
};

extern bool reset_msg_stack;

static const CoinType *fsm_getCoin(bool has_name, const char *name)
{
    const CoinType *coin;
    if (has_name) {
        coin = coinByName(name);
    } else {
        coin = coinByName("Bitcoin");
    }
    if(!coin)
    {
        fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
        layoutHome();
        return 0;
    }

    return coin;
}

static HDNode *fsm_getDerivedNode(const char *curve, uint32_t *address_n, size_t address_n_count, uint32_t *fingerprint)
{
    static HDNode CONFIDENTIAL node;
    if (fingerprint) {
        *fingerprint = 0;
    }

    if(!storage_getRootNode(&node, curve, true))
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized,
                        "Device not initialized or passphrase request cancelled");
        layoutHome();
        return 0;
    }

    if(!address_n || address_n_count == 0)
    {
        return &node;
    }

    if(hdnode_private_ckd_cached(&node, address_n, address_n_count, fingerprint) == 0)
    {
        fsm_sendFailure(FailureType_Failure_Other, "Failed to derive private key");
        layoutHome();
        return 0;
    }

    return &node;
}

#if DEBUG_LINK
static void sendFailureWrapper(FailureType code, const char *text) {
    fsm_sendFailure(code, text);
}
#endif

void fsm_init(void)
{
    msg_map_init(MessagesMap, sizeof(MessagesMap) / sizeof(MessagesMap_t));
#if DEBUG_LINK
    set_msg_failure_handler(&sendFailureWrapper);
#else
    set_msg_failure_handler(&fsm_sendFailure);
#endif

    /* set leaving handler for layout to help with determine home state */
    set_leaving_handler(&leave_home);

#if DEBUG_LINK
    set_msg_debug_link_get_state_handler(&fsm_msgDebugLinkGetState);
#endif

    msg_init();
}

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

#if DEBUG_LINK
void fsm_sendFailureDebug(FailureType code, const char *text, const char *source)
#else
void fsm_sendFailure(FailureType code, const char *text)
#endif
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

#if DEBUG_LINK
    resp->has_message = true;
    strlcpy(resp->message, source, sizeof(resp->message));
    if (text) {
        strlcat(resp->message, text, sizeof(resp->message));
    }
#else
    if (text)
    {
        resp->has_message = true;
        strlcpy(resp->message, text, sizeof(resp->message));
    }
#endif
    msg_write(MessageType_MessageType_Failure, resp);
}


void fsm_msgClearSession(ClearSession *msg)
{
    (void)msg;
    session_clear(true);
    fsm_sendSuccess("Session cleared");
}

#include "fsm_msg_common.h"
#include "fsm_msg_coin.h"
#include "fsm_msg_ethereum.h"
#include "fsm_msg_crypto.h"
#include "fsm_msg_debug.h"
