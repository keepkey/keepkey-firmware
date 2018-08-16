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

static const CoinType *fsm_getCoin(const char *name)
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

static HDNode *fsm_getDerivedNode(const char *curve, uint32_t *address_n, size_t address_n_count)
{
    static HDNode CONFIDENTIAL node;

    if(!storage_get_root_node(&node, curve, true))
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

    if(hdnode_private_ckd_cached(&node, address_n, address_n_count, NULL) == 0)
    {
        fsm_sendFailure(FailureType_Failure_Other, "Failed to derive private key");
        go_home();
        return 0;
    }

    return &node;
}

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

void fsm_msgRawTxAck(RawMessage *msg, uint32_t frame_length)
{
    static RawMessageState msg_state = RAW_MESSAGE_NOT_STARTED;
    static uint32_t msg_offset = 0, skip = 0;

    /* Start raw transaction */
    if(msg_state == RAW_MESSAGE_NOT_STARTED)
    {
        msg_state = RAW_MESSAGE_STARTED;
        skip = parse_pb_varint(msg, RAW_TX_ACK_VARINT_COUNT);
    }

    /* Parse raw transaction */
    if(msg_state == RAW_MESSAGE_STARTED)
    {
        msg_offset += msg->length;

        parse_raw_txack(msg->buffer, msg->length);

        /* Finish raw transaction */
        if(msg_offset >= frame_length - skip)
        {
            msg_offset = 0;
            skip = 0;
            msg_state = RAW_MESSAGE_NOT_STARTED;
        }
    }
}

void fsm_msgClearSession(ClearSession *msg)
{
    (void)msg;
    session_clear(true);
    fsm_sendSuccess("Session cleared");
}

void fsm_msgEstimateTxSize(EstimateTxSize *msg)
{
    RESP_INIT(TxSize);
    resp->has_tx_size = true;
    resp->tx_size = transactionEstimateSize(msg->inputs_count, msg->outputs_count);
    msg_write(MessageType_MessageType_TxSize, resp);
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
        storage_dumpNode(&resp->node, storage_get_node());
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

void fsm_msgDebugLinkFlashDump(DebugLinkFlashDump *msg)
{
#ifndef EMULATOR
    if (!msg->has_length || msg->length > sizeof(((DebugLinkFlashDumpResponse *)0)->data.bytes)) {
#endif
        fsm_sendFailure(FailureType_Failure_Other, "Invalid FlashDump parameters");
        go_home();
        return;
#ifndef EMULATOR
    }

    RESP_INIT(DebugLinkFlashDumpResponse);

#  if DEBUG_LINK
    memcpy(resp->data.bytes, (void*)msg->address, msg->length);
#  else
    if (variant_mfr_flashDump)
        variant_mfr_flashDump(resp->data.bytes, (void*)msg->address, msg->length);
#  endif

    resp->has_data = true;
    resp->data.size = msg->length;
    msg_write(MessageType_MessageType_DebugLinkFlashDumpResponse, resp);
#endif
}

void fsm_msgSoftReset(SoftReset *msg) {
    (void)msg;
    if (variant_mfr_softReset)
        variant_mfr_softReset();
    else {
        fsm_sendFailure(FailureType_Failure_Other, "SoftReset: unsupported outside of MFR firmware");
        go_home();
    }
}

void fsm_msgFlashWrite(FlashWrite *msg) {
#ifndef EMULATOR
    if (!variant_mfr_flashWrite || !variant_mfr_flashHash ||
        !variant_mfr_sectorFromAddress || !variant_mfr_sectorLength ||
        !variant_mfr_sectorStart) {
#endif
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: this isn't MFR firmware");
        go_home();
        return;
#ifndef EMULATOR
    }

    if (!msg->has_address || !msg->has_data || msg->data.size > 1024) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: invalid parameters");
        go_home();
        return;
    }

    uint8_t sector = variant_mfr_sectorFromAddress((uint8_t*)msg->address);
    if (variant_mfr_sectorLength(sector) < (uint8_t*)msg->address -
                                  (uint8_t*)variant_mfr_sectorStart(sector) +
                                  msg->data.size) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: write must not span more than one sector");
        go_home();
        return;
    }

    _Static_assert(FLASH_BOOTSTRAP_SECTOR_FIRST == FLASH_BOOTSTRAP_SECTOR_LAST,
                   "Bootstrap isn't one sector?");
    if (FLASH_BOOTSTRAP_SECTOR_FIRST == sector ||
        (FLASH_VARIANT_SECTOR_FIRST <= sector &&
         sector <= FLASH_VARIANT_SECTOR_LAST) ||
        (FLASH_BOOT_SECTOR_FIRST <= sector &&
         sector <= FLASH_BOOT_SECTOR_LAST)) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: cannot write to read-only sector");
        go_home();
        return;
    }

    if (!variant_mfr_flashWrite((uint8_t*)msg->address, msg->data.bytes, msg->data.size,
                                 msg->has_erase ? msg->erase : false)) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: write failed");
        go_home();
        return;
    }

    if (memcmp((void*)msg->address, (void*)msg->data.bytes, msg->data.size) != 0) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: write / read-back mismatch");
        go_home();
        return;
    }

    RESP_INIT(FlashHashResponse);

    if (!variant_mfr_flashHash((uint8_t*)msg->address, msg->data.size, 0, 0,
                                resp->data.bytes, sizeof(resp->data.bytes))) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: FlashHash failed");
        go_home();
        return;
    }

    resp->has_data = true;
    resp->data.size = sizeof(resp->data.bytes);
    msg_write(MessageType_MessageType_FlashHashResponse, resp);
#endif
}

void fsm_msgFlashHash(FlashHash *msg) {
#ifndef EMULATOR
    if (!variant_mfr_flashHash) {
#endif
        fsm_sendFailure(FailureType_Failure_Other, "FlashHash: this isn't MFR firmware");
        go_home();
        return;
#ifndef EMULATOR
    }

    if (!msg->has_address || !msg->has_length || !msg->has_challenge) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashHash: invalid parameters");
        go_home();
        return;
    }

    RESP_INIT(FlashHashResponse);

    if (!variant_mfr_flashHash((uint8_t*)msg->address, msg->length,
                                msg->challenge.bytes, msg->challenge.size,
                                resp->data.bytes, sizeof(resp->data.bytes))) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashHash: failed");
        go_home();
        return;
    }

    resp->has_data = true;
    resp->data.size = sizeof(resp->data.bytes);
    msg_write(MessageType_MessageType_FlashHashResponse, resp);
#endif
}

#include "fsm_msg_common.h"
#include "fsm_msg_coin.h"
#include "fsm_msg_ethereum.h"
#include "fsm_msg_crypto.h"
