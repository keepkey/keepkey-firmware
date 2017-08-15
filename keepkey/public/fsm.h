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

#ifndef FSM_H
#define FSM_H

/* === Includes ============================================================ */

#include <interface.h>
#include <msg_dispatch.h>

/* === Defines ============================================================= */

#define RESP_INIT(TYPE) \
    TYPE *resp = (TYPE *) (void *) msg_resp; \
    _Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE" is too large"); \
    memset(resp, 0, sizeof(TYPE));

#define CHECK_INITIALIZED \
    if (!storage_is_initialized()) { \
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized"); \
        return; \
    } 

#define CHECK_NOT_INITIALIZED \
    if(storage_is_initialized()) { \
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, \
                        "Device is already initialized. Use Wipe first."); \
        return; \
    }

#define CHECK_PARAM(cond, errormsg) \
	if (!(cond)) { \
		fsm_sendFailure(FailureType_Failure_SyntaxError, (errormsg)); \
                go_home(); \
		return; \
	}

#define ENTROPY_BUF sizeof(((Entropy *)NULL)->entropy.bytes)

#define BTC_ADDRESS_SIZE     	35
#define RAW_TX_ACK_VARINT_COUNT	4

/* === Functions =========================================================== */

void fsm_init(void);

void fsm_sendSuccess(const char *text);
void fsm_sendFailure(FailureType code, const char *text);

void fsm_msgInitialize(Initialize *msg);
void fsm_msgGetFeatures(GetFeatures *msg);
void fsm_msgPing(Ping *msg);
void fsm_msgChangePin(ChangePin *msg);
void fsm_msgWipeDevice(WipeDevice *msg);
void fsm_msgFirmwareErase(FirmwareErase *msg);
void fsm_msgFirmwareUpload(FirmwareUpload *msg);
void fsm_msgGetEntropy(GetEntropy *msg);
void fsm_msgGetPublicKey(GetPublicKey *msg);
void fsm_msgLoadDevice(LoadDevice *msg);
void fsm_msgResetDevice(ResetDevice *msg);
void fsm_msgSignTx(SignTx *msg);
//void fsm_msgPinMatrixAck(PinMatrixAck *msg);
void fsm_msgCancel(Cancel *msg);
void fsm_msgTxAck(TxAck *msg);
void fsm_msgRawTxAck(RawMessage *msg, uint32_t frame_length);
void fsm_msgCipherKeyValue(CipherKeyValue *msg);
void fsm_msgClearSession(ClearSession *msg);
void fsm_msgApplySettings(ApplySettings *msg);
//void fsm_msgButtonAck(ButtonAck *msg);
void fsm_msgGetAddress(GetAddress *msg);
void fsm_msgEntropyAck(EntropyAck *msg);
void fsm_msgSignMessage(SignMessage *msg);
void fsm_msgVerifyMessage(VerifyMessage *msg);
void fsm_msgSignIdentity(SignIdentity *msg);
void fsm_msgEncryptMessage(EncryptMessage *msg);
void fsm_msgDecryptMessage(DecryptMessage *msg);
//void fsm_msgPassphraseAck(PassphraseAck *msg);
void fsm_msgEstimateTxSize(EstimateTxSize *msg);
void fsm_msgRecoveryDevice(RecoveryDevice *msg);
void fsm_msgWordAck(WordAck *msg);
void fsm_msgEthereumGetAddress(EthereumGetAddress *msg);
void fsm_msgEthereumSignTx(EthereumSignTx *msg);
void fsm_msgEthereumTxAck(EthereumTxAck *msg);
void fsm_msgCharacterAck(CharacterAck *msg);
void fsm_msgApplyPolicies(ApplyPolicies *msg);

#if DEBUG_LINK
//void fsm_msgDebugLinkDecision(DebugLinkDecision *msg);
void fsm_msgDebugLinkGetState(DebugLinkGetState *msg);
void fsm_msgDebugLinkStop(DebugLinkStop *msg);
#endif

#endif
