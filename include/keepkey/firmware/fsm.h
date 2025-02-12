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

#include "keepkey/transport/interface.h"
#include "keepkey/board/messages.h"

#define RESP_INIT(TYPE)                                                    \
  TYPE *resp = (TYPE *)msg_resp;                                           \
  _Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE " is too large"); \
  memset(resp, 0, sizeof(TYPE));

#define ENTROPY_BUF sizeof(((Entropy *)NULL)->entropy.bytes)

#define BTC_ADDRESS_SIZE 35
#define RAW_TX_ACK_VARINT_COUNT 4

#define STR(X) #X
#define VERSTR(X) STR(X)

void fsm_init(void);

void fsm_sendSuccess(const char *text);

void fsm_sendFailure(FailureType code, const char *text);

void fsm_msgInitialize(Initialize *msg);
void fsm_msgGetFeatures(GetFeatures *msg);
void fsm_msgGetCoinTable(GetCoinTable *msg);
void fsm_msgPing(Ping *msg);
void fsm_msgChangePin(ChangePin *msg);
void fsm_msgChangeWipeCode(ChangeWipeCode *msg);
void fsm_msgWipeDevice(WipeDevice *msg);
void fsm_msgFirmwareErase(FirmwareErase *msg);
void fsm_msgFirmwareUpload(FirmwareUpload *msg);
void fsm_msgGetEntropy(GetEntropy *msg);
void fsm_msgGetPublicKey(GetPublicKey *msg);
void fsm_msgLoadDevice(LoadDevice *msg);
void fsm_msgResetDevice(ResetDevice *msg);
void fsm_msgSignTx(SignTx *msg);
// void fsm_msgPinMatrixAck(PinMatrixAck *msg);
void fsm_msgCancel(Cancel *msg);
void fsm_msgTxAck(TxAck *msg);
void fsm_msgCipherKeyValue(CipherKeyValue *msg);
void fsm_msgClearSession(ClearSession *msg);
void fsm_msgApplySettings(ApplySettings *msg);
// void fsm_msgButtonAck(ButtonAck *msg);
void fsm_msgGetAddress(GetAddress *msg);
void fsm_msgEntropyAck(EntropyAck *msg);
void fsm_msgSignMessage(SignMessage *msg);
void fsm_msgVerifyMessage(VerifyMessage *msg);
void fsm_msgSignIdentity(SignIdentity *msg);
void fsm_msgEncryptMessage(EncryptMessage *msg);
void fsm_msgDecryptMessage(DecryptMessage *msg);
// void fsm_msgPassphraseAck(PassphraseAck *msg);
void fsm_msgRecoveryDevice(RecoveryDevice *msg);
void fsm_msgWordAck(WordAck *msg);

void fsm_msgCharacterAck(CharacterAck *msg);
void fsm_msgApplyPolicies(ApplyPolicies *msg);

#ifndef BITCOIN_ONLY
// ethereum
void fsm_msgEthereumGetAddress(EthereumGetAddress *msg);
void fsm_msgEthereumSignTx(EthereumSignTx *msg);
void fsm_msgEthereumTxAck(EthereumTxAck *msg);
void fsm_msgEthereumSignMessage(EthereumSignMessage *msg);
void fsm_msgEthereumVerifyMessage(const EthereumVerifyMessage *msg);
void fsm_msgEthereumSignTypedHash(const EthereumSignTypedHash *msg);
void fsm_msgEthereum712TypesValues(Ethereum712TypesValues *msg);

void fsm_msgNanoGetAddress(NanoGetAddress *msg);
void fsm_msgNanoSignTx(NanoSignTx *msg);

/// Modifies the RippleSignTx, setting the flag to indicate
/// that the ECDSA sig is canonical.
void fsm_msgRippleSignTx(RippleSignTx *msg);
void fsm_msgRippleGetAddress(const RippleGetAddress *msg);

void fsm_msgEosGetPublicKey(const EosGetPublicKey *msg);
void fsm_msgEosSignTx(const EosSignTx *msg);
void fsm_msgEosTxActionAck(const EosTxActionAck *msg);

void fsm_msgBinanceGetAddress(const BinanceGetAddress *msg);
void fsm_msgBinanceSignTx(const BinanceSignTx *msg);
void fsm_msgBinanceTransferMsg(const BinanceTransferMsg *msg);

void fsm_msgCosmosGetAddress(const CosmosGetAddress *msg);
void fsm_msgCosmosSignTx(const CosmosSignTx *msg);
void fsm_msgCosmosMsgAck(const CosmosMsgAck *msg);

void fsm_msgOsmosisGetAddress(const OsmosisGetAddress *msg);
void fsm_msgOsmosisSignTx(const OsmosisSignTx *msg);
void fsm_msgOsmosisMsgAck(const OsmosisMsgAck *msg);

void fsm_msgThorchainGetAddress(const ThorchainGetAddress *msg);
void fsm_msgThorchainSignTx(const ThorchainSignTx *msg);
void fsm_msgThorchainMsgAck(const ThorchainMsgAck *msg);

void fsm_msgMayachainGetAddress(const MayachainGetAddress *msg);
void fsm_msgMayachainSignTx(const MayachainSignTx *msg);
void fsm_msgMayachainMsgAck(const MayachainMsgAck *msg);

#endif  // BITCOIN_ONLY

#if DEBUG_LINK
// void fsm_msgDebugLinkDecision(DebugLinkDecision *msg);
void fsm_msgDebugLinkGetState(DebugLinkGetState *msg);
void fsm_msgDebugLinkStop(DebugLinkStop *msg);
#endif

void fsm_msgDebugLinkFlashDump(DebugLinkFlashDump *msg);
void fsm_msgFlashWrite(FlashWrite *msg);
void fsm_msgFlashHash(FlashHash *msg);
void fsm_msgSoftReset(SoftReset *msg);

#endif
