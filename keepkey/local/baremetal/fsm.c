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

#include <stdio.h>

#include <crypto.h>
#include <layout.h>
#include <confirm_sm.h>

#include <fsm.h>
#include <messages.h>
#include <storage.h>
#include <coins.h>
#include <debug.h>
#include <transaction.h>
#include <rand.h>
#include <storage.h>
#include <protect.h>
#include <reset.h>
#include <recovery.h>
#include <memory.h>
#include <usb.h>
#include <util.h>
#include <signing.h>



// message methods
static uint8_t msg_resp[MSG_OUT_SIZE];

#define RESP_INIT(TYPE) TYPE *resp = (TYPE *)msg_resp; memset(resp, 0, sizeof(TYPE));

void fsm_sendSuccess(const char *text)
{
	RESP_INIT(Success);
	if (text) {
		resp->has_message = true;
		strlcpy(resp->message, text, sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Success, resp);
}

void fsm_sendFailure(FailureType code, const char *text)
{
	RESP_INIT(Failure);
	resp->has_code = true;
	resp->code = code;
	if (text) {
		resp->has_message = true;
		strlcpy(resp->message, text, sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Failure, resp);
}

HDNode *fsm_getRootNode(void)
{
	static HDNode node;
	if (!storage_getRootNode(&node)) {
		layout_home();
		fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized or passphrase request cancelled");
		return 0;
	}
	return &node;
}

void fsm_deriveKey(HDNode *node, uint32_t *address_n, size_t address_n_count)
{
    size_t i;

    for (i = 0; i < address_n_count; i++) {
        hdnode_private_ckd(node, address_n[i]);
    }
}

void fsm_msgInitialize(Initialize *msg)
{
	(void)msg;
	recovery_abort();
	signing_abort();
	RESP_INIT(Features);
	resp->has_vendor = true;         strlcpy(resp->vendor, "keepkey.com", sizeof(resp->vendor));
	resp->has_major_version = true;  resp->major_version = 0;
	resp->has_minor_version = true;  resp->minor_version = 0;
	resp->has_patch_version = true;  resp->patch_version = 0;

        resp->has_device_id = false;
	//resp->has_device_id = true;      strlcpy(resp->device_id, storage_get_uuid_str(), sizeof(resp->device_id));

        resp->has_passphrase_protection = false;
//        resp->has_passphrase_protection = true; resp->passphrase_protection = storage_get_passphrase_protected();

#ifdef SCM_REVISION
	resp->has_revision = true; memcpy(resp->revision.bytes, SCM_REVISION, sizeof(resp->revision)); resp->revision.size = SCM_REVISION_LEN;
#endif
	resp->has_bootloader_hash = true; 
        resp->bootloader_hash.size = memory_bootloader_hash(resp->bootloader_hash.bytes);

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

	resp->coins_count = COINS_COUNT;
	memcpy(resp->coins, coins, COINS_COUNT * sizeof(CoinType));
	resp->has_initialized = true;  resp->initialized = storage_isInitialized();
	msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgPing(Ping *msg)
{
	RESP_INIT(Success);
	msg_write(MessageType_MessageType_Success, resp);
	layout_home();
}

void fsm_msgWipeDevice(WipeDevice *msg)
{
    (void)msg;
    if(confirm("Wipe Private Keys and Settings", "Are you sure you want to erase private keys and settings? Any money stored will be lost."))
    {
        storage_reset();
        storage_commit();

        fsm_sendSuccess("Device wiped");
        layout_home();
    } else {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Wipe cancelled");
        layout_home();
    }
}

void fsm_msgGetPublicKey(GetPublicKey *msg)
{
	RESP_INIT(PublicKey);

	HDNode *node = fsm_getRootNode();
	if (!node) return;

        layout_standard_notification("Preparing Keys...", "This may take a moment.");
	fsm_deriveKey(node, msg->address_n, msg->address_n_count);

	resp->node.depth = node->depth;
	resp->node.fingerprint = node->fingerprint;
	resp->node.child_num = node->child_num;
	resp->node.chain_code.size = 32;
	memcpy(resp->node.chain_code.bytes, node->chain_code, 32);
	resp->node.has_private_key = false;
	resp->node.has_public_key = true;
	resp->node.public_key.size = 33;
	memcpy(resp->node.public_key.bytes, node->public_key, 33);

	msg_write(MessageType_MessageType_PublicKey, resp);
	layout_home();
}

void fsm_msgLoadDevice(LoadDevice *msg)
{
    if (storage_isInitialized()) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Device is already initialized. Use Wipe first.");
        return;
    }

    storage_loadDevice(msg);
    storage_commit();
    fsm_sendSuccess("Device loaded");
    layout_home();
}

void fsm_msgResetDevice(ResetDevice *msg)
{
    if (storage_isInitialized()) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Device is already initialized. Use Wipe first.");
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
    if (msg->inputs_count < 1) {
        fsm_sendFailure(FailureType_Failure_Other, "Transaction must have at least one input");
        layout_home();
        return;
    }

    if (msg->outputs_count < 1) {
        fsm_sendFailure(FailureType_Failure_Other, "Transaction must have at least one output");
        layout_home();
        return;
    }

    HDNode *node = fsm_getRootNode();
    if (!node) return;
    const CoinType *coin = coinByName(msg->coin_name);
    if (!coin) {
        fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
        layout_home();
        return;
    }

    signing_init(msg->inputs_count, msg->outputs_count, coin, node);
}

void fsm_msgSimpleSignTx(SimpleSignTx *msg)
{
    RESP_INIT(TxRequest);

    if (msg->inputs_count < 1) {
        fsm_sendFailure(FailureType_Failure_Other, "Transaction must have at least one input");
        layout_home();
        return;
    }

    if (msg->outputs_count < 1) {
        fsm_sendFailure(FailureType_Failure_Other, "Transaction must have at least one output");
        layout_home();
        return;
    }

    HDNode *node = fsm_getRootNode();
    if (!node) return;
    const CoinType *coin = coinByName(msg->coin_name);
    if (!coin) {
        fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
        layout_home();
        return;
    }

    uint32_t version = 1;
    uint32_t lock_time = 0;
    int tx_size = transactionSimpleSign(coin, node, msg->inputs, msg->inputs_count, msg->outputs, msg->outputs_count, version, lock_time, resp->serialized.serialized_tx.bytes);
    if (tx_size < 0) {
        fsm_sendFailure(FailureType_Failure_Other, "Signing cancelled by user");
        layout_home();
        return;
    }
    if (tx_size == 0) {
        fsm_sendFailure(FailureType_Failure_Other, "Error signing transaction");
        layout_home();
        return;
    }

    size_t i, j;

    // determine change address
    uint64_t change_spend = 0;
    for (i = 0; i < msg->outputs_count; i++) {
        if (msg->outputs[i].address_n_count > 0) { // address_n set -> change address
            if (change_spend == 0) { // not set
                change_spend = msg->outputs[i].amount;
            } else {
                fsm_sendFailure(FailureType_Failure_Other, "Only one change output allowed");
                layout_home();
                return;
            }
        }
    }

    // check origin transactions
    uint8_t prev_hashes[ pb_arraysize(SimpleSignTx, transactions) ][32];
    for (i = 0; i < msg->transactions_count; i++) {
        if (!transactionHash(&(msg->transactions[i]), prev_hashes[i])) {
            memset(prev_hashes[i], 0, 32);
        }
    }

    // calculate spendings
    uint64_t to_spend = 0;
    bool found;
    for (i = 0; i < msg->inputs_count; i++) {
        found = false;
        for (j = 0; j < msg->transactions_count; j++) {
            if (memcmp(msg->inputs[i].prev_hash.bytes, prev_hashes[j], 32) == 0) { // found prev TX
                if (msg->inputs[i].prev_index < msg->transactions[j].bin_outputs_count) {
                    to_spend += msg->transactions[j].bin_outputs[msg->inputs[i].prev_index].amount;
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            fsm_sendFailure(FailureType_Failure_Other, "Invalid prevhash");
            layout_home();
            return;
        }
    }

    uint64_t spending = 0;
    for (i = 0; i < msg->outputs_count; i++) {
        spending += msg->outputs[i].amount;
    }

    if (spending > to_spend) {
        fsm_sendFailure(FailureType_Failure_NotEnoughFunds, "Insufficient funds");
        layout_home();
        return;
    }

    uint64_t fee = to_spend - spending;
    if (fee > (((uint64_t)tx_size + 999) / 1000) * coin->maxfee_kb) {

        char linebuf[layout_char_width()];
        snprintf(linebuf, sizeof(linebuf), "Fee over threshold: %s", satoshi_to_str(fee, true));
        if(!confirm("Confirm?", linebuf))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Fee over threshold. Signing cancelled.");
            layout_home();
            return;        
        }
    }

    // last confirmation
    char outstr[layout_char_width()+1];

    snprintf(outstr, sizeof(outstr), "Confirm tx: %s  FEE(%s)?", 
            satoshi_to_str(to_spend - change_spend - fee, true),
            satoshi_to_str(fee, true));
    if(!confirm("Confirm?", outstr)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled by user");
        layout_standard_notification(outstr, "CANCELLED");
    } else {
        resp->has_request_type = true;
        resp->request_type = RequestType_TXFINISHED;
        resp->has_serialized = true;
        resp->serialized.has_serialized_tx = true;
        resp->serialized.serialized_tx.size = (uint32_t)tx_size;
        msg_write(MessageType_MessageType_TxRequest, resp);
        layout_standard_notification(outstr, "CONFIRMED");
    }

    layout_home();
}

void fsm_msgCancel(Cancel *msg)
{
    (void)msg;
    recovery_abort();
    signing_abort();
}

void fsm_msgTxAck(TxAck *msg)
{
    if (msg->has_tx) {
        signing_txack(&(msg->tx));
    } else {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No transaction provided");
    }
}

void fsm_msgApplySettings(ApplySettings *msg)
{
    if(msg->has_label)
    {
        if(!confirm("Change label to: \"%s\"?", msg->label))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Apply settings cancelled");
            layout_home();
            return;
        } else {
            storage_setLabel(msg->label);
            storage_commit();
        }
    }

    fsm_sendSuccess("Settings applied");
    layout_home();
}

void fsm_msgGetAddress(GetAddress *msg)
{
    RESP_INIT(Address);

    HDNode *node = fsm_getRootNode();
    if (!node) return;
    const CoinType *coin = coinByName(msg->coin_name);
    if (!coin) {
        fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
        layout_home();
        display_refresh();
        return;
    }

    fsm_deriveKey(node, msg->address_n, msg->address_n_count);

    ecdsa_get_address(node->public_key, coin->address_type, resp->address);

    msg_write(MessageType_MessageType_Address, resp);
    layout_home();
    display_refresh();
}

void fsm_msgEntropyAck(EntropyAck *msg)
{
	if (msg->has_entropy) {
		reset_entropy(msg->entropy.bytes, msg->entropy.size);
	} else {
		reset_entropy(0, 0);
	}
}

void fsm_msgRecoveryDevice(RecoveryDevice *msg)
{
    if (storage_isInitialized()) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Device is already initialized. Use Wipe first.");
        return;
    }
    recovery_init(
            msg->has_word_count ? msg->word_count : 12,
            msg->has_passphrase_protection && msg->passphrase_protection,
            msg->has_pin_protection && msg->pin_protection,
            msg->has_language ? msg->language : 0,
            msg->has_label ? msg->label : 0,
            msg->has_enforce_wordlist ? msg->enforce_wordlist : false
            );
}

void fsm_msgWordAck(WordAck *msg)
{
    recovery_word(msg->word);
}

static const MessagesMap_t MessagesMap[] = {
    // in messages
    {'i', MessageType_MessageType_Initialize,		Initialize_fields,	(void (*)(void *))fsm_msgInitialize},
    {'i', MessageType_MessageType_Ping,			Ping_fields,		(void (*)(void *))fsm_msgPing},
    {'o', MessageType_MessageType_Features,	        Features_fields,	0},
    {'i', MessageType_MessageType_SignTx,	        SignTx_fields,		(void (*)(void *))fsm_msgSignTx},
    {'o', MessageType_MessageType_Success,	        Success_fields,		0},
    {'o', MessageType_MessageType_Failure,	        Failure_fields,		0},
    {'i', MessageType_MessageType_GetAddress,		GetAddress_fields,	(void (*)(void *))fsm_msgGetAddress},
    {'i', MessageType_MessageType_ResetDevice,		ResetDevice_fields,	(void (*)(void *))fsm_msgResetDevice},
    {'o', MessageType_MessageType_EntropyRequest,        EntropyRequest_fields,	0},
    {'i', MessageType_MessageType_EntropyAck,		EntropyAck_fields,	(void (*)(void *))fsm_msgEntropyAck},
    {'i', MessageType_MessageType_WipeDevice,		WipeDevice_fields,	(void (*)(void *))fsm_msgWipeDevice},
    {'i', MessageType_MessageType_GetPublicKey,	GetPublicKey_fields,	(void (*)(void *))fsm_msgGetPublicKey},
    {'i', MessageType_MessageType_LoadDevice,		LoadDevice_fields,	(void (*)(void *))fsm_msgLoadDevice},
    {'i', MessageType_MessageType_ResetDevice,		ResetDevice_fields,	(void (*)(void *))fsm_msgResetDevice},
    {'i', MessageType_MessageType_SignTx,		SignTx_fields,		(void (*)(void *))fsm_msgSignTx},
    //UNUSED BY TREZOR NOW {'i', MessageType_MessageType_SimpleSignTx,	SimpleSignTx_fields,	(void (*)(void *))fsm_msgSimpleSignTx},
    {'i', MessageType_MessageType_Cancel,		Cancel_fields,		(void (*)(void *))fsm_msgCancel},
    //TODO: {'i', MessageType_MessageType_TxAck,		TxAck_fields,		(void (*)(void *))fsm_msgTxAck},
    {'i', MessageType_MessageType_ApplySettings,	ApplySettings_fields,	(void (*)(void *))fsm_msgApplySettings},
    {'o', MessageType_MessageType_Address,		Address_fields,	        0},
    {'i', MessageType_MessageType_EntropyAck,		EntropyAck_fields,	(void (*)(void *))fsm_msgEntropyAck},
    {'i', MessageType_MessageType_RecoveryDevice,	RecoveryDevice_fields,	(void (*)(void *))fsm_msgRecoveryDevice},
    {'i', MessageType_MessageType_WordAck,		WordAck_fields,		(void (*)(void *))fsm_msgWordAck},
    {'o', MessageType_MessageType_WordRequest,		WordRequest_fields,	0},

    {0,0,0,0}
};

void fsm_init(void)
{
    msg_init(MessagesMap);
}

