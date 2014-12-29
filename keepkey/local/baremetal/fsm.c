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

#include <ecdsa.h>
#include <aes.h>
#include <hmac.h>
#include <bip39.h>
#include <base58.h>
#include <layout.h>
#include <confirm_sm.h>
#include <pin_sm.h>
#include <passphrase_sm.h>
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
#include <util.h>
#include <signing.h>
#include <resources.h>
#include <timer.h>
#include <crypto.h>
#include <protect.h>

// message methods
static uint8_t msg_resp[MAX_FRAME_SIZE];

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
	if (protectAbortedByInitialize) {
		fsm_msgInitialize((Initialize *)0);
		protectAbortedByInitialize = false;
		return;
	}
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

	/*
	 * Vendor ID
	 */
	resp->has_vendor = true;         strlcpy(resp->vendor, "keepkey.com", sizeof(resp->vendor));

	/*
	 * Version
	 */
	resp->has_major_version = true;  resp->major_version = MAJOR_VERSION;
	resp->has_minor_version = true;  resp->minor_version = MINOR_VERSION;
	resp->has_patch_version = true;  resp->patch_version = PATCH_VERSION;

	/*
	 * Device ID
	 */
	resp->has_device_id = true;      strlcpy(resp->device_id, storage_get_uuid_str(), sizeof(resp->device_id));

	/*
	 * Security settings
	 */
	resp->has_pin_protection = true; resp->pin_protection = storage_has_pin();
	resp->has_passphrase_protection = true; resp->passphrase_protection = storage_get_passphrase_protected();

#ifdef SCM_REVISION
	int len = sizeof(SCM_REVISION) - 1;
	resp->has_revision = true; memcpy(resp->revision.bytes, SCM_REVISION, len); resp->revision.size = len;
#endif

	/*
	 * Bootloader hash
	 */
	resp->has_bootloader_hash = true; resp->bootloader_hash.size = memory_bootloader_hash(resp->bootloader_hash.bytes);

	/*
	 * Settings for device
	 */
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

	/*
	 * Coin type support
	 */
	resp->coins_count = COINS_COUNT;
	memcpy(resp->coins, coins, COINS_COUNT * sizeof(CoinType));

	/*
	 * Is device initialized?
	 */
	resp->has_initialized = true;  resp->initialized = storage_isInitialized();

	/*
	 * Are private keys imported
	 */
	//TODO:resp->has_imported = true; resp->imported = storage.has_imported && storage.imported;

	msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgPing(Ping *msg)
{
	RESP_INIT(Success);

	if(msg->has_button_protection && msg->button_protection)
		if(!confirm_ping_msg(msg->message))
		{
			layout_home();
			return;
		}

	if(msg->has_pin_protection && msg->pin_protection)
	{
		if (!pin_protect_cached())
		{
			layout_home();
			return;
		}
	}

	if(msg->has_passphrase_protection && msg->passphrase_protection) {
		if(!passphrase_protect()) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "Ping cancelled");
			layout_home();
			return;
		}
	}

	if(msg->has_message) 
    {
		resp->has_message = true;
		memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
	}

	msg_write(MessageType_MessageType_Success, resp);
	layout_home();
}

void fsm_msgChangePin(ChangePin *msg)
{
	bool removal = msg->has_remove && msg->remove;
	bool confirmed = false;

	if (removal)
	{
		if (storage_has_pin())
		{
			confirmed = confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
				"Remove Your PIN", "Are you sure you want to remove your PIN protecting this KeepKey?");
		} else {
			fsm_sendSuccess("PIN removed");
			return;
		}
	} else {
		if (storage_has_pin())
			confirmed = confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
				"Change Your PIN", "Are you sure you want to change your PIN protecting this KeepKey?");
		else
			confirmed = confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
				"Add PIN Protection", "Are you sure you want to add PIN protection this KeepKey?");
	}

	if (!confirmed)
	{
		fsm_sendFailure(FailureType_Failure_ActionCancelled, removal ? "PIN removal cancelled" : "PIN change cancelled");
		layout_home();
		return;
	}

	if (!pin_protect())
	{
		layout_home();
		return;
	}

	if (removal)
	{
		storage_set_pin(0);

		/* Setup saving animation */
		layout_loading(SAVING_ANIM);

		storage_commit();

		fsm_sendSuccess("PIN removed");
	}
	else
	{
		if (change_pin())
		{
			/* Setup saving animation */
			layout_loading(SAVING_ANIM);

			storage_commit();

			fsm_sendSuccess("PIN changed");
		}
		else
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "PIN change failed");
	}

	layout_home();
}

void fsm_msgWipeDevice(WipeDevice *msg)
{
	(void)msg;
	if(!confirm_with_button_request(ButtonRequestType_ButtonRequest_WipeDevice, "Wipe Private Keys and Settings", "Are you sure you want to erase private keys and settings? This process cannot be undone and any money stored will be lost."))
	{
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Wipe cancelled");
		layout_home();
		return;
	}

	/* Setup wipe animation */
	layout_loading(WIPE_ANIM);

	/* Wipe device */
	storage_reset();
	storage_reset_uuid();
	storage_commit();

	fsm_sendSuccess("Device wiped");
	layout_home();
}

void fsm_msgFirmwareErase(FirmwareErase *msg)
{
	(void)msg;
	fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in bootloader mode");
}

void fsm_msgFirmwareUpload(FirmwareUpload *msg)
{
	(void)msg;
	fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in bootloader mode");
}

void fsm_msgGetEntropy(GetEntropy *msg)
{
	if(!confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
		"Generate and Return Entropy", "Are you sure you would like to generate entropy using the hardware RNG, and return it to the computer client?"))
	{
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Entropy cancelled");
		layout_home();
		return;
	}

	RESP_INIT(Entropy);
	uint32_t len = msg->size;

	if (len > 1024) {
		len = 1024;
	}

	resp->entropy.size = len;
	random_buffer(resp->entropy.bytes, len);
	msg_write(MessageType_MessageType_Entropy, resp);
	layout_home();
}

void fsm_msgGetPublicKey(GetPublicKey *msg)
{
	RESP_INIT(PublicKey);

	HDNode *node = fsm_getRootNode();
	if (!node) return;

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

    if(!confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
    	"Import Recovery Sentence", "Importing a recovery sentence directly from a connected computer is not recommended unless you understand the risks."))
    {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Load cancelled");
		layout_home();
		return;
    }

	if (msg->has_mnemonic && !(msg->has_skip_checksum && msg->skip_checksum) ) {
		if (!mnemonic_check(msg->mnemonic)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "Mnemonic with wrong checksum provided");
			layout_home();
			return;
		}
	}

	storage_loadDevice(msg);

	/* Setup saving animation */
	layout_loading(SAVING_ANIM);

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
        layout_standard_notification(outstr, "CANCELLED", NOTIFICATION_INFO);
    } else {
        resp->has_request_type = true;
        resp->request_type = RequestType_TXFINISHED;
        resp->has_serialized = true;
        resp->serialized.has_serialized_tx = true;
        resp->serialized.serialized_tx.size = (uint32_t)tx_size;
        msg_write(MessageType_MessageType_TxRequest, resp);
        layout_standard_notification(outstr, "CONFIRMED", NOTIFICATION_INFO);
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
	if (msg->has_label && msg->has_language)
	{
		if(!confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
			"Change Label and Language", "Are you sure you would like to change the label to \"%s\" and the language to %s?", msg->label, msg->language))
		{
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "Apply settings cancelled");
			layout_home();
			return;
		}
	}
	else if (msg->has_label)
	{
		if(!confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
			"Change Label", "Are you sure you would like to change the label to \"%s\"?", msg->label))
		{
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "Apply settings cancelled");
			layout_home();
			return;
		}
	}
	else if (msg->has_language)
	{
		if(!confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
			"Change Language", "Are you sure you would like to change the language to %s?", msg->language))
		{
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "Apply settings cancelled");
			layout_home();
			return;
		}
	}

	if (!msg->has_label && !msg->has_language) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No setting provided");
		return;
	}

	if (!pin_protect_cached())
	{
		layout_home();
		return;
	}

	if (msg->has_label) {
		storage_setLabel(msg->label);
	}
	if (msg->has_language) {
		storage_setLanguage(msg->language);
	}

	/* Setup saving animation */
	layout_loading(SAVING_ANIM);

	storage_commit();

	fsm_sendSuccess("Settings applied");
	layout_home();
}

void fsm_msgCipherKeyValue(CipherKeyValue *msg)
{
	if (!msg->has_key) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No key provided");
		return;
	}
	if (!msg->has_value) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No value provided");
		return;
	}
	if (msg->value.size % 16) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "Value length must be a multiple of 16");
		return;
	}

	if (!pin_protect_cached())
	{
		layout_home();
		return;
	}

	HDNode *node = fsm_getRootNode();
	if (!node) return;
	fsm_deriveKey(node, msg->address_n, msg->address_n_count);

	bool encrypt = msg->has_encrypt && msg->encrypt;
	bool ask_on_encrypt = msg->has_ask_on_encrypt && msg->ask_on_encrypt;
	bool ask_on_decrypt = msg->has_ask_on_decrypt && msg->ask_on_decrypt;
	if ((encrypt && ask_on_encrypt) || (!encrypt && ask_on_decrypt)) {
		if(!confirm_cipher(encrypt, msg->key))
		{
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "CipherKeyValue cancelled");
			layout_home();
			return;
		}
	}

	uint8_t data[256 + 4];
	strlcpy((char *)data, msg->key, sizeof(data));
	strlcat((char *)data, ask_on_encrypt ? "E1" : "E0", sizeof(data));
	strlcat((char *)data, ask_on_decrypt ? "D1" : "D0", sizeof(data));

	hmac_sha512(node->private_key, 32, data, strlen((char *)data), data);

	RESP_INIT(CipheredKeyValue);
	if (encrypt) {
		aes_encrypt_ctx ctx;
		aes_encrypt_key256(data, &ctx);
		aes_cbc_encrypt(msg->value.bytes, resp->value.bytes, msg->value.size, data + 32, &ctx);
	} else {
		aes_decrypt_ctx ctx;
		aes_decrypt_key256(data, &ctx);
		aes_cbc_decrypt(msg->value.bytes, resp->value.bytes, msg->value.size, data + 32, &ctx);
	}
	resp->has_value = true;
	resp->value.size = msg->value.size;
	msg_write(MessageType_MessageType_CipheredKeyValue, resp);
	layout_home();
}

void fsm_msgClearSession(ClearSession *msg)
{
	(void)msg;
	session_clear();
	fsm_sendSuccess("Session cleared");
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

    /*
     * TODO: Implement address display
     */
    /*if (msg->has_show_display && msg->show_display) {
		layoutAddress(resp->address);
		if (!protectButton(ButtonRequestType_ButtonRequest_Address, true)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show address cancelled");
			layoutHome();
			return;
		}
	}*/

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

void fsm_msgSignMessage(SignMessage *msg)
{
	RESP_INIT(MessageSignature);

	if(!confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall, "Sign Message", msg->message.bytes))
	{
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Sign message cancelled");
		layout_home();
		return;
	}

	if (!pin_protect_cached())
	{
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

	fsm_deriveKey(node, msg->address_n, msg->address_n_count);
	uint8_t addr_raw[21];
	ecdsa_get_address_raw(node->public_key, coin->address_type, addr_raw);
	base58_encode_check(addr_raw, 21, resp->address);

	/*
	 * Sign message animation
	 */

	if (cryptoMessageSign(msg->message.bytes, msg->message.size, node->private_key, addr_raw, resp->signature.bytes) == 0) {
		resp->has_address = true;
		resp->has_signature = true;
		resp->signature.size = 65;
		msg_write(MessageType_MessageType_MessageSignature, resp);
	} else {
		fsm_sendFailure(FailureType_Failure_Other, "Error signing message");
	}

	layout_home();
}

void fsm_msgVerifyMessage(VerifyMessage *msg)
{
	if (!msg->has_address) {
		fsm_sendFailure(FailureType_Failure_Other, "No address provided");
		return;
	}
	if (!msg->has_message) {
		fsm_sendFailure(FailureType_Failure_Other, "No message provided");
		return;
	}

	/*
	 * Verifying Animation
	 */

	uint8_t addr_raw[21];
	if (!ecdsa_address_decode(msg->address, addr_raw))
	{
		fsm_sendFailure(FailureType_Failure_InvalidSignature, "Invalid address");
	}
	if (msg->signature.size == 65 && cryptoMessageVerify(msg->message.bytes, msg->message.size, addr_raw, msg->signature.bytes) == 0)
	{
		if(confirm_with_button_request(ButtonRequestType_ButtonRequest_Other, "Verify Message", msg->message.bytes))
		{
			fsm_sendSuccess("Message verified");
		}
	}
	else
	{
		fsm_sendFailure(FailureType_Failure_InvalidSignature, "Invalid signature");
	}

	layout_home();
}

void fsm_msgEncryptMessage(EncryptMessage *msg)
{
	if (!msg->has_pubkey) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No public key provided");
		return;
	}
	if (!msg->has_message) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No message provided");
		return;
	}
	curve_point pubkey;
	if (msg->pubkey.size != 33 || ecdsa_read_pubkey(msg->pubkey.bytes, &pubkey) == 0) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid public key provided");
		return;
	}
	bool display_only = msg->has_display_only && msg->display_only;
	bool signing = msg->address_n_count > 0;
	RESP_INIT(EncryptedMessage);
	const CoinType *coin = 0;
	HDNode *node = 0;
	uint8_t address_raw[21];
	if (signing) {
		coin = coinByName(msg->coin_name);
		if (!coin) {
			fsm_sendFailure(FailureType_Failure_Other, "Invalid coin name");
			return;
		}

		if (!pin_protect_cached())
		{
			layout_home();
			return;
		}

		node = fsm_getRootNode();
		if (!node) return;
		fsm_deriveKey(node, msg->address_n, msg->address_n_count);
		hdnode_fill_public_key(node);
		ecdsa_get_address_raw(node->public_key, coin->address_type, address_raw);
	}

	if(!confirm_encrypt_msg(msg->message.bytes, signing))
	{
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Encrypt message cancelled");
		layout_home();
		return;
	}

	//TODO:Encrypting animation

	if (cryptoMessageEncrypt(&pubkey, msg->message.bytes, msg->message.size, display_only, resp->nonce.bytes, (pb_size_t *)&(resp->nonce.size), resp->message.bytes, (pb_size_t *)&(resp->message.size), resp->hmac.bytes, (pb_size_t *)&(resp->hmac.size), signing ? node->private_key : 0, signing ? address_raw : 0) != 0) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Error encrypting message");
		layout_home();
		return;
	}
	resp->has_nonce = true;
	resp->has_message = true;
	resp->has_hmac = true;
	msg_write(MessageType_MessageType_EncryptedMessage, resp);
	layout_home();
}

void fsm_msgDecryptMessage(DecryptMessage *msg)
{
	if (!msg->has_nonce) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No nonce provided");
		return;
	}
	if (!msg->has_message) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No message provided");
		return;
	}
	if (!msg->has_hmac) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "No message hmac provided");
		return;
	}
	curve_point nonce_pubkey;
	if (msg->nonce.size != 33 || ecdsa_read_pubkey(msg->nonce.bytes, &nonce_pubkey) == 0) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid nonce provided");
		return;
	}

	if (!pin_protect_cached())
	{
		layout_home();
		return;
	}

	HDNode *node = fsm_getRootNode();
	if (!node) return;
	fsm_deriveKey(node, msg->address_n, msg->address_n_count);

	//TODO:Decrypting animation
	//layoutProgressSwipe("Decrypting", 0, 0);

	RESP_INIT(DecryptedMessage);
	bool display_only = false;
	bool signing = false;
	uint8_t address_raw[21];
	if (cryptoMessageDecrypt(&nonce_pubkey, msg->message.bytes, msg->message.size, msg->hmac.bytes, msg->hmac.size, node->private_key, resp->message.bytes, (pb_size_t *)&(resp->message.size), &display_only, &signing, address_raw) != 0) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Error decrypting message");
		layout_home();
		return;
	}
	if (signing) {
		base58_encode_check(address_raw, 21, resp->address);
	}

	if(!confirm_decrypt_msg(resp->message.bytes, signing ? resp->address : 0))
	{
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Decrypt message cancelled");
		layout_home();
		return;
	}

	if (display_only) {
		resp->has_address = false;
		resp->has_message = false;
		memset(resp->address, sizeof(resp->address), 0);
		memset(&(resp->message), sizeof(resp->message), 0);
	} else {
		resp->has_address = signing;
		resp->has_message = true;
	}
	msg_write(MessageType_MessageType_DecryptedMessage, resp);
	layout_home();
}

void fsm_msgRecoveryDevice(RecoveryDevice *msg)
{
    if (storage_isInitialized())
    {
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
	{'i', MessageType_MessageType_Initialize,			Initialize_fields,			(void (*)(void *))fsm_msgInitialize},
	{'i', MessageType_MessageType_Ping,					Ping_fields,				(void (*)(void *))fsm_msgPing},
	{'i', MessageType_MessageType_ChangePin,			ChangePin_fields,			(void (*)(void *))fsm_msgChangePin},
	{'i', MessageType_MessageType_WipeDevice,			WipeDevice_fields,			(void (*)(void *))fsm_msgWipeDevice},
	{'i', MessageType_MessageType_FirmwareErase,		FirmwareErase_fields,		(void (*)(void *))fsm_msgFirmwareErase},
	{'i', MessageType_MessageType_FirmwareUpload,		FirmwareUpload_fields,		(void (*)(void *))fsm_msgFirmwareUpload},
	{'i', MessageType_MessageType_GetEntropy,			GetEntropy_fields,			(void (*)(void *))fsm_msgGetEntropy},
	{'i', MessageType_MessageType_GetPublicKey,			GetPublicKey_fields,		(void (*)(void *))fsm_msgGetPublicKey},
	{'i', MessageType_MessageType_LoadDevice,			LoadDevice_fields,			(void (*)(void *))fsm_msgLoadDevice},
	{'i', MessageType_MessageType_ResetDevice,			ResetDevice_fields,			(void (*)(void *))fsm_msgResetDevice},
	{'i', MessageType_MessageType_SignTx,				SignTx_fields,				(void (*)(void *))fsm_msgSignTx},
	{'i', MessageType_MessageType_PinMatrixAck,			PinMatrixAck_fields,		0},
	{'i', MessageType_MessageType_Cancel,				Cancel_fields,				(void (*)(void *))fsm_msgCancel},
//TODO:	{'i', MessageType_MessageType_TxAck,				TxAck_fields,				(void (*)(void *))fsm_msgTxAck},
	{'i', MessageType_MessageType_CipherKeyValue,		CipherKeyValue_fields,		(void (*)(void *))fsm_msgCipherKeyValue},
	{'i', MessageType_MessageType_ClearSession,			ClearSession_fields,		(void (*)(void *))fsm_msgClearSession},
	{'i', MessageType_MessageType_ApplySettings,		ApplySettings_fields,		(void (*)(void *))fsm_msgApplySettings},
	{'i', MessageType_MessageType_ButtonAck,			ButtonAck_fields,			0},
	{'i', MessageType_MessageType_GetAddress,			GetAddress_fields,			(void (*)(void *))fsm_msgGetAddress},
	{'i', MessageType_MessageType_EntropyAck,			EntropyAck_fields,			(void (*)(void *))fsm_msgEntropyAck},
	{'i', MessageType_MessageType_SignMessage,			SignMessage_fields,			(void (*)(void *))fsm_msgSignMessage},
	{'i', MessageType_MessageType_VerifyMessage,		VerifyMessage_fields,		(void (*)(void *))fsm_msgVerifyMessage},
	{'i', MessageType_MessageType_EncryptMessage,		EncryptMessage_fields,		(void (*)(void *))fsm_msgEncryptMessage},
	{'i', MessageType_MessageType_DecryptMessage,		DecryptMessage_fields,		(void (*)(void *))fsm_msgDecryptMessage},
	{'i', MessageType_MessageType_PassphraseAck,		PassphraseAck_fields,		0},
//TODO:	{'i', MessageType_MessageType_EstimateTxSize,		EstimateTxSize_fields,		(void (*)(void *))fsm_msgEstimateTxSize},
	{'i', MessageType_MessageType_RecoveryDevice,		RecoveryDevice_fields,		(void (*)(void *))fsm_msgRecoveryDevice},
	{'i', MessageType_MessageType_WordAck,				WordAck_fields,				(void (*)(void *))fsm_msgWordAck},
	// out messages
	{'o', MessageType_MessageType_Success,				Success_fields,				0},
	{'o', MessageType_MessageType_Failure,				Failure_fields,				0},
	{'o', MessageType_MessageType_Entropy,				Entropy_fields,				0},
	{'o', MessageType_MessageType_PublicKey,			PublicKey_fields,			0},
	{'o', MessageType_MessageType_Features,				Features_fields,			0},
	{'o', MessageType_MessageType_PinMatrixRequest,		PinMatrixRequest_fields,	0},
//TODO	{'o', MessageType_MessageType_TxRequest,			TxRequest_fields,			0},
	{'o', MessageType_MessageType_CipheredKeyValue,		CipheredKeyValue_fields,	0},
	{'o', MessageType_MessageType_ButtonRequest,		ButtonRequest_fields,		0},
	{'o', MessageType_MessageType_Address,				Address_fields,				0},
	{'o', MessageType_MessageType_EntropyRequest,		EntropyRequest_fields,		0},
	{'o', MessageType_MessageType_MessageSignature,		MessageSignature_fields,	0},
	{'o', MessageType_MessageType_EncryptedMessage,		EncryptedMessage_fields,	0},
	{'o', MessageType_MessageType_DecryptedMessage,		DecryptedMessage_fields,	0},
	{'o', MessageType_MessageType_PassphraseRequest,	PassphraseRequest_fields,	0},
//TODO:	{'o', MessageType_MessageType_TxSize,				TxSize_fields,				0},
	{'o', MessageType_MessageType_WordRequest,			WordRequest_fields,			0},
	// end
	{0, 0, 0, 0}
};

static const RawMessagesMap_t RawMessagesMap[] = {
	// end
	{0,0,0}
};

void fsm_init(void)
{
	msg_map_init(MessagesMap, MESSAGE_MAP);
	msg_map_init(RawMessagesMap, RAW_MESSAGE_MAP);
	msg_failure_init(&fsm_sendFailure);
	msg_init();
}
