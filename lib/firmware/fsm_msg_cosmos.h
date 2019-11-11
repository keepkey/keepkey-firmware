#include "keepkey/firmware/cosmos.h"

void fsm_msgCosmosGetAddress(const CosmosGetAddress *msg)
{
    RESP_INIT(CosmosAddress);

    CHECK_INITIALIZED

    CHECK_PIN

    uint32_t fingerprint;
    const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, &fingerprint);
    if (!node) { return; }

    cosmos_getAddress(node->public_key, resp->address);

    if (msg->has_show_display && msg->show_display)
    {
        if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Share public account ID?"), "%s", resp->address))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
            layoutHome();
            return;
        }
    }

    resp->has_address = true;

    layoutHome();
    msg_write(MessageType_MessageType_CosmosAddress, resp);
}

void fsm_msgCosmosSignTx(const CosmosSignTx *msg)
{
    CHECK_INITIALIZED
    CHECK_PIN

    uint32_t fingerprint;
    const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, &fingerprint);
    if (!node) { return; }

    // Confirm transaction basics
    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Confirm Main Details"), "From: %s\nTo: %s\nAmount: %f ATOM", msg->msg.from_address, msg->msg.to_address, (float)msg->msg.amount * 1E-6))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Confirm Fee Details"), "Fee: %"PRIu32" uATOM\nGas: %"PRIu32"", msg->fee.amount, msg->fee.gas))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Confirm Aux Details"), "Memo: \"%s\"\nChain ID: %s\nAccount #: %"PRIu64"", msg->memo, msg->chain_id, msg->account_number))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    RESP_INIT(CosmosSignedTx);

    if (!cosmos_signTx(node->private_key,
                       msg->account_number,
                       msg->chain_id,
                       strlen(msg->chain_id),
                       msg->fee.amount,
                       msg->fee.gas,
                       msg->memo,
                       strlen(msg->memo),
                       msg->msg.amount,
                       msg->msg.from_address,
                       msg->msg.to_address,
                       msg->sequence,
                       resp->signature.bytes))
    {
        fsm_sendFailure(FailureType_Failure_FirmwareError,
                        _("Failed to sign transaction"));
        layoutHome();
        return;
    }
    resp->signature.size = 64;
    resp->has_signature = true;

    memcpy(resp->public_key.bytes, node->public_key, 33);
    resp->public_key.size = 33;
    resp->has_public_key = true;

    layoutHome();
    msg_write(MessageType_MessageType_CosmosSignedTx, resp);
}
