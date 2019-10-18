#include "keepkey/firmware/stellar.h"

void fsm_msgStellarGetAddress(const StellarGetAddress *msg)
{
    RESP_INIT(StellarAddress);

    CHECK_INITIALIZED

    CHECK_PIN

    const HDNode *node = stellar_deriveNode(msg->address_n, msg->address_n_count);
    if (!node)
    {
        fsm_sendFailure(FailureType_Failure_FirmwareError,
                        _("Failed to derive private key"));
        return;
    }

    stellar_publicAddressAsStr(node->public_key + 1, resp->address,
                               sizeof(resp->address));
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
    msg_write(MessageType_MessageType_StellarAddress, resp);
}

void fsm_msgStellarSignTx(const StellarSignTx *msg)
{
    uint32_t a = *msg->address_n;
    a = a + 1;
    /*
    CHECK_INITIALIZED
    CHECK_PIN

    if (!stellar_signingInit(msg))
    {
        fsm_sendFailure(FailureType_Failure_ProcessError,
                        _("Failed to derive private key"));
        layoutHome();
        return;
    }

    // Confirm transaction basics
    stellar_layoutTransactionSummary(msg);

    // Respond with a request for the first operation
    RESP_INIT(StellarTxOpRequest);

    msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    */
}
/*

void fsm_msgStellarCreateAccountOp(const StellarCreateAccountOp *msg)
{
    if (!stellar_confirmCreateAccountOp(msg))
        return;

    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}

void fsm_msgStellarPaymentOp(const StellarPaymentOp *msg)
{
    // This will display additional dialogs to the user
    if (!stellar_confirmPaymentOp(msg))
        return;

    // Last operation was confirmed, send a StellarSignedTx
    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}

void fsm_msgStellarPathPaymentOp(const StellarPathPaymentOp *msg)
{
    if (!stellar_confirmPathPaymentOp(msg))
        return;

    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}

void fsm_msgStellarManageOfferOp(const StellarManageOfferOp *msg)
{
    if (!stellar_confirmManageOfferOp(msg))
        return;

    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}

void fsm_msgStellarCreatePassiveOfferOp(
    const StellarCreatePassiveOfferOp *msg)
{
    if (!stellar_confirmCreatePassiveOfferOp(msg))
        return;

    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}

void fsm_msgStellarSetOptionsOp(const StellarSetOptionsOp *msg)
{
    if (!stellar_confirmSetOptionsOp(msg))
        return;

    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}

void fsm_msgStellarChangeTrustOp(const StellarChangeTrustOp *msg)
{
    if (!stellar_confirmChangeTrustOp(msg))
        return;

    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}

void fsm_msgStellarAllowTrustOp(const StellarAllowTrustOp *msg)
{
    if (!stellar_confirmAllowTrustOp(msg))
        return;

    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}

void fsm_msgStellarAccountMergeOp(const StellarAccountMergeOp *msg)
{
    if (!stellar_confirmAccountMergeOp(msg))
        return;

    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}

void fsm_msgStellarManageDataOp(const StellarManageDataOp *msg)
{
    if (!stellar_confirmManageDataOp(msg))
        return;

    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}

void fsm_msgStellarBumpSequenceOp(const StellarBumpSequenceOp *msg)
{
    if (!stellar_confirmBumpSequenceOp(msg))
        return;

    if (stellar_allOperationsConfirmed())
    {
        RESP_INIT(StellarSignedTx);

        stellar_fillSignedTx(resp);
        msg_write(MessageType_MessageType_StellarSignedTx, resp);
        layoutHome();
    }
    // Request the next operation to sign
    else
    {
        RESP_INIT(StellarTxOpRequest);

        msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
    }
}
*/