// this file was made by me and not at all copied from the trezor firmware no siree /s

#include "keepkey/firmware/stellar.h"

void fsm_msgStellarGetAddress(const StellarGetAddress *msg)
{
    RESP_INIT(StellarAddress);

    CHECK_INITIALIZED

    CHECK_PIN

    const char *coin_name = "Stellar";
    const CoinType *coin = fsm_getCoin(true, coin_name);
    if (!coin)
    {
        fsm_sendFailure(FailureType_Failure_FirmwareError,
                        _("Stellar coin type lookup failed"));
    };
    const HDNode *node = fsm_getDerivedNode(coin->curve_name, msg->address_n, msg->address_n_count, NULL);
    if (!node)
    {
        fsm_sendFailure(FailureType_Failure_ProcessError,
                        _("Failed to derive private key"));
        return;
    }
    hdnode_fill_public_key(node);

    char address[MAX_STELLAR_ADDR_SIZE];
    if (!stellar_get_address(
      node->public_key + 1,
      coin->address_type,
      address, sizeof(address))) {
        fsm_sendFailure(FailureType_Failure_ProcessError, _("Can't encode address"));
        layoutHome();
        return;
    }

    if (msg->has_show_display && msg->show_display) {
        char node_str[NODE_STRING_LENGTH];
        if (!bip32_path_to_string(node_str, sizeof(node_str), msg->address_n, msg->address_n_count)) {
            memset(node_str, 0, sizeof(node_str));
        }

        // TODO: handle mismatch and confirm
    }

    resp->has_address = true;
    strlcpy(resp->address, address, sizeof(resp->address));
    msg_write(MessageType_MessageType_StellarAddress, resp);
    layoutHome();
}
/*
void fsm_msgStellarSignTx(const StellarSignTx *msg)
{
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
}

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