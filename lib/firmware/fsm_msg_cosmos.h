#include "keepkey/firmware/stellar.h"

void fsm_msgCosmosGetAddress(const CosmosGetAddress *msg)
{
    RESP_INIT(CosmosAddress);

    CHECK_INITIALIZED

    CHECK_PIN

    // const HDNode *node = stellar_deriveNode(msg->address_n, msg->address_n_count);
    // if (!node)
    // {
    //     fsm_sendFailure(FailureType_Failure_FirmwareError,
    //                     _("Failed to derive private key"));
    //     return;
    // }

    // stellar_publicAddressAsStr(node->public_key + 1, resp->address,
    //                            sizeof(resp->address));
    // if (msg->has_show_display && msg->show_display)
    // {
    //     if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Share public account ID?"), "%s", resp->address))
    //     {
    //         fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    //         layoutHome();
    //         return;
    //     }
    // }

    // resp->has_address = true;

    // layoutHome();
    // msg_write(MessageType_MessageType_StellarAddress, resp);
}

void fsm_msgCosmosSignTx(const CosmosSignTx *msg)
{
    CHECK_INITIALIZED
    CHECK_PIN

    // if (!stellar_signingInit(msg))
    // {
        // fsm_sendFailure(FailureType_Failure_FirmwareError,
                        // _("Failed to derive private key"));
        // layoutHome();
        // return;
    // }

    // Confirm transaction basics
    // stellar_layoutTransactionSummary(msg);

    // Respond with a request for the first operation
    RESP_INIT(CosmosSignedTx);

    // msg_write(MessageType_MessageType_StellarTxOpRequest, resp);
}
