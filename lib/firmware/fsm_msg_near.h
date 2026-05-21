/*
 * NEAR Protocol FSM message handlers.
 * Included directly by fsm.c (same pattern as fsm_msg_eos.h).
 */

void fsm_msgNearGetAddress(const NearGetAddress *msg)
{
    CHECK_INITIALIZED
    CHECK_PIN

    /* Ed25519 SLIP-0010 — coin type 397, all hardened */
    HDNode *node = fsm_getDerivedNode(ED25519_NAME,
                                      msg->address_n, msg->address_n_count,
                                      NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    RESP_INIT(NearAddress);

    if (!near_getAddress(node, msg, resp)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "NEAR address cancelled");
        layoutHome();
        return;
    }

    layoutHome();
    msg_write(MessageType_MessageType_NearAddress, resp);
}

void fsm_msgNearSignTx(const NearSignTx *msg)
{
    CHECK_INITIALIZED
    CHECK_PIN

    HDNode *node = fsm_getDerivedNode(ED25519_NAME,
                                      msg->address_n, msg->address_n_count,
                                      NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    RESP_INIT(NearSignedTx);

    if (!near_signTx(node, msg, resp)) {
        fsm_sendFailure(FailureType_Failure_Other,
                        "NEAR signing failed or cancelled");
        layoutHome();
        return;
    }

    layoutHome();
    msg_write(MessageType_MessageType_NearSignedTx, resp);
}
