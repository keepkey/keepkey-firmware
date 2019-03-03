#include "keepkey/firmware/ethereum_contracts.h"

#include "keepkey/firmware/erc721.h"

bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx *msg,
                              const HDNode *node)
{
    if (erc721_isKnown(msg)) {
        if (erc721_isTransferFrom(data_total, msg, node))
            return true;

        if (erc721_isApprove(data_total, msg))
            return true;
    }

    return false;
}

bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx *msg,
                                const HDNode *node)
{
    if (erc721_isKnown(msg)) {
        if (erc721_isTransferFrom(data_total, msg, node))
            return erc721_confirmTransferFrom(msg);

        if (erc721_isApprove(data_total, msg))
            return erc721_confirmApprove(msg);
    }

    return false;
}

