/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2019 ShapeShift
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

#include "keepkey/firmware/ethereum_contracts.h"

#include "keepkey/firmware/erc721.h"

bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx *msg,
                              const HDNode *node)
{
    if (erc721_isKnown(msg)) {
        if (erc721_isTransfer(data_total, msg))
            return true;

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
        if (erc721_isTransfer(data_total, msg))
            return erc721_confirmTransfer(msg);

        if (erc721_isTransferFrom(data_total, msg, node))
            return erc721_confirmTransferFrom(msg);

        if (erc721_isApprove(data_total, msg))
            return erc721_confirmApprove(msg);
    }

    return false;
}

