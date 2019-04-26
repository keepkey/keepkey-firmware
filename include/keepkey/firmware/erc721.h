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

#ifndef KEEPKEY_FIRMWARE_ERC721_H
#define KEEPKEY_FIRMWARE_ERC721_H

#include "trezor/crypto/bip32.h"

typedef struct _EthereumSignTx EthereumSignTx;

typedef struct {
    const char *name;
    const char *contract;
} ERC721Token;

const ERC721Token *erc721_byContractAddress(const uint8_t *contract);

bool erc721_isKnown(const EthereumSignTx *msg);

bool erc721_isTransfer(uint32_t data_total, const EthereumSignTx *msg);

bool erc721_confirmTransfer(const EthereumSignTx *msg);

bool erc721_isTransferFrom(uint32_t data_total, const EthereumSignTx *msg,
                           const HDNode *node);

bool erc721_confirmTransferFrom(const EthereumSignTx *msg);

bool erc721_isApprove(uint32_t data_total, const EthereumSignTx *msg);

bool erc721_confirmApprove(const EthereumSignTx *msg);

#endif

