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

#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts/compound.h"
#include "keepkey/firmware/ethereum_contracts/makerdao.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/bignum.h"

bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx *msg,
                              const HDNode *node)
{
    (void)node;

    if (makerdao_isMakerDAO(data_total, msg))
        return true;

    if (compound_isCompound(data_total, msg))
        return true;

    return false;
}

bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx *msg,
                                const HDNode *node)
{
    (void)node;

    if (makerdao_isMakerDAO(data_total, msg))
        return makerdao_confirmMakerDAO(data_total, msg);

    if (compound_isCompound(data_total, msg))
        return compound_confirmCompound(data_total, msg);

    return false;
}

bool ethereum_contractIsMethod(const EthereumSignTx *msg, const char *hash,
                              size_t arg_count)
{
    if (ethereum_contractIsProxyCall(msg)) {
        if (!ethereum_contractHasProxiedParams(msg, arg_count))
            return false;

        if (memcmp(ethereum_contractGetProxiedMethod(msg), hash, 4) != 0)
            return false;

        return true;
    }

    if (!ethereum_contractHasParams(msg, arg_count))
        return false;

    if (memcmp(ethereum_contractGetMethod(msg), hash, 4) != 0)
        return false;

    return true;
}

const uint8_t *ethereum_contractGetMethod(const EthereumSignTx *msg)
{
    return msg->data_initial_chunk.bytes;
}

bool ethereum_contractHasParams(const EthereumSignTx *msg, size_t count)
{
    return msg->data_initial_chunk.size == 4 + count * 32;
}

const uint8_t *ethereum_contractGetParam(const EthereumSignTx *msg, size_t idx)
{
    if (ethereum_contractIsProxyCall(msg)) {
        return msg->data_initial_chunk.bytes + 4 + 3 * 32 + 4 + idx * 32;
    }

    return msg->data_initial_chunk.bytes + 4 + idx * 32;
}

bool ethereum_contractHasProxiedParams(const EthereumSignTx *msg, size_t count)
{
    return msg->data_initial_chunk.size == 4 + 3 * 32 + 4 + count * 32 + (32 - 4);
}

const uint8_t *ethereum_contractGetProxiedMethod(const EthereumSignTx *msg)
{
    return msg->data_initial_chunk.bytes + 4 + 3 * 32;
}

bool ethereum_contractIsProxyCall(const EthereumSignTx *msg) {
    if (memcmp(msg->data_initial_chunk.bytes, "\x1c\xff\x79\xcd", 4) != 0)
        return false;

    if (msg->data_initial_chunk.size < 4 + 32 + 32 + 32)
        return false;

    bignum256 offset;
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32, 32, &offset);

    if (32 < bn_bitcount(&offset))
        return false;

    if (64 != bn_write_uint32(&offset))
        return false;

    bignum256 length;
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32 + 32, 32, &length);

    if (32 < bn_bitcount(&length))
        return false;

    if (msg->data_initial_chunk.size == 4 + 3 * 32 + (bn_write_uint32(&length) - 4))
        return false;

    return true;
}

void ethereum_contractGetETHValue(const EthereumSignTx *msg, bignum256 *val)
{
    uint8_t pad_val[32];
    memset(pad_val, 0, sizeof(pad_val));
    memcpy(pad_val + (32 - msg->value.size), msg->value.bytes, msg->value.size);
    bn_read_be(pad_val, val);
}

bool ethereum_contractIsETHValueZero(const EthereumSignTx *msg) {
    bignum256 val;
    ethereum_contractGetETHValue(msg, &val);
    return bn_is_zero(&val);
}

