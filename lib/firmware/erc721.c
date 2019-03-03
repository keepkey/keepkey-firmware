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

#include "keepkey/firmware/erc721.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/address.h"

const ERC721Token erc721s[] = {
    { "CryptoKities",             "\x06\x01\x2c\x8c\xf9\x7b\xea\xd5\xde\xae\x23\x70\x70\xf9\x58\x7f\x8e\x7a\x26\x6d" },
    { "Gods Unchained",           "\x6e\xbe\xaf\x8e\x8e\x94\x6f\x07\x16\xe6\x53\x3a\x6f\x2c\xef\xc8\x3f\x60\xe8\xab" },
    { "LucidSight-MLB-NFT",       "\x8c\x9b\x26\x1f\xae\xf3\xb3\xc2\xe6\x4a\xb5\xe5\x8e\x04\x61\x5f\x8c\x78\x80\x99" },
    { "MARBLE-NFT",               "\x1d\x96\x36\x88\xfe\x22\x09\xa9\x8d\xb3\x5c\x67\xa0\x41\x52\x48\x22\xcf\x04\xff" },
    { "MyCryptoHeroes:Land",      "\x61\x79\x13\xdd\x43\xdb\xdf\x42\x36\xb8\x5e\xc7\xbd\xf9\xad\xfd\x7e\x35\xb3\x40" },
    { "Spheroid SPACE",           "\x7b\x00\xae\x36\xc7\x48\x5b\x67\x8f\xe9\x45\xc2\xdd\x93\x49\xeb\x5b\xaf\x7b\x6b" },
    { "CryptoFlowers",            "\x8b\xc6\x7d\x00\x25\x3f\xd6\x0b\x1a\xfc\xce\x88\xb7\x88\x20\x41\x31\x39\xf4\xc6" },
    { "MyCryptoHeroes:Hero",      "\x27\x3f\x7f\x8e\x64\x89\x68\x2d\xf7\x56\x15\x1f\x55\x25\x57\x6e\x32\x2d\x51\xa3" },
    { "MyCryptoHeroes:Extension", "\xdc\xea\xf1\x65\x2a\x13\x1f\x32\xa8\x21\x46\x8d\xc0\x3a\x92\xdf\x0e\xdd\x86\xea" },
    { "EtheremonMonster",         "\x5d\x00\xd3\x12\xe1\x71\xbe\x53\x42\x06\x7c\x09\xba\xe8\x83\xf9\xbc\xb2\x00\x3b" },
    { "Flowerpatch",              "\x4f\x41\xd1\x0f\x7e\x67\xfd\x16\xbd\xe9\x16\xb4\xa6\xdc\x3d\xd1\x01\xc5\x73\x94" },
    { "Evolution Land Objects",   "\x14\xa4\x12\x3d\xa9\xad\x21\xb2\x21\x5d\xc0\xab\x69\x84\xec\x1e\x89\x84\x2c\x6d" },
    { "Guarda Token",             "\x9e\xff\xec\x6d\x60\x0e\xa9\xac\x54\x75\x78\x82\xda\x1a\xcc\xd7\x9e\x29\x2e\x50" },
    { "Decentraland LAND",        "\xf8\x7e\x31\x49\x2f\xaf\x9a\x91\xb0\x2e\xe0\xde\xaa\xd5\x0d\x51\xd5\x6d\x5d\x4d" },
    { "EtheremonAdventure",       "\xbf\xde\x62\x46\xdf\x72\xd3\xca\x86\x41\x96\x28\xca\xc4\x6a\x9d\x2b\x60\x39\x3c" },
};

const ERC721Token *erc721_byContractAddress(const uint8_t *contract) {
    for (size_t i = 0; i < sizeof(erc721s)/sizeof(erc721s[0]); i++)
        if (memcmp(contract, erc721s[i].contract, 20) == 0)
            return &erc721s[i];

    return NULL;
}

bool erc721_isKnown(const EthereumSignTx *msg)
{
    if (msg->to.size != 20)
        return false;

    return erc721_byContractAddress(msg->to.bytes);
}

bool erc721_isTransferFrom(uint32_t data_total, const EthereumSignTx *msg,
                           const HDNode *node)
{
    if (data_total != 4 + 32 + 32 + 32)
        return false;

    if (data_total != msg->data_initial_chunk.size)
        return false;

    if (memcmp(msg->data_initial_chunk.bytes, "\x23\xb8\x72\xdd", 4) != 0)
        return false;

    // 'from' padding
    if (memcmp(msg->data_initial_chunk.bytes + 4,
               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) != 0)
        return false;

    // 'to' padding
    if (memcmp(msg->data_initial_chunk.bytes + 36,
               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) != 0)
        return false;

    // As a simplification, only handle transferFrom's that take NFTs to the
    // address we're signing with.
    uint8_t my_address[20];
    if (!hdnode_get_ethereum_pubkeyhash(node, my_address))
        return false;

    if (memcmp(msg->data_initial_chunk.bytes + 36, my_address, 20) != 0)
        return false;

    return true;
}

bool erc721_confirmTransferFrom(const EthereumSignTx *msg)
{
    const ERC721Token *erc721 = erc721_byContractAddress(msg->to.bytes);
    if (!erc721)
        return false;

    char token_id[32*2+1];
    data2hex(msg->data_initial_chunk.bytes + 68, 32, token_id);

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Transfer", "Take ownership of %s token with id %s?",
                   erc721->name, token_id);
}

bool erc721_isApprove(uint32_t data_total, const EthereumSignTx *msg)
{
    if (data_total != 4 + 32 + 32)
        return false;

    if (data_total != msg->data_initial_chunk.size)
        return false;

    if (memcmp(msg->data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4) != 0)
        return false;

    // 'address' padding
    if (memcmp(msg->data_initial_chunk.bytes + 4,
               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) != 0)
        return false;

    return true;
}

bool erc721_confirmApprove(const EthereumSignTx *msg)
{
    const ERC721Token *erc721 = erc721_byContractAddress(msg->to.bytes);
    if (!erc721)
        return false;

    char address[43] = "0x";
    ethereum_address_checksum(msg->data_initial_chunk.bytes + 4,
                              address + 2, false, msg->chain_id);

    char token_id[32*2+1];
    data2hex(msg->data_initial_chunk.bytes + 68, 32, token_id);

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Approve", "Grant %s permission to take %s token with id %s?",
                   address, erc721->name, token_id);
}

