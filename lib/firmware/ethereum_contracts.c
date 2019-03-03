#include "keepkey/firmware/ethereum_contracts.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/address.h"

typedef struct {
    const char *name;
    const char *contract;
} ERC721Token;

const ERC721Token erc721s[] = {
   { "CryptoKitty", "\x06\x01\x2c\x8c\xf9\x7b\xea\xd5\xde\xae\x23\x70\x70\xf9\x58\x7f\x8e\x7a\x26\x6d" },
};

static const ERC721Token *erc721ByContractAddress(const uint8_t *contract) {
    for (size_t i = 0; i < sizeof(erc721s)/sizeof(erc721s[0]); i++)
        if (memcmp(contract, erc721s[i].contract, 20) == 0)
            return &erc721s[i];

    return NULL;
}

static bool isKnownERC721(const EthereumSignTx *msg)
{
    if (msg->to.size != 20)
        return false;

    return erc721ByContractAddress(msg->to.bytes);
}

static bool isERC721TransferFrom(uint32_t data_total, const EthereumSignTx *msg,
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

static bool confirmERC721TransferFrom(const EthereumSignTx *msg)
{
    const ERC721Token *erc721 = erc721ByContractAddress(msg->to.bytes);
    if (!erc721)
        return false;

    char token_id[32*2+1];
    data2hex(msg->data_initial_chunk.bytes + 68, 32, token_id);

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Transfer", "Take ownership of %s with id %s?",
                   erc721->name, token_id);
}

static bool isERC721Approve(uint32_t data_total, const EthereumSignTx *msg)
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

static bool confirmERC721Approve(const EthereumSignTx *msg)
{
    const ERC721Token *erc721 = erc721ByContractAddress(msg->to.bytes);
    if (!erc721)
        return false;

    char address[43] = "0x";
    ethereum_address_checksum(msg->data_initial_chunk.bytes + 4,
                              address + 2, false, msg->chain_id);

    char token_id[32*2+1];
    data2hex(msg->data_initial_chunk.bytes + 68, 32, token_id);

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Approve", "Grant %s permission to take %s with id %s?",
                   address, erc721->name, token_id);
}


bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx *msg,
                              const HDNode *node)
{
    if (isKnownERC721(msg)) {
        if (isERC721TransferFrom(data_total, msg, node))
            return true;

        if (isERC721Approve(data_total, msg))
            return true;
    }

    return false;
}

bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx *msg,
                                const HDNode *node)
{
    if (isKnownERC721(msg)) {
        if (isERC721TransferFrom(data_total, msg, node))
            return confirmERC721TransferFrom(msg);

        if (isERC721Approve(data_total, msg))
            return confirmERC721Approve(msg);
    }

    return false;
}

