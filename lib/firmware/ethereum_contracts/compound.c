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

#include "keepkey/firmware/ethereum_contracts/compound.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/address.h"

typedef struct {
    TokenType token;
    TokenType ctoken;
} CompoundContract;

static CompoundContract contracts[] = {
    // Mainnet
    {{ 1, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "ETH",   18},
     { 1, "\x4d\xdc\x2d\x19\x39\x48\x92\x6d\x02\xf9\xb1\xfe\x9e\x1d\xaa\x07\x18\x27\x0e\xd5", "cETH",   8}},
    {{ 1, "\x0d\x87\x75\xf6\x48\x43\x06\x79\xa7\x09\xe9\x8d\x2b\x0c\xb6\x25\x0d\x28\x87\xef", "BAT",   18},
     { 1, "\x6c\x8c\x6b\x02\xe7\xb2\xbe\x14\xd4\xfa\x60\x22\xdf\xd6\xd7\x59\x21\xd9\x0e\x4e", "cBAT",   8}},
    {{ 1, "\x89\xd2\x4a\x6b\x4c\xcb\x1b\x6f\xaa\x26\x25\xfe\x56\x2b\xdd\x9a\x23\x26\x03\x59", "DAI",   18},
     { 1, "\xf5\xdc\xe5\x72\x82\xa5\x84\xd2\x74\x6f\xaf\x15\x93\xd3\x12\x1f\xca\xc4\x44\xdc", "cDAI",   8}},
    {{ 1, "\x19\x85\x36\x5e\x9f\x78\x35\x9a\x9B\x6A\xD7\x60\xe3\x24\x12\xf4\xa4\x45\xE8\x62", "REP",   18},
     { 1, "\x15\x80\x79\xee\x67\xfc\xe2\xf5\x84\x72\xa9\x65\x84\xa7\x3c\x7a\xb9\xac\x95\xc1", "cREP",   8}},
    {{ 1, "\xa0\xb8\x69\x91\xc6\x21\x8b\x36\xc1\xd1\x9d\x4a\x2e\x9e\xb0\xce\x36\x06\xeb\x48", "USDC",   6},
     { 1, "\x39\xaa\x39\xc0\x21\xdf\xba\xe8\xfa\xc5\x45\x93\x66\x93\xac\x91\x7d\x5e\x75\x63", "cUSDC",  6}},
    {{ 1, "\xe4\x1d\x24\x89\x57\x1d\x32\x21\x89\x24\x6d\xaf\xa5\xeb\xde\x1f\x46\x99\xf4\x98", "ZRX",   18},
     { 1, "\xb3\x31\x9f\x5d\x18\xbc\x0d\x84\xdd\x1b\x48\x25\xdc\xde\x5d\x5f\x72\x66\xd4\x07", "cZRX",   8}},
};

static CompoundContract *contractByAddress(const uint8_t *address)
{
    for (size_t i = 0; i < sizeof(contracts)/sizeof(contracts[0]); i++) {
        if (memcmp(address, contracts[i].ctoken.address, 20) == 0)
            return &contracts[i];
    }

    return NULL;
}

static CompoundContract *contractBySymbol(uint32_t chain_id, const char *symbol)
{
    for (size_t i = 0; i < sizeof(contracts)/sizeof(contracts[0]); i++) {
        if (chain_id == contracts[i].ctoken.chain_id &&
            strcmp(symbol, contracts[i].ctoken.ticker) == 0)
            return &contracts[i];
    }

    return NULL;
}

static bool isMintCEther(const EthereumSignTx *msg)
{
    // `mint()`
    if (!ethereum_contractIsMethod(msg, "\x12\x49\xc5\x8b", 0))
        return false;

    if (contractByAddress(msg->to.bytes) != contractBySymbol(msg->chain_id, "cETH"))
        return false;

    return true;
}

static bool confirmMintCEther(const EthereumSignTx *msg)
{
    bignum256 deposit_val;
    ethereum_contractGetETHValue(msg, &deposit_val);

    char deposit[32];
    ethereumFormatAmount(&deposit_val, NULL, msg->chain_id, deposit, sizeof(deposit));

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Mint cETH from %s?", deposit);
}

static bool isMintCErc20(const EthereumSignTx *msg)
{
    // `mint(uint256)`
    if (!ethereum_contractIsMethod(msg, "\xa0\x71\x2d\x68", 1))
        return false;

    if (contractByAddress(msg->to.bytes) == contractBySymbol(msg->chain_id, "cETH"))
        return false;

    return true;
}

static bool confirmMintCErc20(const EthereumSignTx *msg)
{
    const CompoundContract *CC = contractByAddress(msg->to.bytes);
    if (!CC)
        return false;

    bignum256 value;
    bn_from_bytes(ethereum_contractGetParam(msg, 0), 32, &value);

    char deposit[32];
    ethereumFormatAmount(&value, &CC->token, msg->chain_id, deposit, sizeof(deposit));

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Mint %s from %s?", CC->ctoken.ticker, deposit);
}

static bool isRedeem(const EthereumSignTx *msg)
{
    // `redeem(uint256)`
    if (!ethereum_contractIsMethod(msg, "\xdb\x00\x6a\x75", 1))
        return false;

    return true;
}

static bool confirmRedeem(const EthereumSignTx *msg)
{
    const CompoundContract *CC = contractByAddress(msg->to.bytes);
    if (!CC)
        return false;

    bignum256 value;
    bn_from_bytes(ethereum_contractGetParam(msg, 0), 32, &value);

    char redeem[32];
    ethereumFormatAmount(&value, &CC->ctoken, msg->chain_id, redeem, sizeof(redeem));

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Redeem %s for %s?", redeem, CC->token.ticker);
}

static bool isRedeemUnderlying(const EthereumSignTx *msg)
{
    // `redeemUnderlying(uint256)`
    if (!ethereum_contractIsMethod(msg, "\x85\x2a\x12\xe3", 1))
        return false;

    return true;
}

static bool confirmRedeemUnderlying(const EthereumSignTx *msg)
{
    const CompoundContract *CC = contractByAddress(msg->to.bytes);
    if (!CC)
        return false;

    bool iscETH = CC == contractBySymbol(msg->chain_id, "cETH");

    bignum256 value;
    bn_from_bytes(ethereum_contractGetParam(msg, 0), 32, &value);

    char redeem[32];
    ethereumFormatAmount(&value, iscETH ? NULL : &CC->token, msg->chain_id, redeem, sizeof(redeem));

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Redeem %s for %s?", CC->ctoken.ticker, redeem);
}

static bool isBorrow(const EthereumSignTx *msg)
{
    // `borrow(uint256)`
    if (!ethereum_contractIsMethod(msg, "\xc5\xeb\xea\xec", 1))
        return false;

    return true;
}

static bool confirmBorrow(const EthereumSignTx *msg)
{
    const CompoundContract *CC = contractByAddress(msg->to.bytes);
    if (!CC)
        return false;

    bool iscETH = CC == contractBySymbol(msg->chain_id, "cETH");

    bignum256 value;
    bn_from_bytes(ethereum_contractGetParam(msg, 0), 32, &value);

    char borrow[32];
    ethereumFormatAmount(&value, iscETH ? NULL : &CC->token, msg->chain_id, borrow, sizeof(borrow));

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Borrow %s against %s?", borrow, CC->ctoken.ticker);
}

static bool isRepayBorrowCErc20(const EthereumSignTx *msg)
{
    // `repayBorrow(uint256)`
    if (!ethereum_contractIsMethod(msg, "\x0e\x75\x27\x02", 1))
        return false;

    if (contractByAddress(msg->to.bytes) == contractBySymbol(msg->chain_id, "cETH"))
        return false;

    return true;
}

static bool confirmRepayBorrowCErc20(const EthereumSignTx *msg)
{
    const CompoundContract *CC = contractByAddress(msg->to.bytes);
    if (!CC)
        return false;

    if (memcmp(ethereum_contractGetParam(msg, 0), "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 32) == 0)
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Repay full %s debt?", CC->token.ticker);

    bignum256 value;
    bn_from_bytes(ethereum_contractGetParam(msg, 0), 32, &value);

    char repay[32];
    ethereumFormatAmount(&value, &CC->token, msg->chain_id, repay, sizeof(repay));

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Repay %s debt?", repay);
}

static bool isRepayBorrowCEther(const EthereumSignTx *msg)
{
    // `repayBorrow()`
    if (!ethereum_contractIsMethod(msg, "\x4e\x4d\x9f\xea", 1))
        return false;

    if (contractByAddress(msg->to.bytes) != contractBySymbol(msg->chain_id, "cETH"))
        return false;

    return true;
}

static bool confirmRepayBorrowCEther(const EthereumSignTx *msg)
{
    const CompoundContract *CC = contractByAddress(msg->to.bytes);
    if (!CC)
        return false;

    bignum256 value;
    ethereum_contractGetETHValue(msg, &value);

    char repay[32];
    ethereumFormatAmount(&value, NULL, msg->chain_id, repay, sizeof(repay));

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Repay %s debt?", repay);
}

static bool isRepayBorrowBehalfCErc20(const EthereumSignTx *msg)
{
    // `repayBorrowBehalf(address,uint256)`
    if (!ethereum_contractIsMethod(msg, "\x26\x08\xf8\x18", 2))
        return false;

    if (contractByAddress(msg->to.bytes) == contractBySymbol(msg->chain_id, "cETH"))
        return false;

    return true;
}

static bool confirmRepayBorrowBehalfCErc20(const EthereumSignTx *msg)
{
    const CompoundContract *CC = contractByAddress(msg->to.bytes);
    if (!CC)
        return false;

    char borrower[43] = "0x";
    ethereum_address_checksum(ethereum_contractGetParam(msg, 0) + 12, borrower + 2, false, msg->chain_id);

    if (memcmp(ethereum_contractGetParam(msg, 1), "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 32) == 0)
        return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Repay full %s debt on behalf of %s?", CC->token.ticker, borrower);

    bignum256 value;
    bn_from_bytes(ethereum_contractGetParam(msg, 1), 32, &value);

    char repay[32];
    ethereumFormatAmount(&value, &CC->token, msg->chain_id, repay, sizeof(repay));

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Repay %s debt on behalf of %s?", repay, borrower);
}

static bool isRepayBorrowBehalfCEther(const EthereumSignTx *msg)
{
    // `repayBorrowBehalf(address)`
    if (!ethereum_contractIsMethod(msg, "\xe5\x97\x46\x19", 1))
        return false;

    if (contractByAddress(msg->to.bytes) != contractBySymbol(msg->chain_id, "cETH"))
        return false;

    return true;
}

static bool confirmRepayBorrowBehalfCEther(const EthereumSignTx *msg)
{
    const CompoundContract *CC = contractByAddress(msg->to.bytes);
    if (!CC)
        return false;

    char borrower[43] = "0x";
    ethereum_address_checksum(ethereum_contractGetParam(msg, 0) + 12, borrower + 2, false, msg->chain_id);

    bignum256 value;
    ethereum_contractGetETHValue(msg, &value);

    char repay[32];
    ethereumFormatAmount(&value, NULL, msg->chain_id, repay, sizeof(repay));

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Repay %s debt on behalf of %s?", repay, borrower);
}

static bool isLiquidateBorrowCErc20(const EthereumSignTx *msg)
{
    // `liquidateBorrow(address,uint256,address)`
    if (!ethereum_contractIsMethod(msg, "\xf5\xe3\xc4\x62", 3))
        return false;

    if (contractByAddress(msg->to.bytes) == contractBySymbol(msg->chain_id, "cETH"))
        return false;

    return true;
}

static bool confirmLiquidateBorrowCErc20(const EthereumSignTx *msg)
{
    const CompoundContract *CC = contractByAddress(msg->to.bytes);
    if (!CC)
        return false;

    char borrower[43] = "0x";
    ethereum_address_checksum(ethereum_contractGetParam(msg, 0) + 12, borrower + 2, false, msg->chain_id);

    bignum256 value;
    bn_from_bytes(ethereum_contractGetParam(msg, 1), 32, &value);

    char repay[32];
    ethereumFormatAmount(&value, &CC->token, msg->chain_id, repay, sizeof(repay));

    char collateral[43] = "0x";
    ethereum_address_checksum(ethereum_contractGetParam(msg, 2) + 12, collateral + 2, false, msg->chain_id);

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Liquidate %s debt on %s taking collateral from %s?",
                   repay, borrower, collateral);
}

static bool isLiquidateBorrowCEther(const EthereumSignTx *msg)
{
    // `liquidateBorrow(address,address)`
    if (!ethereum_contractIsMethod(msg, "\xaa\xe4\x0a\x2a", 2))
        return false;

    if (contractByAddress(msg->to.bytes) != contractBySymbol(msg->chain_id, "cETH"))
        return false;

    return true;
}

static bool confirmLiquidateBorrowCEther(const EthereumSignTx *msg)
{
    const CompoundContract *CC = contractByAddress(msg->to.bytes);
    if (!CC)
        return false;

    char borrower[43] = "0x";
    ethereum_address_checksum(ethereum_contractGetParam(msg, 0) + 12, borrower + 2, false, msg->chain_id);

    bignum256 value;
    ethereum_contractGetETHValue(msg, &value);

    char repay[32];
    ethereumFormatAmount(&value, NULL, msg->chain_id, repay, sizeof(repay));

    char collateral[43] = "0x";
    ethereum_address_checksum(ethereum_contractGetParam(msg, 1) + 12, collateral + 2, false, msg->chain_id);

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Liquidate %s debt on %s taking collateral from %s?",
                   repay, borrower, collateral);
}

static bool isEnterMarkets(const EthereumSignTx *msg)
{
    // `enterMarkets(address[])`
    if (memcmp(ethereum_contractGetMethod(msg), "\xc2\x99\x82\x38", 4) != 0)
        return false;

    bignum256 offset;
    bn_from_bytes(msg->data_initial_chunk.bytes + 4, 32, &offset);

    if (32 < bn_bitcount(&offset))
        return false;

    if (32 != bn_write_uint32(&offset))
        return false;

    bignum256 length;
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32, 32, &length);

    if (32 < bn_bitcount(&length))
        return false;

    uint32_t len = bn_write_uint32(&length);
    if (len & 0x3f)
        return false;

    return true;
}

static bool confirmEnterMarkets(const EthereumSignTx *msg)
{
    if (memcmp(msg->to.bytes, "\x3d\x98\x19\x21\x0a\x31\xb4\x96\x1b\x30\xef\x54\xbe\x2a\xed\x79\xb9\xc9\xcd\x3b", 20) != 0) {
        char comptroller[43] = "0x";
        ethereum_address_checksum(msg->to.bytes, comptroller + 2, false, msg->chain_id);

        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                     "Confirm Comptroller:\n%s", comptroller))
            return false;
    }

    bignum256 length;
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32, 32, &length);
    uint32_t len = bn_write_uint32(&length);

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Enter %" PRIu32 " markets?", len / 32);
}

static bool isExitMarket(const EthereumSignTx *msg)
{
    // `exitMarket(address)`
    if (!ethereum_contractIsMethod(msg, "\xed\xe4\xed\xd0", 1))
        return false;

    const CompoundContract *contract = contractByAddress(ethereum_contractGetParam(msg, 0));
    if (!contract)
        return false;

    return true;
}

static bool confirmExitMarket(const EthereumSignTx *msg)
{
    const CompoundContract *contract = contractByAddress(ethereum_contractGetParam(msg, 0));
    if (!contract)
        return false;

    return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Compound",
                   "Exit %s market?", contract->ctoken.ticker);
}

static bool isCTokenAction(uint32_t data_total, const EthereumSignTx *msg)
{
    if (data_total != msg->data_initial_chunk.size)
        return false;

    const CompoundContract *contract = contractByAddress(msg->to.bytes);
    if (!contract)
        return false;

    if (contract->token.chain_id != msg->chain_id)
        return false;

    if (contract->ctoken.chain_id != msg->chain_id)
        return false;



    if (isMintCEther(msg))
        return true;

    if (isMintCErc20(msg))
        return true;

    if (isRedeem(msg))
        return true;

    if (isRedeemUnderlying(msg))
        return true;

    if (isBorrow(msg))
        return true;

    if (isRepayBorrowCErc20(msg))
        return true;

    if (isRepayBorrowBehalfCErc20(msg))
        return true;

    if (isRepayBorrowCEther(msg))
        return true;

    if (isRepayBorrowBehalfCEther(msg))
        return true;

    if (isLiquidateBorrowCErc20(msg))
        return true;

    if (isLiquidateBorrowCEther(msg))
        return true;

    return false;
}

bool compound_isCompound(uint32_t data_total, const EthereumSignTx *msg)
{
    if (!msg->has_chain_id)
        return false;

    if (ethereum_contractIsProxyCall(msg))
        return false;

    if (isCTokenAction(data_total, msg))
        return true;

    if (isEnterMarkets(msg))
        return true;

    if (isExitMarket(msg))
        return data_total == msg->data_initial_chunk.size;

    return false;
}

static bool confirmCTokenAction(const EthereumSignTx *msg)
{
    if (isMintCEther(msg))
        return confirmMintCEther(msg);

    if (isMintCErc20(msg))
        return confirmMintCErc20(msg);

    if (isRedeem(msg))
        return confirmRedeem(msg);

    if (isRedeemUnderlying(msg))
        return confirmRedeemUnderlying(msg);

    if (isBorrow(msg))
        return confirmBorrow(msg);

    if (isRepayBorrowCErc20(msg))
        return confirmRepayBorrowCErc20(msg);

    if (isRepayBorrowBehalfCErc20(msg))
        return confirmRepayBorrowBehalfCErc20(msg);

    if (isRepayBorrowCEther(msg))
        return confirmRepayBorrowCEther(msg);

    if (isRepayBorrowBehalfCEther(msg))
        return confirmRepayBorrowBehalfCEther(msg);

    if (isLiquidateBorrowCErc20(msg))
        return confirmLiquidateBorrowCErc20(msg);

    if (isLiquidateBorrowCEther(msg))
        return confirmLiquidateBorrowCEther(msg);

    return false;
}

bool compound_confirmCompound(uint32_t data_total, const EthereumSignTx *msg)
{
    if (isCTokenAction(data_total, msg))
        return confirmCTokenAction(msg);

    if (isEnterMarkets(msg))
        return confirmEnterMarkets(msg);

    if (isExitMarket(msg))
        return confirmExitMarket(msg);

    return false;
}

