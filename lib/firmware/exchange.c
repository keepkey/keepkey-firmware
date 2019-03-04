/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2015 KeepKey LLC
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

#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/util.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/crypto.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/exchange.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/policy.h"
#include "types.pb.h"

#include <string.h>
#include <stdio.h>

/* exchange error variable */
static ExchangeError exchange_error = NO_EXCHANGE_ERROR;

/* exchange public key for signature varification */
static const char *ShapeShift_pubkey = "1HxFWu1wM88q1aLkfUmpZBjhTWcdXGB6gT";

/* exchange API Key */
static const uint8_t ShapeShift_api_key[64] =
{
    0x6a, 0xd5, 0x83, 0x1b, 0x77, 0x84, 0x84, 0xbb, 0x84, 0x9d, 0xa4, 0x51,
    0x80, 0xac, 0x35, 0x04, 0x78, 0x48, 0xe5, 0xca, 0xc0, 0xfa, 0x66, 0x64,
    0x54, 0xf4, 0xff, 0x78, 0xb8, 0xc7, 0x39, 0x9f, 0xea, 0x6a, 0x8c, 0xe2,
    0xc7, 0xee, 0x62, 0x87, 0xbc, 0xd7, 0x8d, 0xb6, 0x61, 0x0c, 0xa3, 0xf5,
    0x38, 0xd6, 0xb3, 0xe9, 0x0c, 0xa8, 0x0c, 0x8e, 0x63, 0x68, 0xb6, 0x02,
    0x14, 0x45, 0x95, 0x0b
};

/*
 * exchange_tx_layout_str() - assemble display message for exchange transaction output
 *
 * INPUT
 *      coint   - coin type being process
 *      amt     - pointer to coin amount
 *      amt     - size of amount buffer
 *      out     - porint to output buffer
 *      out_len - size of output buffer
 *
 * OUTPUT
 *      true/false - status
 *
 */
static bool exchange_tx_layout_str(const CoinType *coin, const uint8_t *amt, size_t amt_len, char *out, size_t out_len)
{
    const TokenType *token = NULL;
    if (!isEthereumLike(coin->coin_name) && coin->has_contract_address) {
        if (!coin->has_forkid)
            return false;

        token = tokenByChainAddress(coin->forkid, coin->contract_address.bytes);
    }

    if (isEthereumLike(coin->coin_name) || token) {
        if (!coin->has_forkid)
            return false;

        bignum256 value;
        bn_from_bytes(amt, amt_len, &value);
        ethereumFormatAmount(&value, token, coin->forkid, out, out_len);
        return true;
    }

    if (amt_len <= sizeof(uint64_t)) {
        uint8_t amt_rev[sizeof(uint64_t)];
        memset(amt_rev, 0, sizeof(amt_rev));
        memcpy(amt_rev, amt, amt_len);
        rev_byte_order(amt_rev, amt_len);
        uint64_t amount64;
        memcpy(&amount64, amt_rev, sizeof(amount64));
        coin_amnt_to_str(coin, amount64, out, out_len);
        return true;
    }

    return false;
}

/// \returns true iff two addresses match. Ignores differencess in leading '0x' for ETH-like addresses.
bool addresses_same(const char *LHS, size_t LHS_len, const char *RHS, size_t RHS_len, bool isETH)
{
    if (isETH) {
        if (LHS[0] == '0' && (LHS[1] == 'x' || LHS[1] == 'X')) {
            LHS += 2;
            LHS_len -= 2;
        }

        if (RHS[0] == '0' && (RHS[1] == 'x' || RHS[1] == 'X')) {
            RHS += 2;
            RHS_len -= 2;
        }
    }

    return strncasecmp(LHS, RHS, MIN(LHS_len, RHS_len)) == 0;
}

/*
 * verify_exchange_address - verify address specified in exchange contract belongs to device.
 *
 * INPUT
 *     coin - the CoinType
 *     address_n_count - depth of node
 *     address_n - pointer to node path
 *     address_str - string representation of address
 *     address_str_len - address length
 *     root - root hd node
 *
 * OUTPUT
 *     true/false - success/failure
 */
static bool verify_exchange_address(const CoinType *coin, size_t address_n_count,
                                    uint32_t *address_n, char *address_str, size_t address_str_len,
                                    const HDNode *root, bool is_token)
{
    static CONFIDENTIAL HDNode node;
    memcpy(&node, root, sizeof(HDNode));
    if (hdnode_private_ckd_cached(&node, address_n, address_n_count, NULL) == 0) {
        memzero(&node, sizeof(node));
        return false;
    }

    if (isEthereumLike(coin->coin_name) || is_token) {
        char tx_out_address[sizeof(((ExchangeAddress *)NULL)->address)];
        EthereumAddress_address_t ethereum_addr;

        ethereum_addr.size = 20;
        if (hdnode_get_ethereum_pubkeyhash(&node, ethereum_addr.bytes) == 0) {
            memzero(&node, sizeof(node));
            return false;
        }

        data2hex((char *)ethereum_addr.bytes, 20, tx_out_address);
        return addresses_same(tx_out_address, sizeof(tx_out_address),
                              address_str, address_str_len, true);
    }

    const curve_info *curve = get_curve_by_name(coin->curve_name);
    if (!curve) {
        memzero(&node, sizeof(node));
        return false;
    }

    char tx_out_address[36];
    hdnode_fill_public_key(&node);
    ecdsa_get_address(node.public_key, coin->address_type, curve->hasher_pubkey,
                      curve->hasher_base58, tx_out_address,
                      sizeof(tx_out_address));

    memzero(&node, sizeof(node));
    return strncmp(tx_out_address, address_str, sizeof(tx_out_address)) == 0;
}

/*
 * verify_exchange_coin() - Verify coin type in exchange contract
 *
 * INPUT
 *     coin1 - reference coin name
 *     coin2 - coin name in exchange
 *     len: length of buffer
 * OUTPUT
 *     true/false -  success/failure
 */
bool verify_exchange_coin(const char *coin1, const char *coin2, uint32_t len)
{
    if (strncasecmp(coin1, coin2, len) == 0)
        return true;

    const CoinType *response_coin = coinByNameOrTicker(coin2);
    if (!response_coin)
        return false;

    if (strncasecmp(coin1, response_coin->coin_shortcut, len) == 0)
        return true;

    return strncmp(coin1, response_coin->coin_name, len) == 0;
}

static const CoinType *getWithdrawCoin(const ExchangeType *exchange)
{
    const CoinType *coin = coinByNameOrTicker(exchange->signed_exchange_response.responseV2.withdrawal_address.coin_type);

    if (!coin)
        coin = coinByNameOrTicker(exchange->withdrawal_coin_name);

    return coin;
}

static const CoinType *getDepositCoin(const ExchangeType *exchange)
{
    return coinByNameOrTicker(exchange->signed_exchange_response.responseV2.deposit_address.coin_type);
}

static const CoinType *getReturnCoin(const ExchangeType *exchange)
{
    return coinByNameOrTicker(exchange->signed_exchange_response.responseV2.return_address.coin_type);
}

/*
 * verify_exchange_dep_amount() Verify deposit amount specified in exchange contract
 *
 * INPUT
 *     coin - name of coin being compare for the amount value
 *     exch_dep_amt - pointer to deposit amount in char buffer
 *
 *
 * OUTPUT
 *      true/false - success/failure
 *
 */
static bool verify_exchange_dep_amount(const char *coin, void *dep_amt_ptr, ExchangeResponseV2_deposit_amount_t *exch_dep_amt)
{
    bool ret_stat = false;
    char amt_str[sizeof(exch_dep_amt->bytes)];

    memset(amt_str, 0, sizeof(amt_str));
    if (isEthereumLike(coin))
    {
        memcpy(amt_str, exch_dep_amt->bytes, exch_dep_amt->size);
    }
    else
    {
        if(exch_dep_amt->size <= sizeof(uint64_t))
        {
            memcpy(amt_str, exch_dep_amt->bytes, exch_dep_amt->size);
            rev_byte_order((uint8_t *)amt_str, exch_dep_amt->size);
        }
        else
        {
            goto verify_exchange_dep_amount_exit;
        }
    }

    if(memcmp(amt_str, dep_amt_ptr, exch_dep_amt->size) == 0)
    {
        ret_stat = true;
    }
verify_exchange_dep_amount_exit:
    return(ret_stat);
}

/// \brief Loose matching of two coins.
///
/// Note: we can't just do pointer comparison here, since one of the coins
/// might be constructed from the Token table.
static bool verify_coins_match(const CoinType *lhs, const CoinType *rhs)
{
    if (!lhs || !rhs)
        return false;

    if (strcasecmp(lhs->coin_shortcut, rhs->coin_shortcut) == 0)
        return true;

    if (strcasecmp(lhs->coin_name, rhs->coin_name) == 0)
        return true;

    return false;
}

/*
 * verify_exchange_contract() - Verify content of exchange contract is valid
 *
 * INPUT
 *     exchange:  exchange pointer
 *     root - root hd node
 * OUTPUT
 *     true/false -  success/failure
 */
static bool verify_exchange_contract(const CoinType *coin, void *vtx_out, const HDNode *root)
{
    ExchangeType *exchange;
    if (isEthereumLike(coin->coin_name)) {
        exchange = &((EthereumSignTx *)vtx_out)->exchange_type;

        /*Verify response structure from client is compatible*/
        if (exchange->signed_exchange_response.has_response) {
            /*Obsolete response data structure detected. Should be ExchangeResponseV2! */
            set_exchange_error(ERROR_EXCHANGE_RESPONSE_STRUCTURE);
            return false;
        }
    } else {
        exchange = &((TxOutputType *)vtx_out)->exchange_type;
    }

    void *tx_out_amount;
    char tx_out_address[sizeof(((ExchangeAddress *)NULL)->address)];
    memset(tx_out_address, 0, sizeof(tx_out_address));
    CoinType standard_deposit;
    const CoinType *deposit_coin = NULL;
    if (isEthereumLike(coin->coin_name)) {
        EthereumSignTx *tx_out = (EthereumSignTx *)vtx_out;
        tx_out->has_chain_id = coin->has_forkid;
        tx_out->chain_id = coin->forkid;

        if (ethereum_isNonStandardERC20(tx_out)) {
            // token specific address, shorcut, and value
            data2hex(tx_out->token_to.bytes, tx_out->token_to.size, tx_out_address);
            tx_out_amount = (void *)tx_out->token_value.bytes;
            deposit_coin = coinByShortcut(tx_out->token_shortcut);
        } else if (ethereum_isStandardERC20(tx_out)) {
            if (!ethereum_getStandardERC20Recipient(tx_out, tx_out_address, sizeof(tx_out_address)) ||
                !ethereum_getStandardERC20Amount(tx_out, &tx_out_amount) ||
                !ethereum_getStandardERC20Coin(tx_out, &standard_deposit)) {
                set_exchange_error(ERROR_EXCHANGE_RESPONSE_STRUCTURE);
                return false;
            }
            deposit_coin = &standard_deposit;
        } else {
            data2hex(tx_out->to.bytes, tx_out->to.size, tx_out_address);
            tx_out_amount = (void *)tx_out->value.bytes;
            deposit_coin = coin;
        }
    } else {
        TxOutputType *tx_out = (TxOutputType *)vtx_out;
        exchange = &tx_out->exchange_type;
        memcpy(tx_out_address, tx_out->address, sizeof(tx_out->address));
        tx_out_amount = (void *)&tx_out->amount;
        deposit_coin = coin;
    }

    if (!deposit_coin) {
        set_exchange_error(ERROR_EXCHANGE_RESPONSE_STRUCTURE);
        return false;
    }

    /* verify Exchange signature */
    uint8_t response_raw[sizeof(ExchangeResponseV2)];
    memset(response_raw, 0, sizeof(response_raw));
    int response_raw_filled_len = encode_pb(
                                (const void *)&exchange->signed_exchange_response.responseV2,
                                ExchangeResponseV2_fields,
                                response_raw,
                                sizeof(response_raw));

    if(response_raw_filled_len == 0)
    {
        set_exchange_error(ERROR_EXCHANGE_SIGNATURE);
        return false;
    }

    const CoinType *signed_coin = coinByShortcut((const char *)"BTC");
    if(cryptoMessageVerify(signed_coin, response_raw, response_raw_filled_len, ShapeShift_pubkey,
                (uint8_t *)exchange->signed_exchange_response.signature.bytes) != 0)
    {
        set_exchange_error(ERROR_EXCHANGE_SIGNATURE);
        return false;
    }

    /* verify Exchange API-Key */
    if(memcmp(ShapeShift_api_key, exchange->signed_exchange_response.responseV2.api_key.bytes,
                sizeof(ShapeShift_api_key)) != 0)
    {
        set_exchange_error(ERROR_EXCHANGE_API_KEY);
        return false;
    }

    /* verify Deposit coin type */
    if (!verify_coins_match(deposit_coin, getDepositCoin(exchange))) {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_COINTYPE);
        return false;
    }

    /* verify Deposit address */
    if(!addresses_same(tx_out_address, sizeof(tx_out_address),
               exchange->signed_exchange_response.responseV2.deposit_address.address,
               sizeof(exchange->signed_exchange_response.responseV2.deposit_address.address),
               isEthereumLike(coin->coin_name)))
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_ADDRESS);
        return false;
    }

    /* verify Deposit amount*/
    if(!verify_exchange_dep_amount(coin->coin_name,
                tx_out_amount, &exchange->signed_exchange_response.responseV2.deposit_amount))
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_AMOUNT);
        return false;
    }

    /* verify Withdrawal address */
    const CoinType *withdraw_coin = getWithdrawCoin(exchange);
    if (!withdraw_coin) {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_COINTYPE);
        return false;
    }

    if (!verify_coins_match(withdraw_coin, coinByNameOrTicker(exchange->withdrawal_coin_name))) {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_COINTYPE);
        return false;
    }

    if (!verify_exchange_address(
             withdraw_coin,
             exchange->withdrawal_address_n_count,
             exchange->withdrawal_address_n,
             exchange->signed_exchange_response.responseV2.withdrawal_address.address,
             sizeof(exchange->signed_exchange_response.responseV2.withdrawal_address.address),
             root, withdraw_coin->has_contract_address))
    {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_ADDRESS);
        return false;
    }

    /* verify Return coin type */
    const CoinType *return_coin = getReturnCoin(exchange);
    if (!return_coin) {
        set_exchange_error(ERROR_EXCHANGE_RETURN_COINTYPE);
        return false;
    }

    if (!verify_coins_match(deposit_coin, return_coin)) {
        set_exchange_error(ERROR_EXCHANGE_RETURN_COINTYPE);
        return false;
    }

    /* verify Return address */
    if (!verify_exchange_address(
             return_coin,
             exchange->return_address_n_count,
             exchange->return_address_n,
             exchange->signed_exchange_response.responseV2.return_address.address,
             sizeof(exchange->signed_exchange_response.responseV2.return_address.address),
             root, return_coin->has_contract_address))
    {
        set_exchange_error(ERROR_EXCHANGE_RETURN_ADDRESS);
        return false;
    }

    set_exchange_error(NO_EXCHANGE_ERROR);
    return true;
}

/*
 * set_exchange_error - set exchange error code
 * INPUT
 *     error_code - exchange error code
 * OUTPUT
 *     none
 */
void set_exchange_error(ExchangeError error_code)
{
    exchange_error = error_code;
}
/*
 * get_exchange_error - get exchange error code
 * INPUT
 *     none
 * OUTPUT
 *     exchange error code
 */
ExchangeError get_exchange_error(void)
{
    return(exchange_error);
}

/*
 * process_exchange_contract() - validate contract from exchange and populate the transaction
 *                               output structure
 *
 * INPUT
 *      coin - pointer signTx coin type
 *      tx_out - pointer transaction output structure
 *      root - root hd node
 *      needs_confirm - whether requires user manual approval
 * OUTPUT
 *      true/false - success/failure
 */
bool process_exchange_contract(const CoinType *coin, void *vtx_out, const HDNode *root, bool needs_confirm)
{
    /* validate contract before processing */
    if (!verify_exchange_contract(coin, vtx_out, root))
        return false;

    /* check if user confirmation is required */
    if (!needs_confirm)
        return true;

    CoinType standard_deposit;
    const CoinType *deposit_coin = NULL;
    ExchangeType *tx_exchange; // FIXME: make this const (can't because of the rev_byte_order in exchange_tx_layout_str)
    if (isEthereumLike(coin->coin_name)) {
        const EthereumSignTx *msg = (const EthereumSignTx *)vtx_out;
        tx_exchange = (ExchangeType*)&msg->exchange_type; // FIXME: drop the cast
        if (ethereum_isNonStandardERC20(msg)) {
            deposit_coin = coinByShortcut(msg->token_shortcut);
        } else if (ethereum_isStandardERC20(msg)) {
            if (!ethereum_getStandardERC20Coin(msg, &standard_deposit)) {
                set_exchange_error(ERROR_EXCHANGE_RESPONSE_STRUCTURE);
                return false;
            }
            deposit_coin = &standard_deposit;
        } else {
            deposit_coin = coinByName(coin->coin_name);
        }
    } else {
        tx_exchange = &((TxOutputType *)vtx_out)->exchange_type;
        deposit_coin = coinByName(coin->coin_name);
    }

    if (!deposit_coin) {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_COINTYPE);
        return false;
    }

    const CoinType *withdrawal_coin = getWithdrawCoin(tx_exchange);
    if (!withdrawal_coin) {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_COINTYPE);
        return false;
    }

    /* assemble deposit amount for display*/
    char amount_dep_str[128];
    if (!exchange_tx_layout_str(deposit_coin,
                tx_exchange->signed_exchange_response.responseV2.deposit_amount.bytes,
                tx_exchange->signed_exchange_response.responseV2.deposit_amount.size,
                amount_dep_str,
                sizeof(amount_dep_str))) {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_AMOUNT);
        return false;
    }

    /* assemble withdrawal amount for display*/
    char amount_wit_str[128];
    if (!exchange_tx_layout_str(withdrawal_coin,
                tx_exchange->signed_exchange_response.responseV2.withdrawal_amount.bytes,
                tx_exchange->signed_exchange_response.responseV2.withdrawal_amount.size,
                amount_wit_str,
                sizeof(amount_wit_str))) {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_AMOUNT);
        return false;
    }

    /* determine withdrawal account number */
    char node_str[100];
    if (!bip32_node_to_string(node_str, sizeof(node_str), withdrawal_coin,
                             tx_exchange->withdrawal_address_n,
                             tx_exchange->withdrawal_address_n_count,
                             /*whole_account=*/false,
                             /*allow_change=*/true,
                             /*show_addridx=*/false)) {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_ADDRESS);
        return false;
    }

    if (!confirm_exchange_output(amount_dep_str, amount_wit_str, node_str)) {
        set_exchange_error(ERROR_EXCHANGE_CANCEL);
        return false;
    }

    return true;
}

