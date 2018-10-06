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
#include "keepkey/board/msg_dispatch.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/crypto.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/exchange.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/policy.h"
#include "keepkey/firmware/util.h"
#include "types.pb.h"

#include <string.h>
#include <stdio.h>

#define MIN(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a < _b ? _a : _b; })

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
static bool exchange_tx_layout_str(const CoinType *coint, uint8_t *amt, size_t amt_len, char *out, size_t out_len)
{
    if (isEthereumLike(coint->coin_name)) {
        return ether_for_display(amt, amt_len, out);
    }

    if (coint->has_contract_address) {
        bool ret_stat = ether_token_for_display(amt, amt_len, coint->decimals, out, out_len);
        if (out_len <= strlen(out) + 1 + sizeof(coint->coin_shortcut) + 1) {
            return false;
        }

        // Append token shortcut to display string
        strncat(out, " ", 1);
        strncat(out, coint->coin_shortcut, sizeof(coint->coin_shortcut)+1);
        return ret_stat;
    }

    if (amt_len <= sizeof(uint64_t)) {
        uint64_t amount64;
        rev_byte_order(amt, amt_len);
        memcpy(&amount64, amt, sizeof(uint64_t));
        coin_amnt_to_str(coint, amount64, out, out_len);
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
 *     coin_name - name of coin
 *     address_n_count - depth of node
 *     address_n - pointer to node path
 *     address_str - string representation of address
 *     address_str_len - address length
 *     root - root hd node
 *
 * OUTPUT
 *     true/false - success/failure
 */
static bool verify_exchange_address(char *coin_name, size_t address_n_count,
                                    uint32_t *address_n, char *address_str, size_t address_str_len,
                                    const HDNode *root, bool is_token)
{
    bool ret_stat = false;

    const CoinType *coin = coinByName(coin_name);
    if (!coin)
        return false;

    static CONFIDENTIAL HDNode node;
    memcpy(&node, root, sizeof(HDNode));
    if (hdnode_private_ckd_cached(&node, address_n, address_n_count, NULL) == 0) {
        goto verify_exchange_address_exit;
    }

    if (isEthereumLike(coin->coin_name) || is_token) {
        char tx_out_address[sizeof(((ExchangeAddress *)NULL)->address)];
        EthereumAddress_address_t ethereum_addr;

        ethereum_addr.size = 20;
        if (hdnode_get_ethereum_pubkeyhash(&node, ethereum_addr.bytes) != 0)
        {
            data2hex((char *)ethereum_addr.bytes, 20, tx_out_address);
            ret_stat = addresses_same(tx_out_address, sizeof(tx_out_address),
                                      address_str, address_str_len, true);
        }
    } else {
        const curve_info *curve = get_curve_by_name(coin->curve_name);
        if (!curve)
            goto verify_exchange_address_exit;

        char tx_out_address[36];
        hdnode_fill_public_key(&node);
        ecdsa_get_address(node.public_key, coin->address_type, curve->hasher_pubkey,
                          curve->hasher_base58, tx_out_address,
                          sizeof(tx_out_address));
        if (strncmp(tx_out_address, address_str, sizeof(tx_out_address)) == 0) {
            ret_stat = true;
        }
    }
verify_exchange_address_exit:
    memzero(&node, sizeof(node));
    return(ret_stat);
}

/*
 *  get_response_coin() - get pointer to coin type 
 *
 * INPUT
 *     response_coin_short_name: pointer to abbreviated coin name
 * OUTPUT
 *     pointer to coin type 
 *     NULL: error
 */
const CoinType * get_response_coin(const char *response_coin_short_name)
{
    char local_coin_name[17];

    strlcpy(local_coin_name, response_coin_short_name, sizeof(local_coin_name));
    strupr(local_coin_name);
    return(coinByShortcut((const char *)local_coin_name));
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
    bool ret_stat = false;
    const CoinType *response_coin = get_response_coin(coin2);

    if(response_coin != 0)
    {
        if(strncmp(coin1, response_coin->coin_name, len) == 0)
        {
            ret_stat = true;
        }
    }
    return(ret_stat);
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
        memcpy (amt_str, exch_dep_amt->bytes, exch_dep_amt->size);
    }
    else
    {
        if(exch_dep_amt->size <= sizeof(uint64_t))
        {
            memcpy (amt_str, exch_dep_amt->bytes, exch_dep_amt->size);
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
    bool ret_stat = false;
    bool is_token = false;
    bool is_ethLike = false;
    int response_raw_filled_len = 0;
    uint8_t response_raw[sizeof(ExchangeResponseV2)];
    const CoinType *response_coin;
    const CoinType *withdraw_coin;

    char tx_out_address[sizeof(((ExchangeAddress *)NULL)->address)];
    char token_shortcut[sizeof(((CoinType *)NULL)->coin_shortcut)];
    void *tx_out_amount;

    ExchangeType *exchange;
    memset(tx_out_address, 0, sizeof(tx_out_address));

    if (isEthereumLike(coin->coin_name))
    {
        EthereumSignTx *tx_out = (EthereumSignTx *)vtx_out;
        exchange = &tx_out->exchange_type;
        /*Verify response structure from client is compatible*/
        if(exchange->signed_exchange_response.has_response)
        {
            /*Obsolete response data structure detected. Should be ExchangeResponseV2! */
            set_exchange_error(ERROR_EXCHANGE_RESPONSE_STRUCTURE);
            goto verify_exchange_contract_exit;
        }
        is_token = is_token_transaction(tx_out);
        if(is_token) {
            // token specific address, shorcut, and value
            data2hex(tx_out->token_to.bytes, tx_out->token_to.size, tx_out_address);
            tx_out_amount = (void *)tx_out->token_value.bytes;
            strncpy(token_shortcut, tx_out->token_shortcut, sizeof(token_shortcut));
        }
        else
        {
            data2hex(tx_out->to.bytes, tx_out->to.size, tx_out_address);
            tx_out_amount = (void *)tx_out->value.bytes;
        }
        is_ethLike = true;
    }
    else
    {
        TxOutputType *tx_out = (TxOutputType *)vtx_out;
        exchange = &tx_out->exchange_type;
        memcpy(tx_out_address, tx_out->address, sizeof(tx_out->address));
        tx_out_amount = (void *)&tx_out->amount;
        is_ethLike = false;
    }

    /* verify Exchange signature */
    memset(response_raw, 0, sizeof(response_raw));
    response_raw_filled_len = encode_pb(
                                (const void *)&exchange->signed_exchange_response.responseV2, 
                                ExchangeResponseV2_fields,
                                response_raw, 
                                sizeof(response_raw));

    if(response_raw_filled_len != 0)
    {
        const CoinType *signed_coin = coinByShortcut((const char *)"BTC");
        if(cryptoMessageVerify(signed_coin, response_raw, response_raw_filled_len, ShapeShift_pubkey,
                    (uint8_t *)exchange->signed_exchange_response.signature.bytes) != 0)
        {
            set_exchange_error(ERROR_EXCHANGE_SIGNATURE);
            goto verify_exchange_contract_exit;
        }
    }
    else
    {
        set_exchange_error(ERROR_EXCHANGE_SIGNATURE);
        goto verify_exchange_contract_exit;
    }

    /* verify Exchange API-Key */
    if(memcmp(ShapeShift_api_key, exchange->signed_exchange_response.responseV2.api_key.bytes, 
                sizeof(ShapeShift_api_key)) != 0)
    {
        set_exchange_error(ERROR_EXCHANGE_API_KEY);
        goto verify_exchange_contract_exit;
    }

    /* verify Deposit coin type */
    const char *exchange_coin_name = is_token ? coinByShortcut(token_shortcut)->coin_name : coin->coin_name;
    if(!verify_exchange_coin(exchange_coin_name,
                     exchange->signed_exchange_response.responseV2.deposit_address.coin_type,
                     sizeof(coin->coin_name)))
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_COINTYPE);
        goto verify_exchange_contract_exit;
    }

    /* verify Deposit address */
    if(!addresses_same(tx_out_address, sizeof(tx_out_address),
               exchange->signed_exchange_response.responseV2.deposit_address.address,
               sizeof(exchange->signed_exchange_response.responseV2.deposit_address.address),
               is_ethLike))
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_ADDRESS);
        goto verify_exchange_contract_exit;
    }

    /* verify Deposit amount*/
    if(!verify_exchange_dep_amount(coin->coin_name, 
                tx_out_amount, &exchange->signed_exchange_response.responseV2.deposit_amount))
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_AMOUNT);
        goto verify_exchange_contract_exit;
    }

    /* verify Withdrawal coin type */
    if(!verify_exchange_coin(exchange->withdrawal_coin_name,
             exchange->signed_exchange_response.responseV2.withdrawal_address.coin_type,
             sizeof(exchange->withdrawal_coin_name)))
    {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_COINTYPE);
        goto verify_exchange_contract_exit;
    }

    /* verify Withdrawal address */
    withdraw_coin = get_response_coin(exchange->signed_exchange_response.responseV2.withdrawal_address.coin_type);
    if(!verify_exchange_address( exchange->withdrawal_coin_name,
             exchange->withdrawal_address_n_count,
             exchange->withdrawal_address_n,
             exchange->signed_exchange_response.responseV2.withdrawal_address.address,
             sizeof(exchange->signed_exchange_response.responseV2.withdrawal_address.address),
             root, withdraw_coin->has_contract_address)) 
    {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_ADDRESS);
        goto verify_exchange_contract_exit;
    }

    /* verify Return coin type */
    const char *return_coin_name = is_token ? coinByShortcut(token_shortcut)->coin_name : coin->coin_name;
    if(!verify_exchange_coin(return_coin_name,
             exchange->signed_exchange_response.responseV2.return_address.coin_type,
             sizeof(coin->coin_name)))
    {
        set_exchange_error(ERROR_EXCHANGE_RETURN_COINTYPE);
        goto verify_exchange_contract_exit;
    }

    /* verify Return address */
    response_coin = get_response_coin(exchange->signed_exchange_response.responseV2.return_address.coin_type);
    if(!verify_exchange_address( (char *)response_coin->coin_name,
             exchange->return_address_n_count,
             exchange->return_address_n,
             exchange->signed_exchange_response.responseV2.return_address.address,
             sizeof(exchange->signed_exchange_response.responseV2.return_address.address),
             root, response_coin->has_contract_address))
    {
        set_exchange_error(ERROR_EXCHANGE_RETURN_ADDRESS);
    }
    else
    {
        set_exchange_error(NO_EXCHANGE_ERROR);
        ret_stat = true;
    }

verify_exchange_contract_exit:
    return(ret_stat);
}

/* === Functions =========================================================== */

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
    bool ret_val = false;
    const CoinType *withdrawal_coin, *deposit_coin;
    char amount_dep_str[128], amount_wit_str[128], node_str[100];
    ExchangeType *tx_exchange;

    /* validate contract before processing */
    if(verify_exchange_contract(coin, vtx_out, root))
    {
        if (isEthereumLike(coin->coin_name))
        {
            tx_exchange = &((EthereumSignTx *)vtx_out)->exchange_type;
            if(is_token_transaction((EthereumSignTx *)vtx_out))
            {
                deposit_coin = coinByShortcut(((EthereumSignTx *)vtx_out)->token_shortcut);
            }
            else
            {
                deposit_coin = coinByName(coin->coin_name);
            }
        }
        else
        {
            tx_exchange = &((TxOutputType *)vtx_out)->exchange_type;
            deposit_coin = coinByName(coin->coin_name);
        }
        /* check user confirmation required*/
        if(needs_confirm)
        {
            withdrawal_coin = coinByName(tx_exchange->withdrawal_coin_name);

            /* assemble deposit amount for display*/
            if(!exchange_tx_layout_str(deposit_coin, 
                        tx_exchange->signed_exchange_response.responseV2.deposit_amount.bytes,
                        tx_exchange->signed_exchange_response.responseV2.deposit_amount.size,
                        amount_dep_str,
                        sizeof(amount_dep_str)))
            {
                set_exchange_error(ERROR_EXCHANGE_DEPOSIT_AMOUNT);
                goto process_exchange_contract_exit;
            }

            /* assemble withdrawal amount for display*/
            if(!exchange_tx_layout_str(withdrawal_coin, 
                        tx_exchange->signed_exchange_response.responseV2.withdrawal_amount.bytes,
                        tx_exchange->signed_exchange_response.responseV2.withdrawal_amount.size,
                        amount_wit_str,
                        sizeof(amount_wit_str)))
             {
                set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_AMOUNT);
                goto process_exchange_contract_exit;
             }

            /* determine withdrawal account number */
            if(bip32_node_to_string(node_str, sizeof(node_str), withdrawal_coin,
                                    tx_exchange->withdrawal_address_n,
                                    tx_exchange->withdrawal_address_n_count,
                                    /*whole_account=*/false))
            {
                if(!confirm_exchange_output("ShapeShift", amount_dep_str, amount_wit_str, node_str))
                {
                    set_exchange_error(ERROR_EXCHANGE_CANCEL);
                    goto process_exchange_contract_exit;
                }
            }
            else
            {
                set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_ADDRESS);
                goto process_exchange_contract_exit;
            }
        }

        ret_val = true;
    }

process_exchange_contract_exit:
    return ret_val;
}

