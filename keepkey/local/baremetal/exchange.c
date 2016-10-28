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

/* === Includes ============================================================ */

#include <stdio.h>
#include <ecdsa.h>
#include <crypto.h>
#include <types.pb.h>
#include <bip32.h>
#include <coins.h>
#include <exchange.h>
#include <layout.h>
#include <app_confirm.h>
#include <msg_dispatch.h>
#include <policy.h>
#include <util.h>

/* === Private Variables =================================================== */
/* exchange error variable */
static ExchangeError exchange_error = NO_EXCHANGE_ERROR;

/* exchange public key for signature varification */
static uint8_t ShapeShift_public_address[25] =
{
    0x00, 0xB9, 0xF5, 0x01, 0xE0, 0xD3, 0x69, 0x28, 0x37, 0x19, 
    0x57, 0x5B, 0xD5, 0x93, 0x40, 0x6C, 0xC3, 0xBA, 0x78, 0xC2, 
    0x71, 0x66, 0x09, 0x5E, 0x64
};

/* exchange API Key */
static uint8_t ShapeShift_api_key[64] =
{
    0x6a, 0xd5, 0x83, 0x1b, 0x77, 0x84, 0x84, 0xbb, 0x84, 0x9d, 0xa4, 0x51, 
    0x80, 0xac, 0x35, 0x04, 0x78, 0x48, 0xe5, 0xca, 0xc0, 0xfa, 0x66, 0x64, 
    0x54, 0xf4, 0xff, 0x78, 0xb8, 0xc7, 0x39, 0x9f, 0xea, 0x6a, 0x8c, 0xe2, 
    0xc7, 0xee, 0x62, 0x87, 0xbc, 0xd7, 0x8d, 0xb6, 0x61, 0x0c, 0xa3, 0xf5, 
    0x38, 0xd6, 0xb3, 0xe9, 0x0c, 0xa8, 0x0c, 0x8e, 0x63, 0x68, 0xb6, 0x02, 
    0x14, 0x45, 0x95, 0x0b
};
/* === Private Functions =================================================== */
/*
 * check_ether_tx() - check transaction is for Ethereum 
 *
 * INPUT 
 *      coin name
 *
 * OUTPUT 
 *      true - Ethereum transaction
 *      false - trasaction for others
 */
bool check_ethereum_tx(const char *coin_name)
{
    if(strcmp(coin_name, "Ethereum") == 0 || strcmp(coin_name, "Ethereum Classic") == 0)
    {
        return(true);
    }
    else
    {
        return(false);
    }
}

/*
 * verify_exchange_address - verify address specified in exchange contract belongs to device.
 *
 * INPUT
 *     coin_name - name of coin
 *     address_n_count - depth of node
 *     address_n - pointer to node path
 *     address_str - string representation of address
 *     root - root hd node
 *
 * OUTPUT
 *     true/false - success/failure
 */
static bool verify_exchange_address(char *coin_name, size_t address_n_count,
                                    uint32_t *address_n, char *address_str, const HDNode *root)
{
    const CoinType *coin;
    HDNode node;
    bool ret_stat = false;

    coin = coinByName(coin_name);

    if(coin)
    {
        memcpy(&node, root, sizeof(HDNode));
        if(hdnode_private_ckd_cached(&node, address_n, address_n_count) == 0)
        {
            goto verify_exchange_address_exit;
        }

        if(check_ethereum_tx(coin->coin_name))
        {
            char tx_out_address[42];
            EthereumAddress_address_t ethereum_addr;

            ethereum_addr.size = 20;

            if(hdnode_get_ethereum_pubkeyhash(&node, ethereum_addr.bytes) == 0)
            {
                goto verify_exchange_address_exit;
            }

            data2hex((char *)ethereum_addr.bytes, 20, tx_out_address);
            if(strncasecmp(tx_out_address, address_str, ethereum_addr.size) == 0)
            {
                ret_stat = true;
            }

        }
        else
        {
            char internal_address[36];
            hdnode_fill_public_key(&node);
            ecdsa_get_address(node.public_key, coin->address_type, internal_address,
                              sizeof(internal_address));

            if(strncmp(internal_address, address_str, sizeof(internal_address)) == 0)
            {
                ret_stat = true;
            }
        }
    }
verify_exchange_address_exit:

    return(ret_stat);
}

/* === Functions =========================================================== */

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
 *     exchange_deposit_amount - pointer to deposit amount in char buffer
 *      
 *
 * OUTPUT
 *      true/false - success/failure
 *
 */
static bool verify_exchange_dep_amount(char *coin, void *amount, ExchangeResponse_deposit_amount_t *exchange_deposit_amount)
{
    bool ret_stat = false;
    char amt_str[sizeof(exchange_deposit_amount->bytes)];

    memset(amt_str, 0, sizeof(amt_str));
    if(check_ethereum_tx(coin))
    {
        memcpy (amt_str, amount, sizeof(amt_str));
    }
    else
    {
        /*convert 64bit decimal to string for bitcoit and altcoins */
        dec64_to_str(*(uint64_t *)amount, amt_str);
    }
    if(memcmp(amt_str, exchange_deposit_amount->bytes, sizeof(amt_str)) == 0)
    {
        ret_stat = true;
    }
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
    int response_raw_filled_len = 0; 
    uint8_t response_raw[sizeof(ExchangeResponse)];
    const CoinType *response_coin;

    char tx_out_address[42];
    void *tx_out_amount;
    ExchangeType *exchange;

    memset(tx_out_address, 0, sizeof(tx_out_address));

    if(check_ethereum_tx(coin->coin_name))
    {
        EthereumSignTx *tx_out = (EthereumSignTx *)vtx_out;
        exchange = &tx_out->exchange_type;
        data2hex(tx_out->to.bytes, tx_out->to.size, tx_out_address);
        tx_out_amount = (void *)tx_out->value.bytes;

    }
    else
    {
        TxOutputType *tx_out = (TxOutputType *)vtx_out;
        exchange = &tx_out->exchange_type;
        memcpy(tx_out_address, tx_out->address, sizeof(tx_out->address));
        tx_out_amount = (void *)&tx_out->amount;
    }

    /* verify Exchange signature */
    memset(response_raw, 0, sizeof(response_raw));
    response_raw_filled_len = encode_pb(
                                (const void *)&exchange->signed_exchange_response.response, 
                                ExchangeResponse_fields,
                                response_raw, 
                                sizeof(response_raw));

    if(response_raw_filled_len != 0)
    {
        const CoinType *signed_coin = coinByShortcut((const char *)"BTC");
        if(cryptoMessageVerify(signed_coin, response_raw, response_raw_filled_len, ShapeShift_public_address, 
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
    if(memcmp(ShapeShift_api_key, exchange->signed_exchange_response.response.api_key.bytes, 
                sizeof(ShapeShift_api_key)) != 0)
    {
        set_exchange_error(ERROR_EXCHANGE_API_KEY);
        goto verify_exchange_contract_exit;
    }

    /* verify Deposit coin type */
    if(!verify_exchange_coin(coin->coin_name,
                         exchange->signed_exchange_response.response.deposit_address.coin_type,
                         sizeof(coin->coin_name)))
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_COINTYPE);
        goto verify_exchange_contract_exit;
    }
    /* verify Deposit address */
    if(strncasecmp(tx_out_address, 
               exchange->signed_exchange_response.response.deposit_address.address, 
               sizeof(tx_out_address)) != 0)
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_ADDRESS);
        goto verify_exchange_contract_exit;
    }

    /* verify Deposit amount*/
    if(!verify_exchange_dep_amount(exchange->signed_exchange_response.response.deposit_address.coin_type, 
                tx_out_amount, &exchange->signed_exchange_response.response.deposit_amount))
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_AMOUNT);
        goto verify_exchange_contract_exit;
    }

    /* verify Withdrawal coin type */
    if(!verify_exchange_coin(exchange->withdrawal_coin_name,
             exchange->signed_exchange_response.response.withdrawal_address.coin_type,
             sizeof(exchange->withdrawal_coin_name)))
    {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_COINTYPE);
        goto verify_exchange_contract_exit;
    }

    /* verify Withdrawal address */
    if(!verify_exchange_address( exchange->withdrawal_coin_name,
             exchange->withdrawal_address_n_count,
             exchange->withdrawal_address_n,
             exchange->signed_exchange_response.response.withdrawal_address.address, root))
    {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_ADDRESS);
        goto verify_exchange_contract_exit;
    }

    /* verify Return coin type */
    if(!verify_exchange_coin(coin->coin_name,
             exchange->signed_exchange_response.response.return_address.coin_type,
             sizeof(coin->coin_name)))
    {
        set_exchange_error(ERROR_EXCHANGE_RETURN_COINTYPE);
        goto verify_exchange_contract_exit;
    }
    /* verify Return address */

    response_coin = get_response_coin(exchange->signed_exchange_response.response.return_address.coin_type);
    if(!verify_exchange_address( (char *)response_coin->coin_name,
             exchange->return_address_n_count,
             exchange->return_address_n,
             exchange->signed_exchange_response.response.return_address.address, root))
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
 *                            output structure
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
    const CoinType *withdrawal_coin;
    char amount_from_str[32], amount_to_str[32], node_str[100];
    ExchangeType *tx_exchange;

    /* validate contract before processing */
    if(verify_exchange_contract(coin, vtx_out, root))
    {
        if(check_ethereum_tx(coin->coin_name))
        {
            EthereumSignTx *tx_out = (EthereumSignTx *)vtx_out;
            tx_exchange = &tx_out->exchange_type;
        }
        else
        {
            TxOutputType *tx_out = (TxOutputType *)vtx_out;
            tx_exchange = &tx_out->exchange_type;
        }

        withdrawal_coin = coinByName(tx_exchange->withdrawal_coin_name);
        if(needs_confirm)
        {
            memset(amount_from_str, 0, sizeof(amount_from_str));
            memset(amount_to_str, 0, sizeof(amount_to_str));

            memcpy(amount_from_str, tx_exchange->signed_exchange_response.response.deposit_amount.bytes, sizeof(amount_from_str));
            memcpy(amount_to_str, tx_exchange->signed_exchange_response.response.withdrawal_amount.bytes, sizeof(amount_to_str));

            if(bip44_node_to_string(withdrawal_coin, node_str, tx_exchange->withdrawal_address_n,
                     tx_exchange->withdrawal_address_n_count))
            {
                if(!confirm_exchange_output("ShapeShift", amount_from_str, amount_to_str, node_str))
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

