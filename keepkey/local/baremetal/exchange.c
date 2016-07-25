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

/* === Private Variables =================================================== */

static const uint8_t exchange_pubkey[65] =
{
    0x04, 0xf6, 0x45, 0xec, 0x65, 0x44, 0xa9, 0x2f, 0x95, 0x1f, 0x3b, 0xca,
    0x16, 0xa2, 0xbc, 0x1c, 0x56, 0x84, 0x6d, 0x06, 0x55, 0x94, 0xdb, 0x22, 
    0x27, 0x25, 0xd5, 0x9b, 0x99, 0x02, 0x52, 0x83, 0x85, 0xeb, 0x20, 0xc6, 
    0x2c, 0x40, 0x83, 0xbd, 0xa5, 0xe9, 0x9d, 0x62, 0x7c, 0x28, 0xbd, 0x89, 
    0x4e, 0xfc, 0x42, 0x34, 0x44, 0xde, 0x9a, 0xfa, 0x9a, 0xd7, 0xe8, 0xaf,  
    0xf6, 0x4d, 0x38, 0x97, 0x0f
};

/* === Private Functions =================================================== */

/*
 *  set_exchange_tx_out() - inline function to populate the transaction output buffer
 *
 *  INPUT
 *      tx_out - pointer to transaction output buffer
 *  OUTPUT
 *      none
 */
inline void set_exchange_tx_out(TxOutputType *tx_out, ExchangeType *ex_tx)
{
    /* clear to prep transaction output */
    memset(tx_out, 0, (size_t)((char *)&tx_out->has_address_type - (char *)tx_out));

    /* populate withdrawal address */
    tx_out->has_address = true;
    memcpy(tx_out->address, ex_tx->signed_exchange_response.response.withdrawal_address.address,
           sizeof(tx_out->address));

    /* populate withdrawal amount */
    tx_out->amount = ex_tx->signed_exchange_response.response.withdrawal_amount;
}

/*
 * verify_exchange_address - verify address specified in exchange token belongs to device.
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
    char internal_address[36];
    bool ret_stat = false;

    coin = coinByName(coin_name);

    if(coin)
    {
    	memcpy(&node, root, sizeof(HDNode));
        if(hdnode_private_ckd_cached(&node, address_n, address_n_count) != 0)
        {
            ecdsa_get_address(node.public_key, coin->address_type, internal_address,
                              sizeof(internal_address));

            if(strncmp(internal_address, address_str, sizeof(internal_address)) == 0)
            {
                ret_stat = true;
            }
        }
    }

    return(ret_stat);
}

/*
 * verify_exchange_token() - Verify content of exchange token is valid
 *
 * INPUT
 *     exchange:  exchange pointer
 *     root - root hd node
 * OUTPUT
 *     true/false -  success/failure
 */
static bool verify_exchange_token(ExchangeType *exchange, const HDNode *root)
{
    bool ret_stat = false;
    uint8_t fingerprint[32];

    /* verify deposit address */
    if(!verify_exchange_address(
             exchange->deposit_coin_name,
             exchange->deposit_address_n_count,
             exchange->deposit_address_n,
             exchange->signed_exchange_response.response.deposit_address.address, root))
    {
        goto verify_exchange_token_exit;
    }

    /* verify return address */
    if(!verify_exchange_address(
             exchange->return_coin_name,
             exchange->return_address_n_count,
             exchange->return_address_n,
             exchange->signed_exchange_response.response.return_address.address, root))
    {
        goto verify_exchange_token_exit;
    }

    /* check exchange signature */
    sha256_Raw((uint8_t *)&exchange->signed_exchange_response.response, sizeof(ExchangeResponse),
               fingerprint);

    if(ecdsa_verify_digest(&secp256k1, exchange_pubkey,
              (uint8_t *)exchange->signed_exchange_response.signature.bytes, fingerprint) == 0)
    {
        ret_stat = true;
    }

verify_exchange_token_exit:

    return(ret_stat);
}

/* === Functions =========================================================== */

/*
 * process_exchange_token() - validate token from exchange and populate the transaction
 *                            output structure
 *
 * INPUT
 *      tx_out - pointer transaction output structure
 *      root - root hd node
 *      needs_confirm - whether requires user manual approval
 * OUTPUT
 *      true/false - success/failure
 */
bool process_exchange_token(TxOutputType *tx_out, const HDNode *root, bool needs_confirm)
{
    const CoinType *withdraw_coin, *deposit_coin;
    bool ret_stat = false;
    char conf_msg[100];

    if(tx_out->has_exchange_type)
    {
        /* validate token before processing */
        if(verify_exchange_token(&tx_out->exchange_type, root))
        {
            deposit_coin = coinByName(tx_out->exchange_type.deposit_coin_name);
            withdraw_coin = coinByName(tx_out->exchange_type.signed_exchange_response.response.withdrawal_address.coin_type);

            if(needs_confirm)
            {
                snprintf(conf_msg, sizeof(conf_msg),
                         "Do you want to exchange \"%s\" to \"%s\" at rate = %d%%%% and deposit to  %s Acc #%d",
                         tx_out->exchange_type.signed_exchange_response.response.withdrawal_address.coin_type,
                         tx_out->exchange_type.deposit_coin_name,
                         (int)tx_out->exchange_type.signed_exchange_response.response.quoted_rate,
                         tx_out->exchange_type.deposit_coin_name,
                         (int)tx_out->exchange_type.deposit_address_n[2] & 0x7ffffff);

                if(!confirm_exchange(conf_msg))
                {
                    ret_stat = false;
                    goto process_exchange_token_exit;
                }

                snprintf(conf_msg, sizeof(conf_msg),
                         "Exchanging %lld %s to %lld %s and depositing to %s Acc #%d",
                         tx_out->exchange_type.signed_exchange_response.response.withdrawal_amount, withdraw_coin->coin_shortcut,
                         tx_out->exchange_type.signed_exchange_response.response.deposit_amount, deposit_coin->coin_shortcut,
                         tx_out->exchange_type.deposit_coin_name,
                         (int)tx_out->exchange_type.deposit_address_n[2] & 0x7ffffff);

                if(!confirm_exchange(conf_msg))
                {
                    ret_stat = false;
                    goto process_exchange_token_exit;
                }
            }

            set_exchange_tx_out(tx_out, &tx_out->exchange_type);
            ret_stat = true;
        }
    } else {

    }

process_exchange_token_exit:

    return(ret_stat);
}

