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
    0x04, 0xa3, 0x3c, 0xec, 0x36, 0xd6, 0xd0, 0x11, 0xaf, 0x09, 0xe0, 0xc4,
    0x98, 0xd1, 0x7c, 0x3b, 0xa7, 0xab, 0x90, 0x7a, 0xbf, 0xbb, 0x64, 0xca,
    0xba, 0x16, 0xad, 0x90, 0x77, 0xca, 0xac, 0xd3, 0xe1, 0x98, 0xa3, 0x23,
    0x62, 0xc3, 0x2d, 0x0e, 0xf0, 0xa7, 0x26, 0x92, 0x59, 0xab, 0xbb, 0xcd,
    0x8a, 0x68, 0x8a, 0x0c, 0x8f, 0x54, 0xa6, 0xdb, 0xc4, 0x05, 0x45, 0x95,
    0x66, 0xcd, 0x65, 0x14, 0x1d
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
    memcpy(tx_out->address, ex_tx->response.request.withdrawal_address.address,
           sizeof(tx_out->address));

    /* populate withdrawal amount */
    tx_out->amount = ex_tx->response.request.withdrawal_amount;
}

/*
 * verify_exchange_address - verify address specified in exchange token belongs to device.
 *
 * INPUT
 *     coin_name - name of coin
 *     address_n_count - depth of node
 *     address_n - pointer to node path
 *     address_str - string representation of address
 *
 * OUTPUT
 *     true/false - success/failure
 */
static bool verify_exchange_address(char *coin_name, size_t address_n_count,
                                    uint32_t *address_n, char *address_str)
{
    const CoinType *coin;
    HDNode node;
    char internal_address[36];
    bool ret_stat = false;

    coin = coinByName(coin_name);

    if(coin)
    {
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
 * OUTPUT
 *     true/false -  success/failure
 */
static bool verify_exchange_token(ExchangeType *exchange)
{
    bool ret_stat = false;
    uint8_t fingerprint[32];

    /* verify deposit address */
    if(!verify_exchange_address(exchange->deposit_coin_name,
                                exchange->deposit_address_n_count,
                                exchange->deposit_address_n,
                                exchange->response.deposit_address.address))
    {
        goto verify_exchange_token_exit;
    }

    /* verify return address */
    if(!verify_exchange_address(exchange->return_coin_name,
                                exchange->return_address_n_count,
                                exchange->return_address_n,
                                exchange->response.request.return_address.address))
    {
        goto verify_exchange_token_exit;
    }

    /* check exchange signature */
    sha256_Raw((uint8_t *)&exchange->response.request, sizeof(ExchangeRequest),
               fingerprint);

    if(ecdsa_verify_digest(&secp256k1, exchange_pubkey,
                           (uint8_t *)exchange->response.signature.bytes,
                           fingerprint) == 0)
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
 *      needs_confirm - whether requires user manual approval
 * OUTPUT
 *      true/false - success/failure
 */
bool process_exchange_token(TxOutputType *tx_out, bool needs_confirm)
{
    const CoinType *withdraw_coin, *deposit_coin;
    bool ret_stat = false;
    char conf_msg[100];

    if(tx_out->has_exchange_type)
    {
        /* validate token before processing */
        if(verify_exchange_token(&tx_out->exchange_type))
        {
            deposit_coin = coinByName(tx_out->exchange_type.deposit_coin_name);
            withdraw_coin = coinByName(tx_out->exchange_type.response.request.withdrawal_coin_type);

            if(needs_confirm)
            {
                snprintf(conf_msg, sizeof(conf_msg),
                         "Do you want to exchange \"%s\" to \"%s\" at rate = %d%%%% and deposit to  %s Acc #%d",
                         tx_out->exchange_type.response.request.withdrawal_coin_type,
                         tx_out->exchange_type.deposit_coin_name,
                         (int)tx_out->exchange_type.response.quoted_rate,
                         tx_out->exchange_type.deposit_coin_name,
                         (int)tx_out->exchange_type.deposit_address_n[2] & 0x7ffffff);

                if(!confirm_exchange(conf_msg))
                {
                    ret_stat = false;
                    goto process_exchange_token_exit;
                }

                snprintf(conf_msg, sizeof(conf_msg),
                         "Exchanging %lld %s to %lld %s and depositing to %s Acc #%d",
                         tx_out->exchange_type.response.request.withdrawal_amount, withdraw_coin->coin_shortcut,
                         tx_out->exchange_type.response.deposit_amount, deposit_coin->coin_shortcut,
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