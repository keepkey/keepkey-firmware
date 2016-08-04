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

/* === Private Variables =================================================== */
/* exchange error variable */
static ExchangeError exchange_error = NO_EXCHANGE_ERROR;

/* exchange public key for signature varification */
static uint8_t exchange_pub_key[21] =
{
    0x00, 0x95, 0xd8, 0xf6, 0x70, 0x88, 0x4f, 0x44, 0x96, 0x27, 
    0x94, 0x74, 0x35, 0xb3, 0xbc, 0x3c, 0x73, 0xd2, 0x77, 0xda, 0xda
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

    /* populate deposit address */
    tx_out->has_address = true;
    memcpy(tx_out->address, ex_tx->signed_exchange_response.response.deposit_address.address,
           sizeof(tx_out->address));

    /* populate deposit amount */
    tx_out->amount = ex_tx->signed_exchange_response.response.deposit_amount;
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
 * verify_exchange_contract() - Verify content of exchange contract is valid
 *
 * INPUT
 *     exchange:  exchange pointer
 *     root - root hd node
 * OUTPUT
 *     true/false -  success/failure
 */
static bool verify_exchange_contract(const CoinType *coin, TxOutputType *tx_out, const HDNode *root)
{
    int response_raw_filled_len = 0; 
    uint8_t response_raw[sizeof(ExchangeResponse)];
    const CoinType *response_coin;
    ExchangeType *exchange = &tx_out->exchange_type;
    
    /* verify Exchange signature */
    memset(response_raw, 0, sizeof(response_raw));
    response_raw_filled_len = encode_pb(
                                (const void *)&exchange->signed_exchange_response.response, 
                                ExchangeResponse_fields,
                                response_raw, 
                                sizeof(response_raw));

    if(response_raw_filled_len != 0)
    {
        if(cryptoMessageVerify( coin, response_raw, response_raw_filled_len, exchange_pub_key, 
                    (uint8_t *)exchange->signed_exchange_response.signature.bytes) != 0)
        {
            set_exchange_error(ERROR_EXCHANGE_SIGNATURE);
            return(false);
        }
    }
    else
    {
        set_exchange_error(ERROR_EXCHANGE_SIGNATURE);
        return(false);
    }

    /* verify Deposit coin type */
    response_coin = coinByShortcut(exchange->signed_exchange_response.response.deposit_address.coin_type);
    if(strncmp(coin->coin_name, 
               response_coin->coin_name,
               sizeof(coin->coin_name)) != 0)
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_COINTYPE);
        return(false);
    }
    /* verify Deposit address */
    if(strncmp(tx_out->address, 
               exchange->signed_exchange_response.response.deposit_address.address, 
               sizeof(tx_out->address)) != 0)
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_ADDRESS);
        return(false);
    }
    /* verify Deposit amount*/
    if(tx_out->amount != exchange->signed_exchange_response.response.deposit_amount)
    {
        set_exchange_error(ERROR_EXCHANGE_DEPOSIT_AMOUNT);
        return(false);
    }

    /* verify Withdrawal coin type */
    response_coin = coinByShortcut(exchange->signed_exchange_response.response.withdrawal_address.coin_type);
    if(strncmp(exchange->withdrawal_coin_name, 
                response_coin->coin_name,
                sizeof(coin->coin_name)) != 0)
    {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_COINTYPE);
        return(false);
    }
    /* verify Withdrawal address */
    if(!verify_exchange_address( exchange->withdrawal_coin_name,
             exchange->withdrawal_address_n_count,
             exchange->withdrawal_address_n,
             exchange->signed_exchange_response.response.withdrawal_address.address, root))
    {
        set_exchange_error(ERROR_EXCHANGE_WITHDRAWAL_ADDRESS);
        return(false);
    }

    /* verify Return coin type */
    response_coin = coinByShortcut(exchange->signed_exchange_response.response.return_address.coin_type);
    if(strncmp(coin->coin_name, 
                response_coin->coin_name,
                sizeof(coin->coin_name)) != 0)
    {
        set_exchange_error(ERROR_EXCHANGE_RETURN_COINTYPE);
        return(false);
    }
    /* verify Return address */
    if(!verify_exchange_address( (char *)response_coin->coin_name,
             exchange->return_address_n_count,
             exchange->return_address_n,
             exchange->signed_exchange_response.response.return_address.address, root))
    {
        set_exchange_error(ERROR_EXCHANGE_RETURN_ADDRESS);
        return(false);
    }
    else
    {
        set_exchange_error(NO_EXCHANGE_ERROR);
        return(true);
    }
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
bool process_exchange_contract(const CoinType *coin, TxOutputType *tx_out, const HDNode *root, bool needs_confirm)
{
    const CoinType *withdraw_coin, *deposit_coin;
    char conf_msg[100];

    if(tx_out->has_exchange_type)
    {
        /* validate contract before processing */
        if(verify_exchange_contract(coin, tx_out, root))
        {
            withdraw_coin = coinByName(tx_out->exchange_type.withdrawal_coin_name);
            deposit_coin = coinByShortcut(tx_out->exchange_type.signed_exchange_response.response.deposit_address.coin_type);

            if(needs_confirm)
            {
                snprintf(conf_msg, sizeof(conf_msg),
                         "Do you want to exchange \"%s\" to \"%s\" at rate = %d%%%% and deposit to  %s Acc #%d",
                         tx_out->exchange_type.signed_exchange_response.response.deposit_address.coin_type,
                         tx_out->exchange_type.withdrawal_coin_name,
                         (int)tx_out->exchange_type.signed_exchange_response.response.quoted_rate,
                         tx_out->exchange_type.withdrawal_coin_name,
                         (int)tx_out->exchange_type.withdrawal_address_n[2] & 0x7ffffff);

                if(!confirm_exchange(conf_msg))
                {
                    return(false);
                }

                snprintf(conf_msg, sizeof(conf_msg),
                         "Exchanging %lld %s to %lld %s and depositing to %s Acc #%d",
                         tx_out->exchange_type.signed_exchange_response.response.deposit_amount, deposit_coin->coin_shortcut,
                         tx_out->exchange_type.signed_exchange_response.response.withdrawal_amount, withdraw_coin->coin_shortcut,
                         tx_out->exchange_type.withdrawal_coin_name,
                         (int)tx_out->exchange_type.withdrawal_address_n[2] & 0x7ffffff);

                if(!confirm_exchange(conf_msg))
                {
                    return(false);
                }
            }

            set_exchange_tx_out(tx_out, &tx_out->exchange_type);
            return(true);
        }
    } 
    return(false);
}

