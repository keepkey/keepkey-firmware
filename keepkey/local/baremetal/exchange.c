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
#include <fsm.h>
#include <exchange.h>
#include <layout.h>
#include <app_confirm.h>

/* === Defines ============================================================= */
/* === External Declarations ================================================*/

/* === Private Variables =================================================== */
/* ShapeShift's public key to verify signature on exchange token */
static const uint8_t exchange_pubkey[33] =
{
    0x02, 0x1c, 0x8f, 0xef, 0xda, 0x71, 0xa2, 0x05, 0x13, 0x42, 0x6b, 0x86, 
    0xde, 0x44, 0xae, 0x74, 0xe9, 0x5a, 0x50, 0x75, 0xdc, 0xb3, 0xcf, 0xd5, 
    0xa3, 0xa6, 0x39, 0xec, 0xa9, 0xbe, 0xe0, 0xdf, 0x92
};

static struct {
    bool exch_flag;
    ExchangeType exch_image;
}exchangeTx;

/* === Private Functions =================================================== */
/*
 *  set_exchange_txout() - inline function to populate the transaction output buffer
 *
 *  INPUT
 *      tx_out - pointer to transaction output buffer
 *  OUTPUT
 *      none
 */
inline void set_exchange_txout(TxOutputType *tx_out, ExchangeType *ex_tx) 
{
    /* clear to prep transaction output */
    memset(tx_out, 0, (size_t)((char *)&tx_out->has_address_type - (char *)tx_out));

    /* Populate withdrawal address */
    tx_out->has_address = 1;
    memcpy(tx_out->address, ex_tx->response.request.withdrawal_address.address, 
        sizeof(tx_out->address));

    /* Populate withdrawal amount */
    tx_out->amount = ex_tx->response.request.withdrawal_amount;
}

/*
 * verify_exchange_token() - Verify "Deposit" and "Return" addresses belong to Keepkey and verify token's signature
 *                           is a valid 
 * INPUT
 *     exchange_ptr:  exchange pointer
 * OUTPUT
 *     true - success 
 *     false - failure
 */
static bool verify_exchange_token(ExchangeType *exchange_ptr)
{
    bool ret_stat = false;
    uint32_t result = CODE_ERR;
    uint8_t pub_key_hash[21];
    const HDNode *node;
    const CoinType *coin;
    char base58_address[36];

    /**************************************************
     *          Verify KeepKey DEPOSIT address            
     **************************************************/
    memset(base58_address, 0, sizeof(base58_address));
    coin = fsm_getCoin(exchange_ptr->deposit_coin_name);
    if(!coin)
    {
        node = fsm_getDerivedNode(exchange_ptr->deposit_address_n, exchange_ptr->deposit_address_n_count);
        ecdsa_get_address(node->public_key, coin->address_type, base58_address, sizeof(base58_address));

        if(strncmp(base58_address, exchange_ptr->response.deposit_address.address, sizeof(base58_address)))
        {
            /*error! Mismatch DEPOSIT address detected */
            goto verify_exchange_token_exit;
        }
    }
    else
    {
        /*error! Unknown coin type */
        goto verify_exchange_token_exit;
    }

    /**************************************************
     *          Verify KeepKey RETURN address
     **************************************************/
    memset(base58_address, 0, sizeof(base58_address));
    coin = fsm_getCoin(exchange_ptr->return_coin_name);
    if(!coin)
    {
        node = fsm_getDerivedNode(exchange_ptr->return_address_n, exchange_ptr->return_address_n_count);
        ecdsa_get_address(node->public_key, coin->address_type, base58_address, sizeof(base58_address));

        if(strncmp(base58_address, exchange_ptr->response.request.return_address.address, sizeof(base58_address)))
        {
            /*error! Mismatch RETURN address detected */
            goto verify_exchange_token_exit;
        }
    }
    else
    {
        /*error! Unknown coin type */
        goto verify_exchange_token_exit;
    }

    /**************************************************
     *          Verify Exchange's signature 
     **************************************************/
    /* withdrawal coin type */
    memset(pub_key_hash, 0, sizeof(pub_key_hash));
    ecdsa_get_address_raw(exchange_pubkey, BTC_ADDR_TYPE, pub_key_hash);
    result = cryptoMessageVerify(
                (const uint8_t *)&exchange_ptr->response.request, 
                sizeof(ExchangeRequest), 
                pub_key_hash, 
                (const uint8_t *)exchange_ptr->response.signature.bytes);

verify_exchange_token_exit:
    if(result == 0) 
    {
        ret_stat = true;
    }
    return(ret_stat);
}

/* === Public Functions =================================================== */
/*
 * reset_exchangetx() - reset exchange related variables to initial state
 * INPUT
 *      none 
 * OUTPUT
 *      none
 */
void reset_exchangetx(void)
{
    /* clear to initialize exchange data */
    memset(&exchangeTx, 0, sizeof(exchangeTx));
}

/*
 * process_exchange_token() - validate token from exchange and populate the transaction
 *                            output structure
 *
 * INPUT
 *      tx_out - pointer transaction output structure
 * OUTPUT
 *      true - success
 *      false - failure
 */
bool process_exchange_token(TxOutputType *tx_out)
{
    bool ret_stat = false;
    char conf_msg[100];

    if(tx_out->has_exchange_type)
    {
        /* process exchange transaction once and cache it until the transaction is complete*/
        if(!exchangeTx.exch_flag)
        {
            /* Validate token before processing */
            if(verify_exchange_token(&tx_out->exchange_type) == true)
            {
                memset(conf_msg, 0, sizeof(conf_msg));
                /* get user confirmation */
                snprintf(conf_msg, sizeof(conf_msg), "Do you want to exchange \"%s\" to \"%s\" at rate = %d%%%% and deposit to  %s Acc #%d", 
                            tx_out->exchange_type.response.request.withdrawal_coin_type, 
                            tx_out->exchange_type.response.request.deposit_coin_type,
                            (int)tx_out->exchange_type.response.quoted_rate,
                            tx_out->exchange_type.deposit_coin_name, 
                            (int)tx_out->exchange_type.deposit_address_n[2] & 0x7ffffff); 
                if(confirm_exchange(conf_msg))
                {
                    snprintf(conf_msg, sizeof(conf_msg), "Exchanging %lld BTC to %lld LTC and depositing to %s Acc #%d", 
                            tx_out->exchange_type.response.request.withdrawal_amount, 
                            tx_out->exchange_type.response.deposit_amount,
                            tx_out->exchange_type.deposit_coin_name, 
                            (int)tx_out->exchange_type.deposit_address_n[2] & 0x7ffffff); 
                    if(confirm_exchange(conf_msg))
                    {
                        set_exchange_txout(tx_out, &tx_out->exchange_type);
                        exchangeTx.exch_flag = 1;
                        /* cache exchange_type for the transaction */
                        exchangeTx.exch_image = tx_out->exchange_type;
                        ret_stat = true;
                    }
                }
            }
        }
        else
        {
            /* Verify if the exchange token is from the same transaction.  */
            if(!memcmp(&exchangeTx.exch_image, &tx_out->exchange_type, sizeof(ExchangeType)))
            {

                /* Found the token to be the same.  Populate the transaction output with cached data*/
                set_exchange_txout(tx_out, &tx_out->exchange_type);
                ret_stat = true;

            }
        }
    }
    return(ret_stat);
}

