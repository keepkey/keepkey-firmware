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
#include <bip32.h>
#include <ecdsa.h>
#include <crypto.h>
#include <types.pb.h>
#include <fsm.h>
#include <exchange.h>

/* === Defines ============================================================= */
/* === External Declarations ============================================================= */
const HDNode *fsm_getDerivedNode(uint32_t *address_n, size_t address_n_count);

/* ShapeShift's public key to verify signature on exchange token */
const uint8_t exchange_pubkey[33] =
{
    0x03, 0x53, 0x75, 0xbf, 0xd4, 0x55, 0xb4, 0x25, 0x51, 0xd0, 0xe7, 0x28, 
    0xcf, 0xdf, 0x6a, 0x21, 0xb0, 0xb4, 0xe4, 0x3e, 0xad, 0x7a, 0xb6, 0x24, 
    0x86, 0xaf, 0x56, 0x3d, 0x9e, 0xd0, 0x6e, 0xc9, 0xa8
};

/* === Private Functions =================================================== */
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

    /* Verify KeepKey DEPOSIT address*/
    memset(base58_address, 0, sizeof(base58_address));
    coin = fsm_getCoin(exchange_ptr->deposit_coin_name);
    node = fsm_getDerivedNode(exchange_ptr->deposit_address_n, exchange_ptr->deposit_address_n_count);
    ecdsa_get_address(node->public_key, coin->address_type, base58_address, sizeof(base58_address));

    if(strncmp(base58_address, exchange_ptr->response.deposit_address.address, sizeof(base58_address)))
    {
        /*error! Mismatch DEPOSIT address detected */
        goto verify_exchange_token_exit;
    }

    /* Verify KeepKey RETURN address*/
    memset(base58_address, 0, sizeof(base58_address));
    coin = fsm_getCoin(exchange_ptr->return_coin_name);
    node = fsm_getDerivedNode(exchange_ptr->return_address_n, exchange_ptr->return_address_n_count);
    ecdsa_get_address(node->public_key, coin->address_type, base58_address, sizeof(base58_address));

    if(strncmp(base58_address, exchange_ptr->response.request.return_address.address, sizeof(base58_address)))
    {
        /*error! Mismatch RETURN address detected */
        goto verify_exchange_token_exit;
    }

    /* Verify Exchange's signature */
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

    /* Validate token before processing */
    if(tx_out->has_exchange_type)
    {
        if(verify_exchange_token(&tx_out->exchange_type) == true)
        {
            /* Populate withdrawal address */
            tx_out->has_address = 1;
            memcpy(tx_out->address, tx_out->exchange_type.response.request.withdrawal_address.address, 
                sizeof(tx_out->address));

            /* Populate withdrawal amount */
            tx_out->amount = tx_out->exchange_type.response.request.withdrawal_amount;
            ret_stat = true;
        }
    }
    return(ret_stat);
}
