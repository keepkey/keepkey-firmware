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
// #include <exchange.pb.h>
#include <types.pb.h>
#include <fsm.h>
#include "keepkey_board/public/keepkey_usart.h"
/* === Defines ============================================================= */
/* === External Declarations ============================================================= */
const HDNode *fsm_getDerivedNode(uint32_t *address_n, size_t address_n_count);
const uint8_t shapeshift_pubkey[33] =
{
    0x03, 0xf6, 0x45, 0xec, 0x65, 0x44, 0xa9, 0x2f, 0x95, 0x1f, 0x3b, 0xca, 
    0x16, 0xa2, 0xbc, 0x1c, 0x56, 0x84, 0x6d, 0x06, 0x55, 0x94, 0xdb, 0x22,
    0x27, 0x25, 0xd5, 0x9b, 0x99, 0x02, 0x52, 0x83, 0x85
};

/* === Private Functions =================================================== */
/* === Public Functions =================================================== */
void dumpbfr(char *str, uint8_t *bfr, int len)
{
    dbg_print("%s : ", str);
    for(int i = 0; i < len; i++)
    {
        dbg_print("%0.2x", *bfr++);
    }
    dbg_print("\n\r");
}
void showVariables(TxOutputType *tx_out)
{
    int i;
    
    dbg_print("signature = "); 
    for(i = 0; i < 150; i++)
    {
        dbg_print("%c", tx_out->exchange_token.signature.bytes[i]);
    }
    dbg_print("\n\r");

    dbg_print("wdrawalAmount(%ld) = %d \n\r", 
            &tx_out->exchange_token.request.withdrawal_amount, tx_out->exchange_token.request.withdrawal_amount);
    dbg_print("%s \n\r", tx_out->exchange_token.request.withdrawal_coin_type);
    dbg_print("%s \n\r", tx_out->exchange_token.request.deposit_coin_type);

    dbg_print("WdrawAddr= ");
    for(i = 0; i < 33; i++)
    {
        dbg_print("%c", tx_out->exchange_token.request.withdrawal_address.address[i]);
    }
    dbg_print("\n\r");

    dbg_print("RetAddr= ");
    for(i = 0; i < 33; i++)
    {
        dbg_print("%c", tx_out->exchange_token.request.return_address.address[i]);
    }
    dbg_print("\n\r");

    dbg_print("DepAddr= ");
    for(i = 0; i < 33; i++)
    {
        dbg_print("%c", tx_out->exchange_token.deposit_address.address[i]);
    }
    dbg_print("\n\r");

}
#if 1
static bool verify_exchange_token(SendAmountResponse *token_ptr)
{
    bool ret_stat = false;
    dbg_print("\n\r****%s(STUBBED!!!!) - withdrawal amount = 0x%d \n\r\n\r", __FUNCTION__, token_ptr->request.withdrawal_amount);
    ret_stat = true;
    return(ret_stat);
}

bool process_exchange_token(TxOutputType *tx_out)
{
    bool ret_stat = false;

    showVariables(tx_out);

    /* Validate token before processing */
    if(verify_exchange_token(&tx_out->exchange_token) == true)
    {
        if(!tx_out->has_address && !tx_out->address_n_count)
        {
            /* Populate withdrawal address */
            tx_out->has_address = 1;
            memcpy(tx_out->address, tx_out->exchange_token.request.withdrawal_address.address, 
                sizeof(tx_out->address));

            /* Populate withdrawal amount */
            tx_out->amount = tx_out->exchange_token.request.withdrawal_amount;
            ret_stat = true;
        }
    }

    return(ret_stat);
}

#else
bool process_exchange_token(void)
{
    uint8_t message[100];
    uint32_t result;
    char btc_address[36];
    uint32_t address_n[4] =  { 0, 0, 0, 0};
    size_t address_n_count = 0;
    SendAmountResponse exchange_token;

    const HDNode *node;

    node = fsm_getDerivedNode(address_n, address_n_count);

    /**** Private Key (hex) ***/
    dumpbfr("privKey", (uint8_t *)node->private_key, sizeof( node->private_key));
    dumpbfr("PubKey", (uint8_t *)node->public_key, sizeof( node->public_key));

    /****  Hashed Pub Key (hex) ***/
    uint8_t pub_key_hash[21];
    ecdsa_get_address_raw(node->public_key, 0, pub_key_hash);
    dumpbfr("PubKey Hash(key )", pub_key_hash, sizeof(pub_key_hash));
    ecdsa_get_address(node->public_key, 0, btc_address, sizeof(btc_address));

    dbg_print("btc_address : %s \n\r", btc_address);

    /**** PubKey Hash from BTC address ***/
    memset(pub_key_hash, 0, sizeof(pub_key_hash));
#if 1
    ecdsa_get_address_raw(shapeshift_pubkey, 0, pub_key_hash);
#else
     ecdsa_address_decode("1EfKbQupktEMXf4gujJ9kCFo83k1iMqwqK", pub_key_hash);
#endif
    dumpbfr("PubKey Hash(addr)", pub_key_hash, sizeof(pub_key_hash));
    

    /* clear signature */
    memset(exchange_token.signature.bytes, 0, sizeof(exchange_token.signature.bytes));
    memset(message, 0, sizeof(message));

    /* prepare data for signing */
    message[0] = 'a';
    /* sign data */
    result = cryptoMessageSign(message, 1, node->private_key, exchange_token.signature.bytes);
    dbg_print("signature result = %x \n\r", result);
    dumpbfr("signature", exchange_token.signature.bytes, sizeof(exchange_token.signature.bytes));

    /*corrupt signature */
//     exchange_token.signature.bytes[1] &= 0xF0;
    result = cryptoMessageVerify(message, 1, pub_key_hash,exchange_token.signature.bytes);

    if(result == 0)
    {
        dbg_print("\n\r ++++ PASSED: signature matched \n\r");
    }
    else
    {
        dbg_print("\n\r ???? FAILED (result = %x): signature not matched!!!  \n\r", result);
        dumpbfr("signature", exchange_token.signature.bytes, sizeof(exchange_token.signature.bytes));
    }
    return(1);
}
#endif
