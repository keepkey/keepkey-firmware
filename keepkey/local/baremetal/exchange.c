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
#include "keepkey_board/public/keepkey_usart.h"
/* === Defines ============================================================= */
/* === External Declarations ============================================================= */
const HDNode *fsm_getDerivedNode(uint32_t *address_n, size_t address_n_count);

/* ShapeShift's public key to verify signature on exchange token */
const uint8_t signature_pubkey[33] =
{
    0x02, 0x43, 0x4d, 0x1e, 0x0d, 0x5e, 0x6b, 0x9f, 0x3d, 0x4a, 0xfe, 0xb3, 
    0xb2, 0x43, 0x7f, 0xd2, 0x34, 0x6c, 0xa9, 0xfb, 0xca, 0x3e, 0x07, 0x58, 
    0x5f, 0xec, 0x94, 0x9b, 0x71, 0x45, 0xfd, 0xee, 0x19
};

/* KeepKey's public key to verify signature on exchange token */
const uint8_t approval_pubkey[33] =
{
    0x02, 0x0b, 0x37, 0xd6, 0x30, 0x79, 0x68, 0x8b, 0x85, 0x31, 0x7f, 0xbf, 
    0x57, 0x69, 0x75, 0xbe, 0x1c, 0x39, 0xe2, 0x21, 0x74, 0x9c, 0x9f, 0x53, 
    0xec, 0xa2, 0x7b, 0xf3, 0x45, 0x56, 0x8e, 0xb3, 0x47
};

/* === Private Functions =================================================== */
/* === Public Functions =================================================== */
void dumpbfr(char *str, uint8_t *bfr, int len)
{
    dbg_print("%s : ", str);
    for(int i = 0; i < len; i++)
    {
        dbg_print("%0.2x", *bfr++);

        if(*bfr == 0) break;
    }
    dbg_print("\n\r");
}
void showVariables(TxOutputType *tx_out)
{
    int i;
    
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
    dumpbfr("ss signature = " , tx_out->exchange_token.signature.bytes, sizeof(tx_out->exchange_token.signature.bytes));
    dumpbfr("kk signature = " , tx_out->exchange_token.approval.bytes, sizeof(tx_out->exchange_token.approval.bytes));
}

/*
 * verify_exchange_token() - check token's signature
 *
 * INPUT
 *     token_ptr:  token pointer
 * OUTPUT
 *     0 when complete
 */
static bool verify_exchange_token(SendAmountResponse *token_ptr)
{
    bool ret_stat = false;
    uint32_t result;
    uint8_t pub_key_hash[21];
    const CoinType *coin = fsm_getCoin(token_ptr->request.withdrawal_coin_type);
    dbg_print("Withdrawal coin = %s, addressType = %d\n\r", coin->coin_name, coin->address_type); 
    coin = fsm_getCoin(token_ptr->request.deposit_coin_type);
    dbg_print("Deposit coin = %s, addressType = %d\n\r", coin->coin_name, coin->address_type); 

    /* Begin ShapeShift Signature verification */
    ecdsa_get_address_raw(signature_pubkey, coin->address_type, pub_key_hash);
    dumpbfr("SS PubKey Hash(addr)", pub_key_hash, sizeof(pub_key_hash));
    result = cryptoMessageVerify(
                (const uint8_t *)&token_ptr->request, 
                sizeof(SendAmountRequest), 
                pub_key_hash, 
                (const uint8_t *)token_ptr->signature.bytes);
    if(result != 0)
    {
        dbg_print("ShapeShift signature check FAILED!!!\n\r");
        goto verify_exchange_token_exit;
    }
    /* Begin KeepKey's Signature verification */
    ecdsa_get_address_raw(approval_pubkey, coin->address_type, pub_key_hash);
    dumpbfr("KK PubKey Hash(addr)", pub_key_hash, sizeof(pub_key_hash));
    result = cryptoMessageVerify(
                (const uint8_t *)&token_ptr->request, 
                sizeof(SendAmountRequest), 
                pub_key_hash, 
                (const uint8_t *)token_ptr->approval.bytes);

    if(result == 0)
    {
        ret_stat = true;
        dbg_print("signature check PASSED!!!\n\r");
    }
    else
    {
        dbg_print("Keepkey signature check FAILED!!!\n\r");
    }
verify_exchange_token_exit:

    return(ret_stat);
}

bool process_exchange_token(TxOutputType *tx_out)
{
    bool ret_stat = false;

    showVariables(tx_out);

    /* Validate token before processing */
    if(verify_exchange_token(&tx_out->exchange_token) == true)
    {
        if(tx_out->has_exchange_token)
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

bool sign_test(SendAmountRequest *exchange_request)
{
    uint32_t result;
    char btc_address[36];
    uint32_t address_n[4] =  { 0, 0, 0, 0};
    size_t address_n_count = 0;
    SendAmountResponse exchange_token;
    bool ret_stat = false;

    const HDNode *node;

    node = fsm_getDerivedNode(address_n, address_n_count);

    /**** Private Key (hex) ***/
    dumpbfr("\n\rprivKey", (uint8_t *)node->private_key, sizeof( node->private_key));
    dumpbfr("PubKey\n\r", (uint8_t *)node->public_key, sizeof( node->public_key));

    /****  Hashed Pub Key (hex) ***/
    uint8_t pub_key_hash[21];
    ecdsa_get_address_raw(node->public_key, 0, pub_key_hash);
    dumpbfr("PubKey Hash(key )", pub_key_hash, sizeof(pub_key_hash));


    ecdsa_get_address(node->public_key, 0, btc_address, sizeof(btc_address));
    dbg_print("btc_address : %s \n\r", btc_address);


    /**** PubKey Hash from BTC address ***/
    memset(pub_key_hash, 0, sizeof(pub_key_hash));
#if 1
    ecdsa_get_address_raw(signature_pubkey, 0, pub_key_hash);
#else
     ecdsa_address_decode("1EfKbQupktEMXf4gujJ9kCFo83k1iMqwqK", pub_key_hash);
#endif
    dumpbfr("PubKey Hash(addr)", pub_key_hash, sizeof(pub_key_hash));
    

    /* clear signature */
    memset(exchange_token.signature.bytes, 0, sizeof(exchange_token.signature.bytes));
#if 0
    uint8_t message[100];
    memset(message, 0, sizeof(message));

    /* prepare data for signing */
    message[0] = 'a';
    /* sign data */
    result = cryptoMessageSign(message, 1, node->private_key, exchange_token.signature.bytes);
    dbg_print("Message signature result = %x \n\r", result);
    dumpbfr("\n\Message signature\n\r", exchange_token.signature.bytes, sizeof(exchange_token.signature.bytes));
    result = cryptoMessageVerify(message, 1, pub_key_hash,exchange_token.signature.bytes);
#else
    result = cryptoMessageSign((const uint8_t *)exchange_request, sizeof(SendAmountRequest), node->private_key, exchange_token.signature.bytes);
    dbg_print("Token signature result = %x \n\r", result);
    dumpbfr("\n\rToken signature\n\r", exchange_token.signature.bytes, sizeof(exchange_token.signature.bytes));

    /*corrupt signature */
//     exchange_token.signature.bytes[1] &= 0xF0;
    result = cryptoMessageVerify((const uint8_t *)exchange_request, sizeof(SendAmountRequest), pub_key_hash,exchange_token.signature.bytes);
#endif

    if(result == 0)
    {
        dbg_print("\n\r ++++ PASSED: signature matched \n\r");
        ret_stat = true;
    }
    else
    {
        dbg_print("\n\r ???? FAILED (result = %x): signature not matched!!!  \n\r", result);
        dumpbfr("signature", exchange_token.signature.bytes, sizeof(exchange_token.signature.bytes));
    }
    return(ret_stat);
}
