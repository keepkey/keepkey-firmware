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
const uint8_t exchange_pubkey[33] =
{
    0x03, 0x53, 0x75, 0xbf, 0xd4, 0x55, 0xb4, 0x25, 0x51, 0xd0, 0xe7, 0x28, 
    0xcf, 0xdf, 0x6a, 0x21, 0xb0, 0xb4, 0xe4, 0x3e, 0xad, 0x7a, 0xb6, 0x24, 
    0x86, 0xaf, 0x56, 0x3d, 0x9e, 0xd0, 0x6e, 0xc9, 0xa8
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
    const CoinType *coin;
    

    coin = fsm_getCoin(tx_out->exchange_type.response.request.withdrawal_coin_type);
    dbg_print("Withdrawal coin type = %s, addr_Type = %d\n\r", tx_out->exchange_type.response.request.withdrawal_coin_type, coin->address_type);

    coin = fsm_getCoin(tx_out->exchange_type.response.request.deposit_coin_type);
    dbg_print("Deposit coin type = %s, addr_Type = %d\n\r", tx_out->exchange_type.response.request.deposit_coin_type, coin->address_type);

    dbg_print("wdrawalAmount(%ld) = %d \n\r", 
            &tx_out->exchange_type.response.request.withdrawal_amount, tx_out->exchange_type.response.request.withdrawal_amount);

    dbg_print("WdrawAddr= ");
    for(i = 0; i < 33; i++)
    {
        dbg_print("%c", tx_out->exchange_type.response.request.withdrawal_address.address[i]);
    }
    dbg_print("\n\r");

    dbg_print("RetAddr= ");
    for(i = 0; i < 33; i++)
    {
        dbg_print("%c", tx_out->exchange_type.response.request.return_address.address[i]);
    }
    dbg_print("\n\r");

    dbg_print("DepAddr= ");
    for(i = 0; i < 33; i++)
    {
        dbg_print("%c", tx_out->exchange_type.response.deposit_address.address[i]);
    }
    dbg_print("\n\r");
    dumpbfr("ss signature = " , tx_out->exchange_type.response.signature.bytes, sizeof(tx_out->exchange_type.response.signature.bytes));

    sign_test(&tx_out->exchange_type.response.request);
}

/*
 * verify_exchange_token() - check token's signature
 *
 * INPUT
 *     exchange_ptr:  exchange pointer
 * OUTPUT
 *     0 when complete
 */
static bool verify_exchange_token(ExchangeType *exchange_ptr)
{
    bool ret_stat = false;
    uint32_t result = 0xff;
    uint8_t pub_key_hash[21];
    const HDNode *node;
    const CoinType *coin;
    char base58_address[36];

    dbg_print("%s : Deposit coin %s \n\r", __FUNCTION__, exchange_ptr->deposit_coin_name);
    for(uint32_t i = 0; i < exchange_ptr->deposit_address_n_count; i++)
    {
        dbg_print("     Deposit Node[%d] 0x%x\n\r", i, exchange_ptr->deposit_address_n[i]);
    }

    coin = fsm_getCoin(exchange_ptr->deposit_coin_name);
    memset(base58_address, 0, sizeof(base58_address));
    node = fsm_getDerivedNode(exchange_ptr->deposit_address_n, exchange_ptr->deposit_address_n_count);
    ecdsa_get_address(node->public_key, coin->address_type, base58_address, sizeof(base58_address));
    dbg_print("%s(%d) base58 address = %s\n\r",  
            exchange_ptr->deposit_coin_name, coin->address_type, base58_address);

    dbg_print("\t     dep addr %s \n\r", exchange_ptr->response.deposit_address.address);

    /* verify deposite address belongs to KeepKey */
    if(strncmp(base58_address, exchange_ptr->response.deposit_address.address, sizeof(base58_address)))
    {
        goto verify_exchange_token_exit;
    }

    for(uint32_t i = 0; i < exchange_ptr->return_address_n_count; i++)
    {
        dbg_print("     Return Node[%d] 0x%x\n\r", i, exchange_ptr->return_address_n[i]);
    }

    /* verify return address belongs to KeepKey */
    coin = fsm_getCoin(exchange_ptr->return_coin_name);
    memset(base58_address, 0, sizeof(base58_address));
    node = fsm_getDerivedNode(exchange_ptr->return_address_n, exchange_ptr->return_address_n_count);
    ecdsa_get_address(node->public_key, coin->address_type, base58_address, sizeof(base58_address));

    dbg_print("%s(%d) base58 address = %s\n\r",  
            exchange_ptr->return_coin_name, coin->address_type, base58_address);

    dbg_print("\t: %s\n\r", exchange_ptr->response.request.return_address.address);

    /* verify deposite address belongs to KeepKey */
    if(strncmp(base58_address, exchange_ptr->response.request.return_address.address, sizeof(base58_address)))
    {
        dbg_print("    Return address check failed!!! %s : %s\n\r", base58_address, 
                exchange_ptr->response.request.return_address.address);

        goto verify_exchange_token_exit;
    }

    /* Exchange Signature Verification */
    /* withdrawal coin type */

#if 0
    coin = fsm_getCoin(exchange_ptr->response.request.withdrawal_coin_type);
    ecdsa_get_address_raw(exchange_pubkey, coin->address_type, pub_key_hash);
#else
    memset(pub_key_hash, 0, sizeof(pub_key_hash));
    ecdsa_get_address_raw(exchange_pubkey, 0, pub_key_hash);
#endif
    dumpbfr(" Node PubKey Hash(key )", pub_key_hash, sizeof(pub_key_hash));
    uint8_t sig[65];
    uint32_t ss_address_n[4] = {0x80000000, 0x80000003, 0x80000000, 0x0};
    node = fsm_getDerivedNode(ss_address_n, 4);
    memset(sig, 0, sizeof(sig));
    
    result = cryptoMessageSign((const uint8_t *)&exchange_ptr->response.request, 
            sizeof(exchange_ptr->response.request), 
            node->private_key, sig);

    dbg_print("result = %d\n\r", result);

    dumpbfr(" XXXXXX  sig = ", sig, sizeof(sig));
    dumpbfr(" YYYYYY  sig = ", (uint8_t *)exchange_ptr->response.signature.bytes, sizeof(sig));
    if(strncmp((void *)sig, (void *)exchange_ptr->response.signature.bytes, sizeof(sig)))
    {
        dbg_print("*********** Failed ************* \n\r");
        for(uint32_t i = 0; i < sizeof(sig); i++)
        {
            dbg_print("\t 0x%0.2x : 0x%0.2x", sig[i], exchange_ptr->response.signature.bytes[i]);
            if(sig[i] == exchange_ptr->response.signature.bytes[i])
            {
                dbg_print("\n\r");
            }
            else
            {
                dbg_print("? \n\r");
            }
        }
    }
    else
    {
        dbg_print("*********** Passed ************* \n\r");
    }

#if 0
    memset(sig, 0, sizeof(sig));
    memcpy(sig, exchange_ptr->response.signature.bytes, sizeof(sig));
//    memcpy(sig, exchange_ptr->response.signature.bytes, sizeof(exchange_ptr->response.signature.bytes));
#endif
    dbg_print("ptr = 0x%x \n\r", exchange_ptr->response.signature.bytes);

    result = cryptoMessageVerify(
                (const uint8_t *)&exchange_ptr->response.request, 
                sizeof(ExchangeRequest), 
                pub_key_hash, 
                (const uint8_t *)exchange_ptr->response.signature.bytes);
//                (const uint8_t *)sig);

verify_exchange_token_exit:
    if(result == 0)
    {
        dbg_print("Exchange signature check OK!!!\n\r"); 
        ret_stat = true;
    }

    return(ret_stat);
}

bool process_exchange_token(TxOutputType *tx_out)
{
    bool ret_stat = false;

    showVariables(tx_out);

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

bool create_signature(const HDNode *node, ExchangeResponse *token, const uint8_t *msg)
{
    bool ret_stat = false;
    uint8_t pub_key_hash[21];
    char btc_address[36];
    uint32_t result;

    /****  Hashed Pub Key from node ***/
    ecdsa_get_address_raw(node->public_key, 0, pub_key_hash);
    dumpbfr("Node PubKey Hash(key )", pub_key_hash, sizeof(pub_key_hash));

    /* Calculate Bit coin address (base58) */
    ecdsa_get_address(node->public_key, 0, btc_address, sizeof(btc_address));
    dbg_print("btc_address : %s \n\r", btc_address);


    memset(pub_key_hash, 0, sizeof(pub_key_hash));
#if 1
    ecdsa_get_address_raw(exchange_pubkey, 0, pub_key_hash);
#else
    /**** PubKey Hash from BTC address ***/
    ecdsa_address_decode("1EfKbQupktEMXf4gujJ9kCFo83k1iMqwqK", pub_key_hash);
#endif
    dumpbfr("SS PubKey Hash(addr)", pub_key_hash, sizeof(pub_key_hash));
    

    /* clear signature */
    memset(token->signature.bytes, 0, sizeof(token->signature.bytes));
    result = cryptoMessageSign(msg, sizeof(ExchangeRequest), 
            node->private_key, token->signature.bytes);
    if(result == 0)
    {
        dumpbfr("Token signature\n\r", token->signature.bytes, sizeof(token->signature.bytes));
        ret_stat = true;
    }
    else
    {
        dbg_print("error creating signature \n\r");
    }
    return(ret_stat);

}

bool sign_test(ExchangeRequest *exchange_request)
{
    uint32_t result;
    bool ret_stat = false;
    const HDNode *ss_node;
    ExchangeResponse exchange_response;
    uint32_t ss_address_n[4] = {0x80000000, 0x80000003, 0x80000000, 0x0};
    uint8_t pub_key_hash[21];

    ss_node = fsm_getDerivedNode(ss_address_n, 4);
    /**** Private Key (hex) ***/
    dumpbfr("SS privKey", (uint8_t *)ss_node->private_key, sizeof( ss_node->private_key));
    /**** Public Key (hex) ***/
    dumpbfr("SS PubKey", (uint8_t *)ss_node->public_key, sizeof( ss_node->public_key));
    create_signature(ss_node, &exchange_response, (const uint8_t *)exchange_request);

/*corrupt signature */
//    exchange_response.signature.bytes[1] &= 0xF0;
    /****  Hashed Pub Key from node ***/
    ecdsa_get_address_raw(ss_node->public_key, 0, pub_key_hash);
    result = cryptoMessageVerify((const uint8_t *)exchange_request, sizeof(ExchangeRequest), 
            pub_key_hash,exchange_response.signature.bytes);

    if(result == 0)
    {
        dbg_print("\n\r %s++++ PASSED: signature matched \n\r", __FUNCTION__);
        ret_stat = true;
    }
    else
    {
        dbg_print("\n\r ???? FAILED (result = %x): signature not matched!!!  \n\r", result);
        dumpbfr("signature", exchange_response.signature.bytes, sizeof(exchange_response.signature.bytes));
    }
    return(ret_stat);
}
