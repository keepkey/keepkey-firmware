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
    0x02, 0x21, 0xcf, 0xe4, 0x46, 0x70, 0xba, 0x4a, 0xa5, 0xa9, 0xd5, 0x6d, 
    0x99, 0x3b, 0x0e, 0x8e, 0x0c, 0xd1, 0x5c, 0x1c, 0xd3, 0x56, 0xf3, 0x6d, 
    0x42, 0x15, 0xc0, 0x8a, 0x83, 0xa9, 0x89, 0xd6, 0x1d
};

/* KeepKey's public key to verify signature on exchange token */
const uint8_t approval_pubkey[33] =
{
    0x02, 0x0b, 0x0b, 0x62, 0xdd, 0xc3, 0xca, 0x4e, 0x29, 0xa2, 0x67, 0xad, 
    0x99, 0x21, 0xc3, 0x2b, 0x11, 0x81, 0x43, 0x2c, 0x5a, 0x70, 0xcf, 0x48, 
    0xe4, 0x40, 0x3f, 0xb4, 0x8b, 0xf4, 0xd6, 0x90, 0xc0
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
    const CoinType *coin;
    

    coin = fsm_getCoin(tx_out->exchange_token.request.withdrawal_coin_type);
    dbg_print("Withdrawal coin type = %s, addr_Type = %d\n\r", tx_out->exchange_token.request.withdrawal_coin_type, coin->address_type);

    coin = fsm_getCoin(tx_out->exchange_token.request.deposit_coin_type);
    dbg_print("Deposit coin type = %s, addr_Type = %d\n\r", tx_out->exchange_token.request.deposit_coin_type, coin->address_type);

    dbg_print("wdrawalAmount(%ld) = %d \n\r", 
            &tx_out->exchange_token.request.withdrawal_amount, tx_out->exchange_token.request.withdrawal_amount);

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


//    sign_test(&tx_out->exchange_token.request);
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
    const CoinType *coin;

    /* withdrawal coin type */
    coin = fsm_getCoin(token_ptr->request.withdrawal_coin_type);

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
        dbg_print("error: ShapeShift signature check FAILED!!!\n\r");
        goto verify_exchange_token_exit;
    }
    else
    {
        dbg_print("ShapeShift signature check OK!!!\n\r");

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

bool create_signature(const HDNode *node, SendAmountResponse *token, const uint8_t *msg)
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
    ecdsa_get_address_raw(signature_pubkey, 0, pub_key_hash);
#else
    /**** PubKey Hash from BTC address ***/
    ecdsa_address_decode("1EfKbQupktEMXf4gujJ9kCFo83k1iMqwqK", pub_key_hash);
#endif
    dumpbfr("SS PubKey Hash(addr)", pub_key_hash, sizeof(pub_key_hash));
    

    /* clear signature */
    memset(token->signature.bytes, 0, sizeof(token->signature.bytes));
    result = cryptoMessageSign(msg, sizeof(SendAmountRequest), 
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

bool sign_test(SendAmountRequest *exchange_request)
{
    uint32_t result;
    bool ret_stat = false;
    const HDNode *ss_node, *kk_node;
    SendAmountResponse exchange_token;
    size_t address_n_count = 2;
    uint32_t ss_address_n[2] = {0x80000000, 0x80000003};
    uint32_t kk_address_n[2] = {0x80000000, 0x80000002};
    uint8_t pub_key_hash[21];

    ss_node = fsm_getDerivedNode(ss_address_n, address_n_count);
    /**** Private Key (hex) ***/
    dumpbfr("SS privKey", (uint8_t *)ss_node->private_key, sizeof( ss_node->private_key));
    /**** Public Key (hex) ***/
    dumpbfr("SS PubKey", (uint8_t *)ss_node->public_key, sizeof( ss_node->public_key));
    create_signature(ss_node, &exchange_token, (const uint8_t *)exchange_request);

    kk_node = fsm_getDerivedNode(kk_address_n, address_n_count);
    /**** Private Key (hex) ***/
    dumpbfr("KK privKey", (uint8_t *)kk_node->private_key, sizeof(kk_node->private_key));
    /**** Public Key (hex) ***/
    dumpbfr("KK PubKey", (uint8_t *)kk_node->public_key, sizeof(kk_node->public_key));
    create_signature(kk_node, &exchange_token, (const uint8_t *)exchange_request);

/*corrupt signature */
//    exchange_token.signature.bytes[1] &= 0xF0;
    /****  Hashed Pub Key from node ***/
    ecdsa_get_address_raw(ss_node->public_key, 0, pub_key_hash);
    result = cryptoMessageVerify((const uint8_t *)exchange_request, sizeof(SendAmountRequest), 
            pub_key_hash,exchange_token.signature.bytes);

    if(result == 0)
    {
        dbg_print("\n\r %s++++ PASSED: signature matched \n\r", __FUNCTION__);
        ret_stat = true;
    }
    else
    {
        dbg_print("\n\r ???? FAILED (result = %x): signature not matched!!!  \n\r", result);
        dumpbfr("signature", exchange_token.signature.bytes, sizeof(exchange_token.signature.bytes));
    }
    return(ret_stat);
}
