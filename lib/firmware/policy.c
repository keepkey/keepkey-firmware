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

#include "keepkey/firmware/policy.h"
#include "keepkey/firmware/transaction.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/exchange.h"

/*
 * run_policy_compile_output() - Policy wrapper around compile output
 *
 * INPUT
 *     - coin: coin type
 *     - root: root hd node
 *     - in: pre-process output
 *     - out: processed output
 *     - needs_confirm: whether confirm is required
 * OUTPUT
 *     integer determining whether operation was succesful
 */
int run_policy_compile_output(const CoinType *coin, const HDNode *root,
                              void *vin, void *vout, bool needs_confirm) {
  /* setup address type with respect to coin type */
  OutputAddressType addr_type;
  if (isEthereumLike(coin->coin_name)) {
    addr_type = ((EthereumSignTx *)vin)->address_type;
  } else if (strcmp("Cosmos", coin->coin_name) == 0) {
    addr_type = ((CosmosMsgSend *)vin)->address_type;
  } else {
    /* Bitcoin, Clones, Forks */
    if (vout == NULL) {
      return TXOUT_COMPILE_ERROR;
    }
    addr_type = ((TxOutputType *)vin)->address_type;
  }

  if (addr_type == OutputAddressType_EXCHANGE) {
    if (!storage_isPolicyEnabled("ShapeShift")) return TXOUT_COMPILE_ERROR;

    if (!process_exchange_contract(coin, vin, root, needs_confirm))
      return TXOUT_EXCHANGE_CONTRACT_ERROR;

    needs_confirm = false;
  }

  if (isEthereumLike(coin->coin_name)) return TXOUT_OK;

  if (strcmp("Cosmos", coin->coin_name) == 0) return TXOUT_OK;

  return compile_output(coin, root, (TxOutputType *)vin,
                        (TxOutputBinType *)vout, needs_confirm);
}
