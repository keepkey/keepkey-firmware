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
  if (isAccountBased(coin->coin_name)) return TXOUT_OK;

  /* Bitcoin, Clones, Forks */
  if (vout == NULL) {
    return TXOUT_COMPILE_ERROR;
  }

  return compile_output(coin, root, (TxOutputType *)vin,
                        (TxOutputBinType *)vout, needs_confirm);
}
