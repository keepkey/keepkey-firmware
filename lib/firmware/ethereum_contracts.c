/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2019 ShapeShift
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

#include "keepkey/firmware/ethereum_contracts.h"

#include "keepkey/firmware/ethereum_contracts/thortx.h"
#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"
#include "keepkey/firmware/ethereum_contracts/zxswap.h"
#include "keepkey/firmware/ethereum_contracts/makerdao.h"

bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx *msg,
                              const HDNode *node) {
  (void)node;


  if (zx_isZxSwap(msg)) return true;
  if (zx_isZxLiquidTx(msg)) return true;
  if (zx_isZxApproveLiquid(msg)) return true;

  if (thor_isThorchainTx(msg)) return true;

  if (makerdao_isMakerDAO(data_total, msg)) return true;

  return false;
}

bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx *msg,
                                const HDNode *node) {
  (void)node;

  if (zx_isZxSwap(msg))
    return zx_confirmZxSwap(data_total, msg);

  if (zx_isZxLiquidTx(msg))
    return zx_confirmZxLiquidTx(data_total, msg);

  if (zx_isZxApproveLiquid(msg))
    return zx_confirmApproveLiquidity(data_total, msg);

  if (thor_isThorchainTx(msg))
    return thor_confirmThorTx(data_total, msg);
  
  if (makerdao_isMakerDAO(data_total, msg))
    return makerdao_confirmMakerDAO(data_total, msg);

  return false;
}
