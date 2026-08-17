/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2022 markrypto
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

#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts/saproxy.h"
#include "keepkey/firmware/ethereum_contracts/thortx.h"
#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"
#include "keepkey/firmware/ethereum_contracts/zxtransERC20.h"
#include "keepkey/firmware/ethereum_contracts/zxswap.h"
#include "keepkey/firmware/ethereum_contracts/makerdao.h"

bool ethereum_contractHandled(uint32_t data_total, const EthereumSignTx* msg,
                              const HDNode* node) {
  (void)node;

  /* 0x transformERC20 is pinned to the ExchangeProxy address and its outcome
   * is bounded by the input amount and minimum output amount shown on screen,
   * so it stays clear-signable at any calldata size; its transformations[]
   * tail legitimately exceeds one 1024-byte chunk. */
  if (zx_isZxTransformERC20(msg)) return true;

  /* Every other handler parses and displays fixed offsets inside the initial
   * chunk only. If the calldata does not fit in that chunk, the remainder
   * streams in via EthereumTxAck and is hashed into the signature without
   * ever being shown, so refuse to claim the tx and fall through to the
   * generic raw-data disclosure path. */
  if (data_total != msg->data_initial_chunk.size) return false;

  if (sa_isWithdrawFromSalary(msg)) return true;
  if (zx_isZxSwap(msg)) return true;
  if (zx_isZxLiquidTx(msg)) return true;
  if (zx_isZxApproveLiquid(msg)) return true;

  if (thor_isThorchainTx(msg)) return true;

  if (makerdao_isMakerDAO(data_total, msg)) return true;

  return false;
}

bool ethereum_contractConfirmed(uint32_t data_total, const EthereumSignTx* msg,
                                const HDNode* node) {
  (void)node;

  if (sa_isWithdrawFromSalary(msg))
    return sa_confirmWithdrawFromSalary(data_total, msg);

  if (zx_isZxTransformERC20(msg))
    return zx_confirmZxTransERC20(data_total, msg);

  if (zx_isZxSwap(msg)) return zx_confirmZxSwap(data_total, msg);

  if (zx_isZxLiquidTx(msg)) return zx_confirmZxLiquidTx(data_total, msg);

  if (zx_isZxApproveLiquid(msg))
    return zx_confirmApproveLiquidity(data_total, msg);

  if (thor_isThorchainTx(msg)) return thor_confirmThorTx(data_total, msg);

  if (makerdao_isMakerDAO(data_total, msg))
    return makerdao_confirmMakerDAO(data_total, msg);

  return false;
}
