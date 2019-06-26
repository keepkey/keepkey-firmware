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

#ifndef KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_MAKERDAO_H
#define KEEPKEY_FIRMWARE_ETHEREUMCONTRACTS_MAKERDAO_H

#include <inttypes.h>
#include <stdbool.h>

typedef struct _EthereumSignTx EthereumSignTx;

bool makerdao_isOasisDEXAddress(const uint8_t *address, uint32_t chain_id);

bool makerdao_isOpen(const EthereumSignTx *msg);
bool makerdao_confirmOpen(const EthereumSignTx *msg);
bool makerdao_isClose(const EthereumSignTx *msg);
bool makerdao_confirmClose(const EthereumSignTx *msg);
bool makerdao_isGive(const EthereumSignTx *msg);
bool makerdao_confirmGive(const EthereumSignTx *msg);
bool makerdao_isLockAndDraw2(const EthereumSignTx *msg);
bool makerdao_confirmLockAndDraw2(const EthereumSignTx *msg);
bool makerdao_isCreateOpenLockAndDraw(const EthereumSignTx *msg);
bool makerdao_confirmCreateOpenLockAndDraw(const EthereumSignTx *msg);
bool makerdao_isLock(const EthereumSignTx *msg);
bool makerdao_confirmLock(const EthereumSignTx *msg);
bool makerdao_isDraw(const EthereumSignTx *msg);
bool makerdao_confirmDraw(const EthereumSignTx *msg);
bool makerdao_isLockAndDraw3(const EthereumSignTx *msg);
bool makerdao_confirmLockAndDraw3(const EthereumSignTx *msg);
bool makerdao_isFree(const EthereumSignTx *msg);
bool makerdao_confirmFree(const EthereumSignTx *msg);
bool makerdao_isWipe(const EthereumSignTx *msg);
bool makerdao_confirmWipe(const EthereumSignTx *msg);
bool makerdao_isWipeAndFree(const EthereumSignTx *msg);
bool makerdao_confirmWipeAndFree(const EthereumSignTx *msg);

bool makerdao_isMakerDAO(uint32_t data_total, const EthereumSignTx *msg);
bool makerdao_confirmMakerDAO(uint32_t data_total, const EthereumSignTx *msg);

#endif
