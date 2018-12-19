/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 KeepKey
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

#ifndef KEEPKEY_FIRMWARE_EOS_CONTRACTS_EOSIOTOKEN_H
#define KEEPKEY_FIRMWARE_EOS_CONTRACTS_EOSIOTOKEN_H

#include <stdbool.h>

typedef struct _EosActionCommon EosActionCommon;
typedef struct _EosActionTransfer EosActionTransfer;

/// \returns true iff successful.
bool eos_compileActionTransfer(const EosActionCommon *common,
                               const EosActionTransfer *action);

#endif
