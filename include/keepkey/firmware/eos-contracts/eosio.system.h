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

#ifndef KEEPKEY_FIRMWARE_EOS_CONTRACTS_EOSIOSYSTEM_H
#define KEEPKEY_FIRMWARE_EOS_CONTRACTS_EOSIOSYSTEM_H

#include "keepkey/firmware/coins.h"

#include <stdbool.h>

typedef struct _EosActionBuyRam EosActionBuyRam;
typedef struct _EosActionBuyRamBytes EosActionBuyRamBytes;
typedef struct _EosActionCommon EosActionCommon;
typedef struct _EosActionDelegate EosActionDelegate;
typedef struct _EosActionDeleteAuth EosActionDeleteAuth;
typedef struct _EosActionLinkAuth EosActionLinkAuth;
typedef struct _EosActionNewAccount EosActionNewAccount;
typedef struct _EosActionRefund EosActionRefund;
typedef struct _EosActionSellRam EosActionSellRam;
typedef struct _EosActionUndelegate EosActionUndelegate;
typedef struct _EosActionUnlinkAuth EosActionUnlinkAuth;
typedef struct _EosActionUpdateAuth EosActionUpdateAuth;
typedef struct _EosActionVoteProducer EosActionVoteProducer;
typedef struct _EosAuthorization EosAuthorization;

/// \returns true iff successful.
bool eos_compileActionDelegate(const EosActionCommon *common,
                               const EosActionDelegate *action);

/// \returns true iff successful.
bool eos_compileActionUndelegate(const EosActionCommon *common,
                                 const EosActionUndelegate *action);

/// \returns true iff successful.
bool eos_compileActionRefund(const EosActionCommon *common,
                             const EosActionRefund *action);

/// \returns true iff successful.
bool eos_compileActionBuyRam(const EosActionCommon *common,
                             const EosActionBuyRam *action);

/// \returns true iff successful.
bool eos_compileActionBuyRamBytes(const EosActionCommon *common,
                                  const EosActionBuyRamBytes *action);

/// \returns true iff successful.
bool eos_compileActionSellRam(const EosActionCommon *common,
                              const EosActionSellRam *action);

/// \returns true iff successful.
bool eos_compileActionVoteProducer(const EosActionCommon *common,
                                   const EosActionVoteProducer *action);

/// \returns true iff successful.
bool eos_compileAuthorization(const char *title, const EosAuthorization *auth,
                              SLIP48Role role);

/// \returns true iff successful.
bool eos_compileActionUpdateAuth(const EosActionCommon *common,
                                 const EosActionUpdateAuth *action);

/// \returns true iff successful.
bool eos_compileActionDeleteAuth(const EosActionCommon *common,
                                 const EosActionDeleteAuth *action);

/// \returns true iff successful.
bool eos_compileActionLinkAuth(const EosActionCommon *common,
                               const EosActionLinkAuth *action);

/// \returns true iff successful.
bool eos_compileActionUnlinkAuth(const EosActionCommon *common,
                                 const EosActionUnlinkAuth *action);

/// \returns true iff successful.
bool eos_compileActionNewAccount(const EosActionCommon *common,
                                 const EosActionNewAccount *action);

#endif
