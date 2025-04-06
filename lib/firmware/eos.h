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

#ifndef LIB_FIRMWARE_EOS_H
#define LIB_FIRMWARE_EOS_H

#include "hwcrypto/crypto/hasher.h"

#define CHECK_PARAM_RET(cond, errormsg, retval)             \
  if (!(cond)) {                                            \
    fsm_sendFailure(FailureType_Failure_Other, (errormsg)); \
    layoutHome();                                           \
    return retval;                                          \
  }

extern CONFIDENTIAL Hasher hasher_preimage;

#endif
