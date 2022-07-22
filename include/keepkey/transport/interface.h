/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 KeepKey LLC
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

#ifndef INTERFACE_H
#define INTERFACE_H

// Allow this file to be used from C++ by renaming an unfortunately named field:
#define delete del
#include "messages.pb.h"
#include "messages-nano.pb.h"
#undef delete

#include "messages-ethereum.pb.h"
#include "messages-binance.pb.h"
#include "messages-cosmos.pb.h"
#include "messages-eos.pb.h"
#include "messages-ripple.pb.h"
#include "messages-tendermint.pb.h"
#include "messages-thorchain.pb.h"

#include "types.pb.h"
#include "trezor_transport.h"

#ifndef EMULATOR
/* The max size of a decoded protobuf */
#define MAX_DECODE_SIZE (13 * 1024)
#else
#define MAX_DECODE_SIZE (26 * 1024)
#endif

#endif
