/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include "protect.h"
#include "messages.h"
#include "util.h"
#include "debug.h"

bool protectButton(ButtonRequestType type, bool confirm_only)
{
    return true;
}

const char *requestPin(PinMatrixRequestType type, const char *text)
{
    return NULL;
}

bool protectPin(bool use_cached)
{
    return true;
}

bool protectChangePin(void)
{
    return true;
}

bool protectPassphrase(void)
{
    return true;
}
