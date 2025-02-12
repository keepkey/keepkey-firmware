/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 markrypto
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

#ifndef KEEPKEY_VARIANT_KEEPKEY_H
#define KEEPKEY_VARIANT_KEEPKEY_H

#include "keepkey/board/variant.h"

#ifdef BITCOIN_ONLY
// use the bitcoin-only logo
#define VARIANTINFO_KEEPKEY                         \
.version = 1, .name = "KeepKeyBTC", .logo = &kkbtc_logo, \
.logo_reversed = &kkbtc_logo_reversed,                \
.screensaver_timeout = ONE_SEC * 60 * 10, .screensaver = &kkbtc_screensaver,

extern const VariantInfo variant_keepkey;
extern const VariantAnimation kkbtc_logo;
extern const VariantAnimation kkbtc_logo_reversed;
extern const VariantAnimation kkbtc_screensaver;

#else

#define VARIANTINFO_KEEPKEY                         \
.version = 1, .name = "KeepKey", .logo = &kk_logo, \
.logo_reversed = &kk_logo_reversed,                \
.screensaver_timeout = ONE_SEC * 60 * 10, .screensaver = &kk_screensaver,

extern const VariantInfo variant_keepkey;
extern const VariantAnimation kk_logo;
extern const VariantAnimation kk_logo_reversed;
extern const VariantAnimation kk_screensaver;

#endif // BITCOIN_ONLY

#endif