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

#ifndef POLICY_H
#define POLICY_H

#include "transaction.h"
#include "coins.h"

#define POLICY_COUNT (sizeof(policies) / sizeof(policies[0]))

// NOTE: when adding policies, *ONLY* add to the end. Otherwise this breaks
// storage_upgradePolicies();
//
// NOTE: storage flags bit 12 is BURNED. It used to persist AdvancedMode, which
// is now session-scoped (never written, never restored -- see storage.c). Do
// not reuse the bit for a new policy or field: firmware at 7.15 and earlier
// reads it as AdvancedMode, so a device downgraded to one of those builds would
// read the new field as "blind signing enabled".
static const PolicyType policies[] = {
    {true, "ShapeShift", true, false},
    {true, "Pin Caching", true, true},
    {true, "Experimental", true, false},
    {true, "AdvancedMode", true, false},
};

int run_policy_compile_output(const CoinType* coin, const HDNode* root,
                              void* vin, void* vout, bool needs_confirm);

#endif
