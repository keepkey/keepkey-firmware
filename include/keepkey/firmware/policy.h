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
static const PolicyType policies[] = {
    {true, "ShapeShift", true, true},
    {true, "Pin Caching", true, false},
    {true, "Experimental", true, false},
    {true, "AdvancedMode", true, false},
};

int run_policy_compile_output(const CoinType *coin, const HDNode *root, void *vin, void *vout, bool needs_confirm);

#endif
