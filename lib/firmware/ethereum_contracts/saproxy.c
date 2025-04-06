/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 ShapeShift
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

#include "keepkey/firmware/ethereum_contracts/saproxy.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "hwcrypto/crypto/address.h"

static bool isWithFromSalary(const EthereumSignTx *msg) {
    if (memcmp(msg->data_initial_chunk.bytes, "\xfe\xa7\xc5\x3f", 4) == 0)
        return true;

    return false;
}

bool sa_isWithdrawFromSalary(const EthereumSignTx *msg) {

    if (memcmp(msg->to.bytes, SAPROXY_ADDRESS, 20) == 0) {   // correct proxy address?
        if (isWithFromSalary(msg)) {                     // does kk handle call?
            return true;
        }
    }
    return false;
}

bool sa_confirmWithdrawFromSalary(uint32_t data_total, const EthereumSignTx *msg) {
    (void)data_total;
    char confStr[41];
    bignum256 salaryId, withdrawAmount;

    bn_from_bytes(msg->data_initial_chunk.bytes + 4, 32, &salaryId);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 1*32, 32, &withdrawAmount);

    // confirm raw unformatted numbers
    bn_format(&salaryId, NULL, "", 0, 0, false, confStr, sizeof(confStr));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
             "Sablier", "Salary ID %s", confStr)) {
        return false;
    }

    // confirm raw unformatted numbers
    bn_format(&withdrawAmount, NULL, " Token Units", 0, 0, false, confStr, sizeof(confStr));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
             "Sablier", "Withdraw Amount %s", confStr)) {
        return false;
    }
    return true;
}
