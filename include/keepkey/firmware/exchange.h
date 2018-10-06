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

#ifndef EXCHANGE_H 
#define  EXCHANGE_H

typedef enum
{
    NO_EXCHANGE_ERROR,
    ERROR_EXCHANGE_SIGNATURE,
    ERROR_EXCHANGE_DEPOSIT_COINTYPE,
    ERROR_EXCHANGE_DEPOSIT_ADDRESS,
    ERROR_EXCHANGE_DEPOSIT_AMOUNT,
    ERROR_EXCHANGE_WITHDRAWAL_COINTYPE,
    ERROR_EXCHANGE_WITHDRAWAL_ADDRESS,
    ERROR_EXCHANGE_WITHDRAWAL_AMOUNT,
    ERROR_EXCHANGE_RETURN_COINTYPE,
    ERROR_EXCHANGE_RETURN_ADDRESS,
    ERROR_EXCHANGE_API_KEY,
    ERROR_EXCHANGE_CANCEL,
    ERROR_EXCHANGE_RESPONSE_STRUCTURE,
}ExchangeError;

bool process_exchange_contract(const CoinType *coin, void *vtx_out, const HDNode *root, bool needs_confirm);
ExchangeError get_exchange_error(void);
void set_exchange_error(ExchangeError error_code);

bool ether_for_display(const uint8_t *value, uint32_t value_len, char *out_str);
/**
 * \brief Format an ethereum token value with the proper number of decimals
 * \param value         The token value interpreted as a 32byte big endian number
 * \param value_len     Length in bytes of value
 * \param decimal       The number of decimals to format this token amount to
 * \param out_str       128 byte buffer to store string result
 * \returns             boolean representing wethere the token value was successfully formatted
 */
bool ether_token_for_display(const uint8_t *value, uint32_t value_len, uint32_t decimal, char *out_str, size_t out_len);

#endif
