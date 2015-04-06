/* START KEEPKEY LICENSE */
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
 *
 */
/* END KEEPKEY LICENSE */

/*
 * @brief Recovery cypher.
 */

#ifndef __RECOVERY_CYPHER_H__
#define __RECOVERY_CYPHER_H__

#include <stdint.h>
#include <stdbool.h>

void recovery_cypher_init(bool passphrase_protection, bool pin_protection, const char *language,
    const char *label, bool _enforce_wordlist);
void next_character(void);
void recovery_character(const char *character);
void recovery_delete_character(void);
void recovery_final_character(void);
bool recovery_cypher_abort(void);
const char *recovery_get_cypher(void);

#endif
