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

#ifndef HOME_SM_H
#define HOME_SM_H

/* === Includes ============================================================ */

#include <stdint.h>

#include <timer.h>

/* === Defines ============================================================= */
 
#define SCREENSAVER_TIMEOUT ONE_SEC * 60 * 10

/* === Typedefs ============================================================ */

/* State for Home SM */
typedef enum {
    AT_HOME,
	AWAY_FROM_HOME,
	SCREENSAVER
} HomeState;
 
/* === Functions =========================================================== */

void go_home(void);
void go_home_forced(void);
void leave_home(void);
void toggle_screensaver(void);
void increment_idle_time(uint32_t increment_ms);
void reset_idle_time(void);

#endif
