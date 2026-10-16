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

#include "keepkey/board/timer.h"

#include <stdbool.h>
#include <stdint.h>

/* State for Home SM */
typedef enum { AT_HOME, AWAY_FROM_HOME, SCREENSAVER } HomeState;

void layoutHome(void);
void layoutHomeForced(void);
void leave_home(void);
void toggle_screensaver(void);
/* Monotonic ms clock behind auto-lock; getSysTime() outside unit tests. */
uint32_t home_clock_ms(void);
/* Test hook: charge simulated idle time. Production uses the clock only. */
void increment_idle_time(uint32_t increment_ms);
void reset_idle_time(void);
/* Call only after validated workflow progress, never on raw host traffic.
 * Defers the auto-lock while that workflow runs; never renews it. */
void note_workflow_progress(void);
/* Forget recorded progress once no workflow runs (after an abort or end). */
void drop_workflow_progress_if_idle(void);
/* Lock now (abort workflows, clear the PIN) if the idle deadline has passed
 * and no progressing workflow defers it. True if this call locked. */
bool auto_lock_if_due(void);
HomeState home_get_state(void);

#endif
