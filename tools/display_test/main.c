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


#include <stdbool.h>
#include <stdint.h>

#ifndef EMULATOR
#  include <libopencm3/cm3/cortex.h>
#endif

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/draw.h"
#include "keepkey/board/layout.h"

#include "keepkey/firmware/app_layout.h"


void mmhisr(void);


/*
 * main() - Application main entry
 *
 * INPUT
 *     none
 * OUTPUT
 *     0 when complete
 */
int main(void)
{
    _buttonusr_isr = (void *)&buttonisr_usr;
    _timerusr_isr = (void *)&timerisr_usr;
    _mmhusr_isr = (void *)&mmhisr;

    /* Init board */
    kk_board_init();

    led_func(SET_RED_LED);

    /* Draw box to consume screen with pixels */
    layout_screen_test();
    display_refresh();

    for(;;);  /* Loops forever */

    return(0);
}
