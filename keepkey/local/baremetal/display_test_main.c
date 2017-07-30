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

/* === Includes ============================================================ */

#include <stdbool.h>
#include <stdint.h>

#include <libopencm3/cm3/cortex.h>

#include <keepkey_board.h>
#include <draw.h>
#include <layout.h>
#include <rng.h>

#include "app_layout.h"

/* === Functions =========================================================== */

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
    uint8_t color, x, y, width, height;
    
    /* Init board */
    board_init();
    led_func(SET_RED_LED);

    for (;;) {
        /* Draw box to consume screen with pixels */
        color = random32() % 192 + 64;
        x = random32() % 256;
        y = random32() % 64;
        width = random32() % (256 - x);
        height = random32() % (64 - y);
        draw_box_simple(layout_get_canvas(), color, x+1, y+1, width, height);
        display_refresh();
        if (! suspend_s(1) )
	{
	    board_reset();
	}
    }


    return(0);
}
