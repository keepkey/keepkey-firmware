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

/* === Defines ============================================================= */

#define TEST_COLOR      0xFF
#define TEST_X          1
#define TEST_Y          1
#define TEST_WIDTH      256
#define TEST_HEIGHT     64

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
    /* Init board */
    board_init();
    led_func(SET_RED_LED);

    /* Draw box to consume screen with pixels */
    draw_box_simple(layout_get_canvas(), TEST_COLOR, TEST_X, TEST_Y, TEST_WIDTH, TEST_HEIGHT);
    display_refresh();

    for(;;);  /* Loops forever */

    return(0);
}