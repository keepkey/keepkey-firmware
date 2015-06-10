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

#include <keepkey_board.h>
#include <keepkey_display.h>
#include <layout.h>
#include <usb_driver.h>

#include "storage.h"

/* === Typedefs ============================================================ */

typedef bool (*test_function_t)(void);

/* === Private Functions =================================================== */

/* --- Test Functions ------------------------------------------------------ */

/*
 * test_usb() - Tests the status of USB initialization
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
static bool test_usb(void)
{
    return usb_init();
}

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
    uint32_t i = 0;
    bool ret_stat = true;
    test_function_t tests[] = {&test_usb};
    Canvas *canvas;

    board_init();
    led_func(SET_RED_LED);

    storage_init();

    for(; i < sizeof(tests) / sizeof(test_function_t); i++)
    {
        ret_stat = ret_stat && *tests[i];
    }

    if(ret_stat)
    {
        /* Tests were successful, so draw a white box so we can catch dead pixels */
        canvas = display_canvas();
        draw_box_simple(canvas, 0xFF, 1, 1, canvas->width, canvas->height);
        display_refresh();
    }

    return(0);
}