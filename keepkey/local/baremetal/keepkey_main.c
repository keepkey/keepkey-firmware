/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include <keepkey_board.h>
#include <layout.h>
#include <fsm.h>
#include <usb_driver.h>
#include <resources.h>
#include <storage.h>
#include <keepkey_usart.h>

static void exec(void)
{
    usb_poll();
    display_refresh();
}

int main(void)
{
	/*
	 * Init board
	 */
    board_init();
    set_red();
    dbg_print("Application Version %d.%d\n\r", MAJOR_VERSION, MINOR_VERSION );

    /*
     * Show loading screen
     */
    layout_intro();

    /*
     * Init storage
     */
    storage_init();

    /*
     * Init protcol buffer message map
     */
    fsm_init();

    /*
     * Listen for commands
     */
    set_green();
    usb_init();
    clear_red();
    while(1)
    {
        exec();
    }

    return 0;
}
