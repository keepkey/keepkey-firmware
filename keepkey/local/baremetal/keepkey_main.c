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

#include <keepkey_board.h>
#include <layout.h>
#include <fsm.h>
#include <usb_driver.h>
#include <resources.h>
#include <storage.h>
#include <keepkey_usart.h>
#include <home_sm.h>


/*
 * void exec() -  Main loop
 *
 * INPUT - none
 * OUTPUT - none
 */
static void exec(void)
{
    usb_poll();
    display_refresh();
}

/*
 * main() - Application main entry
 *
 * INPUT - none
 * OUTPUT - none
 */
int main(void)
{
	/* Init board */
    board_init();
    led_func(SET_RED_LED);
    dbg_print("Application Version %d.%d\n\r", MAJOR_VERSION, MINOR_VERSION );

    /* Show home screen */
    go_home();

    /* Init storage and set progress handler */
    storage_init();
    storage_set_progress_handler(&animating_progress_slowed_handler);

    /* Init protcol buffer message map and usb msg callback */
    fsm_init();

    led_func(SET_GREEN_LED);
    usb_init();
    led_func(CLR_RED_LED);

    /* Monitor host usb commands */
    while(1) {
        exec();
    }
    return 0;
}
