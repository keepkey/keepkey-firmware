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

#include <stdio.h>
#include <stdlib.h>
#include <keepkey_board.h>
#include <draw.h>
#include <font.h>
#include <layout.h>
#include <storage.h>
#include <fsm.h>
#include <usb_driver.h>
#include <bip39.h>

static void exec(unsigned int reset_count)
{
    usb_poll();
    animate();
    display_refresh();

    if(!is_animating())
    {
    	delay(1000);
    	layout_clear();
        const char* mnemonic = mnemonic_generate(128);
        char title[50];
        sprintf(title, "EMI test: Mnemonic Generation     %d", reset_count);
        layout_standard_notification(title, mnemonic, NOTIFICATION_CONFIRM_ANIMATION);

        usb_poll();
        display_refresh();
    }

}

void update_reset_count(unsigned int count)
{
    char temp[20];
    sprintf(temp, "%d", count);
    storage_setLabel(temp);
    storage_commit();
}

int main(void)
{
    board_init();
    set_red();

    /*
     * Show loading screen
     */
    layout_intro();

	while(is_animating()){
		animate();
		display_refresh();
	}

    storage_init();

    // Override label to have a reset counter. 
    const char* label = storage_getLabel();
    unsigned long count = 1;
    if(label)
    {
        count = strtoul(label, NULL, 10);
    }

    count++;
    update_reset_count(count);

    layout_home();
    display_refresh();

    set_green();
    usb_init();
    clear_red();

    while(1)
    {
        exec(count);
    }

    return 0;
}
