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

/***** This file is use for EMI emission test *****/

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
#include <home_sm.h>

/*
 * exec() - exercise CPU processing cycle using mnemonic_generate() function to keep
 *      the CPU active for EMI testing
 *
 * INPUT - 
 *      reset_count - # of counts
 * OUTPUT - 
 *      none
 */
static void exec(uint32_t reset_count)
{
    usb_poll();
    animate();
    display_refresh();

    if(!is_animating())
    {
    	delay_ms(1000);
    	layout_clear();
        const char* mnemonic = mnemonic_generate(128);
        char title[MEDIUM_STR_BUF];

        /* snprintf: 32 + 10 (%u) + 1 (NULL) = 43 */
        snprintf(title, MEDIUM_STR_BUF, "EMI test: Mnemonic Generation [%u]", reset_count);
        layout_standard_notification(title, mnemonic, NOTIFICATION_CONFIRM_ANIMATION);

        usb_poll();
        display_refresh();
    }

}

/*
 *  update_reset_count() - reset counter
 *
 *  INPUT - none
 *  OUTPUT - none
 */
void update_reset_count(uint32_t count)
{
    char temp[SMALL_STR_BUF];

    /* snprintf: 10 (%u) + 1 (NULL) = 11 */
    snprintf(temp, SMALL_STR_BUF, "%u", count);
    
    storage_setLabel(temp);
    storage_commit();
}

/*
 * main() - main application entry poing
 *
 * INPUT - none
 * OUTPUT -none
 */
int main(void)
{
    const char *label;
    uint32_t count;

    board_init();
    led_func(SET_RED_LED);

    /* Show home screen */
    go_home();

	while(is_animating()){
		animate();
		display_refresh();
	}

    storage_init();

    /* Override label to have a reset counter. */
    label = storage_get_label();
    count = 1;
    if(label) {
        count = (uint32_t) strtol(label, NULL, 10);
    }

    count++;
    update_reset_count(count);

    led_func(SET_GREEN_LED);
    usb_init();
    led_func(CLR_RED_LED);

    while(1) {
        exec(count);
    }

    return(0);
}
