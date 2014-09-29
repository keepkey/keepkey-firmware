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
#include <keepkey_board.h>
#include <draw.h>
#include <font.h>
#include <layout.h>
#include <storage.h>
#include <fsm.h>
#include <usb_driver.h>
#include <bip39.h>


static const uint32_t SIDE_PADDING  = 5;
static const uint32_t BAR_PADDING   = 5;
static const uint32_t BAR_HEIGHT    = 15;
static const uint8_t BAR_COLOR      = 0xFF;
static const uint32_t ANIMATION_DURATION = 2000;
static bool animation_complete = false;

static void animate_emi_bar(void* data, uint32_t duration, uint32_t elapsed)
{
    Canvas* canvas = display_canvas();

    BoxDrawableParams* box_params = (BoxDrawableParams*)data;

    uint32_t max_width = ( canvas->width - box_params->base.x - SIDE_PADDING );
    box_params->width = ( max_width * ( elapsed ) ) / duration;

    draw_box( canvas, box_params );

    if(elapsed >= duration)
    {
    	animation_complete = true;
    }
}


void add_animation()
{
	const Font *font = get_body_font();

    static const int line = 4; 
    static BoxDrawableParams box_params;
    box_params.base.y        =  line * font_height(font);
    box_params.base.x        = SIDE_PADDING;
    box_params.width         = 0;
    box_params.height        = BAR_HEIGHT;
    box_params.base.color    = BAR_COLOR;

    animation_complete = false;
    layout_add_animation( 
            &animate_emi_bar,
            (void*)&box_params,
            ANIMATION_DURATION);


}

static void exec(unsigned int reset_count)
{
    usb_poll();
    animate();
    display_refresh();

    if(animation_complete)
    {
    	layout_clear();
    	animation_complete = false;
        char* mnemonic = mnemonic_generate(128);
        mnemonic[40] = '\0';
        layout_line(0, 0xff, "EMI test: Mnemonic Generation       %d", reset_count); 
        layout_line(1, 0xd0, mnemonic);

        add_animation();

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

    add_animation();

    while(1)
    {
        exec(count);
    }

    return 0;
}
