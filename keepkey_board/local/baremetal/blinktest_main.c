/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2014 KeepKey LLC
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
//================================ INCLUDES ===================================


#include <stddef.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include "keepkey_display.h"
#include "keepkey_leds.h"
#include "keepkey_button.h"
#include "timer.h"
#include "layout.h"

static void configure_hw(void);

/*
 * blink() - toggl red led 
 *
 * INPUT - 
 *      *context - pointer to arguments 
 * OUTOPUT - 
 *      none
 *
 */
static void blink(void *context )
{
    led_func(TGL_RED_LED);
}

/*
 * blonk() - toggle led green led
 *
 * INPUT - 
 *      *context - pointer to arguments 
 * OUTPUT - 
 *      none
 */
static void blonk(void *context)
{
    led_func(TGL_GREEN_LED);
}

/*
 * main() - main entry to blinky_main application
 *
 * INPUT - none
 * OUTPUT - 0 - dummy return.
 */
int main(void)
{
    configure_hw();
    display_init();
    layout_init( display_canvas() );
    layout_home();
    post_periodic( &blink, NULL, 1000, 1000 );
    post_periodic( &blonk, NULL, 500, 1000 );

    while( 1 )
    {
        if( display_canvas()->dirty )
        {
            display_refresh();
        }

        animate();
    }
    return 0;
}


/*
 * configure_hw() - harware initialization 
 *
 * INPUT - none
 * OUTPUT - none
 */
static void configure_hw(void)
{
    clock_scale_t clock = hse_8mhz_3v3[ CLOCK_3V3_120MHZ ];
    rcc_clock_setup_hse_3v3( &clock );

    // Enable GPIOA/B/C clock.
    rcc_periph_clock_enable( RCC_GPIOA );
    rcc_periph_clock_enable( RCC_GPIOB );
    rcc_periph_clock_enable( RCC_GPIOC );

    // Enable the peripheral clock for the system configuration 
    rcc_peripheral_enable_clock( &RCC_APB2ENR, RCC_APB2ENR_SYSCFGEN );

    // Enable the periph clock for timer 4
    rcc_peripheral_enable_clock( &RCC_APB1ENR, RCC_APB1ENR_TIM4EN );

    timer_init();

    keepkey_leds_init();

    keepkey_button_init();
}


