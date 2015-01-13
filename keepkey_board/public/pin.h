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

//============================= CONDITIONALS ==================================


#ifndef pin_H
#define pin_H

#ifdef __cplusplus
extern "C" {
#endif



#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>


/**************** #defines ******************************/
// Set a pin.
#define SET_PIN(p)      GPIO_BSRR( (p).port ) = (p).pin
// Clear a pin
#define CLEAR_PIN(p)    GPIO_BSRR( (p).port ) = ( (p).pin << 16 )
// Toggle a pin
#define TOGGLE_PIN(p)   GPIO_ODR( (p).port ) ^= (p).pin

/***************** Typedefs and enums  *******************/
typedef enum
{
    PUSH_PULL_MODE,
    OPEN_DRAIN_MODE,

    NUM_PIN_MODES
} OutputMode;

typedef enum
{
    PULL_UP_MODE,
    PULL_DOWN_MODE,
    NO_PULL_MODE,

    NUM_PULL_MODES
} PullMode;

typedef struct
{
    uint32_t port;
    uint16_t pin;

} Pin;


/******************** Function Declarations ********************/
void pin_init_output(const Pin *pin, OutputMode output_mode, PullMode pull_mode);


#ifdef __cplusplus
}
#endif

#endif // pin_H

