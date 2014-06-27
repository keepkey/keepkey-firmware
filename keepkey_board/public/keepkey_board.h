/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2014 Carbon Design Group <tom@carbondesign.com>
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

#ifndef KEEPKEY_BOARD_H
#define KEEPKEY_BOARD_H

#include <confirm_sm.h>
#include <keepkey_leds.h>
#include <keepkey_display.h>
#include <keepkey_button.h>
#include <layout.h>
#include <timer.h>
#include <usb_driver.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief miscellaneous board functions    
 */

/**
 * Perform a soft reset of the board.
 */
void board_reset(void);

/*
 * Initial setup and configuration of board.
 */
void board_init(void);

#ifdef __cplusplus
}
#endif

#endif
