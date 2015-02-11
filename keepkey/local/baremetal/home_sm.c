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

/*
 * @brief home screen state machine
 */

#include "home_sm.h"

#include "layout.h"

/*******************  variables *************************************/
/* track state of home screen */
static HomeState home_state = AWAY_FROM_HOME;

/*******************FUNCTION Definitions  ****************************/

/*
 * go_home() - returns to home screen
 *
 * INPUT  - 
 *      none
 * OUTPUT - 
 *      none
 */
void go_home()
{
	switch(home_state) {
		case AWAY_FROM_HOME:
		case SCREENSAVER:
			layout_home();
			home_state = AT_HOME;
			break;
		case AT_HOME:
		default:
			/* no action requires */
			break;
	}
}

/*
 * leave_home() - leaves home screen
 *
 * INPUT  -
 *      none
 * OUTPUT - 
 *      none
 */
void leave_home()
{
	switch(home_state) {
		case AT_HOME:
		case SCREENSAVER:
			layout_home_reversed();
			home_state = AWAY_FROM_HOME;
			break;
		case AWAY_FROM_HOME:
		default:
			/* no action requires */
			break;
	}
}
