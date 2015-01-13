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

#ifndef canvas_H
#define canvas_H

#ifdef __cplusplus
extern "C" {
#endif


//=============================== INCLUDES ====================================


#include <stdint.h>
#include <stdbool.h>


//====================== CONSTANTS, TYPES, AND MACROS =========================


typedef struct
{
	uint8_t* 	buffer;
	int 		height;
	int 		width;
	bool 		dirty;
} Canvas;


//=============================== VARIABLES ===================================


//=============================== FUNCTIONS ===================================


#ifdef __cplusplus
}
#endif

#endif // canvas_H

