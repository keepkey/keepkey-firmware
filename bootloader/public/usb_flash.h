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

#ifndef USB_FLASH_H
#define USB_FLASH_H

#include <stdbool.h>
#include <stdint.h>

#define UPLOAD_STATUS_FREQUENCY		1024
#define PROTOBUF_FIRMWARE_PADDING	4

bool usb_flash_firmware();
void storage_part_sav(ConfigFlash *cfg_ptr);
void storage_part_restore(ConfigFlash *cfg_ptr);

#endif
