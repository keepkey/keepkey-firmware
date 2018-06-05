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
 */

/* === Includes ============================================================ */

#include "keepkey/board/resources.h"

#include <string.h>

//============================= LOGO ANIMATION ================================

static const uint8_t salt_logo_1_data[526] =
{
    0x7f, 0x00, 0x7f, 0x00, 0x7f, 0x00, 0x7f, 0x00, 0x7f, 0x00, 0x7f, 0x00, 0x63, 0x00, 0x08, 0xff, 0x23, 0x00, 0xff, 0xff, 0x20, 0x00, 0x03, 0xff, 0x1b, 0x00, 0x13, 0xff, 0x0f, 0x00, 0x0c, 0xff, 0x21, 0x00, 0xff, 0xff, 0x20, 0x00, 0x03, 0xff, 0x1b, 0x00, 0x13, 0xff, 0x0e, 0x00, 0x0f, 0xff, 0x1e, 0x00, 0x03, 0xff, 0x1f, 0x00, 0x03, 0xff, 0x1b, 0x00, 0x13, 0xff, 0x0d, 0x00, 0x05, 0xff, 0x06, 0x00, 0x06, 0xff, 0x1d, 0x00, 0x03, 0xff, 0x1f, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x14, 0x00, 0x04, 0xff, 0x0b, 0x00, 0x03, 0xff, 0x1c, 0x00, 0x05, 0xff, 0x1e, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x14, 0x00, 0x03, 0xff, 0x0d, 0x00, 0xff, 0xff, 0x1d, 0x00, 0x05, 0xff, 0x1e, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x14, 0x00, 0x03, 0xff, 0x2a, 0x00, 0x07, 0xff, 0x1d, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x14, 0x00, 0x03, 0xff, 0x2a, 0x00, 0x03, 0xff, 0xff, 0x00, 0x03, 0xff, 0x1d, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x14, 0x00, 0x04, 0xff, 0x28, 0x00, 0x04, 0xff, 0xff, 0x00, 0x04, 0xff, 0x1c, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x14, 0x00, 0x04, 0xff, 0x28, 0x00, 0x03, 0xff, 0x03, 0x00, 0x03, 0xff, 0x1c, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x15, 0x00, 0x07, 0xff, 0x23, 0x00, 0x04, 0xff, 0x03, 0x00, 0x04, 0xff, 0x1b, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x16, 0x00, 0x0a, 0xff, 0x1f, 0x00, 0x03, 0xff, 0x05, 0x00, 0x03, 0xff, 0x1b, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x17, 0x00, 0x0c, 0xff, 0x1b, 0x00, 0x04, 0xff, 0x05, 0x00, 0x04, 0xff, 0x1a, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x1a, 0x00, 0x0a, 0xff, 0x1a, 0x00, 0x03, 0xff, 0x07, 0x00, 0x03, 0xff, 0x1a, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x1e, 0x00, 0x07, 0xff, 0x18, 0x00, 0x04, 0xff, 0x07, 0x00, 0x04, 0xff, 0x19, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x21, 0x00, 0x05, 0xff, 0x17, 0x00, 0x03, 0xff, 0x09, 0x00, 0x03, 0xff, 0x19, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x22, 0x00, 0x04, 0xff, 0x16, 0x00, 0x04, 0xff, 0x09, 0x00, 0x04, 0xff, 0x18, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x23, 0x00, 0x04, 0xff, 0x15, 0x00, 0x03, 0xff, 0x0b, 0x00, 0x03, 0xff, 0x18, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x23, 0x00, 0x04, 0xff, 0x14, 0x00, 0x04, 0xff, 0x0b, 0x00, 0x04, 0xff, 0x17, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x23, 0x00, 0x04, 0xff, 0x14, 0x00, 0x03, 0xff, 0x0d, 0x00, 0x03, 0xff, 0x17, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x15, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x04, 0xff, 0x13, 0x00, 0x04, 0xff, 0x0d, 0x00, 0x04, 0xff, 0x16, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x14, 0x00, 0x03, 0xff, 0x0b, 0x00, 0x04, 0xff, 0x14, 0x00, 0x03, 0xff, 0x0f, 0x00, 0x03, 0xff, 0x16, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x14, 0x00, 0x05, 0xff, 0x08, 0x00, 0x05, 0xff, 0x13, 0x00, 0x04, 0xff, 0x0f, 0x00, 0x04, 0xff, 0x15, 0x00, 0x03, 0xff, 0x23, 0x00, 0x03, 0xff, 0x15, 0x00, 0x10, 0xff, 0x14, 0x00, 0x17, 0xff, 0x15, 0x00, 0x0f, 0xff, 0x17, 0x00, 0x03, 0xff, 0x16, 0x00, 0x0e, 0xff, 0x14, 0x00, 0x19, 0xff, 0x14, 0x00, 0x0f, 0xff, 0x17, 0x00, 0x03, 0xff, 0x19, 0x00, 0x08, 0xff, 0x17, 0x00, 0x19, 0xff, 0x14, 0x00, 0x0f, 0xff, 0x17, 0x00, 0x03, 0xff, 0x7f, 0x00, 0x7f, 0x00, 0x7f, 0x00, 0x7f, 0x00, 0x4c, 0x00
};
static const VariantImage salt_logo_1_image = {142, 36, 526, salt_logo_1_data};

const VariantAnimation salt_logo = {
    21, 
    {
        {62, 10, 25, 0, &salt_logo_1_image},
        {62, 10, 25, 5, &salt_logo_1_image},
        {62, 10, 25, 10, &salt_logo_1_image},
        {62, 10, 25, 15, &salt_logo_1_image},
        {62, 10, 25, 20, &salt_logo_1_image},
        {62, 10, 25, 25, &salt_logo_1_image},
        {62, 10, 25, 30, &salt_logo_1_image},
        {62, 10, 25, 35, &salt_logo_1_image},
        {62, 10, 25, 40, &salt_logo_1_image},
        {62, 10, 25, 45, &salt_logo_1_image},
        {62, 10, 25, 50, &salt_logo_1_image},
        {62, 10, 25, 55, &salt_logo_1_image},
        {62, 10, 25, 60, &salt_logo_1_image},
        {62, 10, 25, 65, &salt_logo_1_image},
        {62, 10, 25, 70, &salt_logo_1_image},
        {62, 10, 25, 75, &salt_logo_1_image},
        {62, 10, 25, 80, &salt_logo_1_image},
        {62, 10, 25, 85, &salt_logo_1_image},
        {62, 10, 25, 90, &salt_logo_1_image},
        {62, 10, 25, 95, &salt_logo_1_image},
        {62, 10, 25, 100, &salt_logo_1_image},
    }
};
const VariantAnimation salt_logo_reversed = {
    21, 
    {
        {62, 10, 25, 100, &salt_logo_1_image},
        {62, 10, 25, 95, &salt_logo_1_image},
        {62, 10, 25, 90, &salt_logo_1_image},
        {62, 10, 25, 85, &salt_logo_1_image},
        {62, 10, 25, 80, &salt_logo_1_image},
        {62, 10, 25, 75, &salt_logo_1_image},
        {62, 10, 25, 70, &salt_logo_1_image},
        {62, 10, 25, 65, &salt_logo_1_image},
        {62, 10, 25, 60, &salt_logo_1_image},
        {62, 10, 25, 55, &salt_logo_1_image},
        {62, 10, 25, 50, &salt_logo_1_image},
        {62, 10, 25, 45, &salt_logo_1_image},
        {62, 10, 25, 40, &salt_logo_1_image},
        {62, 10, 25, 35, &salt_logo_1_image},
        {62, 10, 25, 30, &salt_logo_1_image},
        {62, 10, 25, 25, &salt_logo_1_image},
        {62, 10, 25, 20, &salt_logo_1_image},
        {62, 10, 25, 15, &salt_logo_1_image},
        {62, 10, 25, 10, &salt_logo_1_image},
        {62, 10, 25, 5, &salt_logo_1_image},
        {62, 10, 25, 0, &salt_logo_1_image}
    }
};

const VariantAnimation salt_screensaver = {
    113, 
    {
        {0, 10, 150, 60, &salt_logo_1_image},
        {2, 10, 150, 60, &salt_logo_1_image},
        {4, 10, 150, 60, &salt_logo_1_image},
        {6, 10, 150, 60, &salt_logo_1_image},
        {8, 10, 150, 60, &salt_logo_1_image},
        {10, 10, 150, 60, &salt_logo_1_image},
        {12, 10, 150, 60, &salt_logo_1_image},
        {14, 10, 150, 60, &salt_logo_1_image},
        {16, 10, 150, 60, &salt_logo_1_image},
        {18, 10, 150, 60, &salt_logo_1_image},
        {20, 10, 150, 60, &salt_logo_1_image},
        {22, 10, 150, 60, &salt_logo_1_image},
        {24, 10, 150, 60, &salt_logo_1_image},
        {26, 10, 150, 60, &salt_logo_1_image},
        {28, 10, 150, 60, &salt_logo_1_image},
        {30, 10, 150, 60, &salt_logo_1_image},
        {32, 10, 150, 60, &salt_logo_1_image},
        {34, 10, 150, 60, &salt_logo_1_image},
        {36, 10, 150, 60, &salt_logo_1_image},
        {38, 10, 150, 60, &salt_logo_1_image},
        {40, 10, 150, 60, &salt_logo_1_image},
        {42, 10, 150, 60, &salt_logo_1_image},
        {44, 10, 150, 60, &salt_logo_1_image},
        {46, 10, 150, 60, &salt_logo_1_image},
        {48, 10, 150, 60, &salt_logo_1_image},
        {50, 10, 150, 60, &salt_logo_1_image},
        {52, 10, 150, 60, &salt_logo_1_image},
        {54, 10, 150, 60, &salt_logo_1_image},
        {56, 10, 150, 60, &salt_logo_1_image},
        {58, 10, 150, 60, &salt_logo_1_image},
        {60, 10, 150, 60, &salt_logo_1_image},
        {62, 10, 150, 60, &salt_logo_1_image},
        {64, 10, 150, 60, &salt_logo_1_image},
        {66, 10, 150, 60, &salt_logo_1_image},
        {68, 10, 150, 60, &salt_logo_1_image},
        {70, 10, 150, 60, &salt_logo_1_image},
        {72, 10, 150, 60, &salt_logo_1_image},
        {74, 10, 150, 60, &salt_logo_1_image},
        {76, 10, 150, 60, &salt_logo_1_image},
        {78, 10, 150, 60, &salt_logo_1_image},
        {80, 10, 150, 60, &salt_logo_1_image},
        {82, 10, 150, 60, &salt_logo_1_image},
        {84, 10, 150, 60, &salt_logo_1_image},
        {86, 10, 150, 60, &salt_logo_1_image},
        {88, 10, 150, 60, &salt_logo_1_image},
        {90, 10, 150, 60, &salt_logo_1_image},
        {92, 10, 150, 60, &salt_logo_1_image},
        {94, 10, 150, 60, &salt_logo_1_image},
        {96, 10, 150, 60, &salt_logo_1_image},
        {98, 10, 150, 60, &salt_logo_1_image},
        {100, 10, 150, 60, &salt_logo_1_image},
        {102, 10, 150, 60, &salt_logo_1_image},
        {104, 10, 150, 60, &salt_logo_1_image},
        {106, 10, 150, 60, &salt_logo_1_image},
        {108, 10, 150, 60, &salt_logo_1_image},
        {110, 10, 150, 60, &salt_logo_1_image},
        {112, 10, 150, 60, &salt_logo_1_image},
        {112, 10, 150, 60, &salt_logo_1_image},
        {110, 10, 150, 60, &salt_logo_1_image},
        {108, 10, 150, 60, &salt_logo_1_image},
        {106, 10, 150, 60, &salt_logo_1_image},
        {104, 10, 150, 60, &salt_logo_1_image},
        {102, 10, 150, 60, &salt_logo_1_image},
        {100, 10, 150, 60, &salt_logo_1_image},
        {98, 10, 150, 60, &salt_logo_1_image},
        {96, 10, 150, 60, &salt_logo_1_image},
        {94, 10, 150, 60, &salt_logo_1_image},
        {92, 10, 150, 60, &salt_logo_1_image},
        {90, 10, 150, 60, &salt_logo_1_image},
        {88, 10, 150, 60, &salt_logo_1_image},
        {86, 10, 150, 60, &salt_logo_1_image},
        {84, 10, 150, 60, &salt_logo_1_image},
        {82, 10, 150, 60, &salt_logo_1_image},
        {80, 10, 150, 60, &salt_logo_1_image},
        {78, 10, 150, 60, &salt_logo_1_image},
        {76, 10, 150, 60, &salt_logo_1_image},
        {74, 10, 150, 60, &salt_logo_1_image},
        {72, 10, 150, 60, &salt_logo_1_image},
        {70, 10, 150, 60, &salt_logo_1_image},
        {68, 10, 150, 60, &salt_logo_1_image},
        {66, 10, 150, 60, &salt_logo_1_image},
        {64, 10, 150, 60, &salt_logo_1_image},
        {62, 10, 150, 60, &salt_logo_1_image},
        {60, 10, 150, 60, &salt_logo_1_image},
        {58, 10, 150, 60, &salt_logo_1_image},
        {56, 10, 150, 60, &salt_logo_1_image},
        {54, 10, 150, 60, &salt_logo_1_image},
        {52, 10, 150, 60, &salt_logo_1_image},
        {50, 10, 150, 60, &salt_logo_1_image},
        {48, 10, 150, 60, &salt_logo_1_image},
        {46, 10, 150, 60, &salt_logo_1_image},
        {44, 10, 150, 60, &salt_logo_1_image},
        {42, 10, 150, 60, &salt_logo_1_image},
        {40, 10, 150, 60, &salt_logo_1_image},
        {38, 10, 150, 60, &salt_logo_1_image},
        {36, 10, 150, 60, &salt_logo_1_image},
        {34, 10, 150, 60, &salt_logo_1_image},
        {32, 10, 150, 60, &salt_logo_1_image},
        {30, 10, 150, 60, &salt_logo_1_image},
        {28, 10, 150, 60, &salt_logo_1_image},
        {26, 10, 150, 60, &salt_logo_1_image},
        {24, 10, 150, 60, &salt_logo_1_image},
        {22, 10, 150, 60, &salt_logo_1_image},
        {20, 10, 150, 60, &salt_logo_1_image},
        {18, 10, 150, 60, &salt_logo_1_image},
        {16, 10, 150, 60, &salt_logo_1_image},
        {14, 10, 150, 60, &salt_logo_1_image},
        {12, 10, 150, 60, &salt_logo_1_image},
        {10, 10, 150, 60, &salt_logo_1_image},
        {8, 10, 150, 60, &salt_logo_1_image},
        {6, 10, 150, 60, &salt_logo_1_image},
        {4, 10, 150, 60, &salt_logo_1_image},
        {2, 10, 150, 60, &salt_logo_1_image},
        {0, 10, 150, 60, &salt_logo_1_image},
    }
};




