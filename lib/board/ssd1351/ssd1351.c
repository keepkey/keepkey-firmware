#include <stddef.h>

#ifndef EMULATOR
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/spi.h>
#endif

#include "keepkey/board/ssd1351/ssd1351.h"
#include "keepkey/board/pin.h"
#include "keepkey/board/timer.h"


static void SSD1351_Select(void) {
  CLEAR_PIN(SSD1351_CS_Pin);
}

void SSD1351_Unselect(void) {
  SET_PIN(SSD1351_CS_Pin);
}


// All displays are reset with the same pin at the same time in display_reset(void)
// static void SSD1351_Reset(void) {
//   SET_PIN(SSD1351_RES_Pin);
//   delay_ms(1);
//   CLEAR_PIN(SSD1351_RES_Pin);
//   delay_ms(1);
//   SET_PIN(SSD1351_RES_Pin);
//   delay_ms(1);
// }

static void SSD1351_WriteCommand(uint8_t cmd) {
#ifndef EMULATOR

  /* Set nDC low */
  CLEAR_PIN(SSD1351_DC_Pin);  // low for cmd

  spi_send(SSD1351_SPI_PORT, (uint16_t)cmd);
  delay_us(10);   // apparently spi_send doesn't wait for buffer to finish as it should
#endif
}

static void SSD1351_WriteData(uint8_t* buff, size_t buff_size) {
  size_t bctr = 0;
  SET_PIN(SSD1351_DC_Pin);  // hi for data

  while(bctr < buff_size) {
    spi_send(SSD1351_SPI_PORT, (uint16_t)buff[bctr]);
    delay_us(10);
    bctr++;
  }

}

static void SSD1351_SetAddressWindow(uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1) {
    // column address set
    SSD1351_WriteCommand(0x15); // SETCOLUMN
    {
        uint8_t data[] = { x0 & 0xFF, x1 & 0xFF };
        SSD1351_WriteData(data, sizeof(data));
    }

    // row address set
    SSD1351_WriteCommand(0x75); // SETROW
    {
        uint8_t data[] = { y0 & 0xFF, y1 & 0xFF };
        SSD1351_WriteData(data, sizeof(data));
    }

    // write to RAM
    SSD1351_WriteCommand(0x5C); // WRITERAM
}

void SSD1351_CSInit(void) {
  // set up chip select pin
  gpio_mode_setup(GPIOC, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE,
    GPIO4);

  gpio_set_output_options(GPIOC, GPIO_OTYPE_PP, GPIO_OSPEED_100MHZ,
    GPIO4);
  return;
}

void SSD1351_Init() {

    SET_PIN(SSD1351_DC_Pin);
    SSD1351_Select();

    // command list is based on https://github.com/adafruit/Adafruit-SSD1351-library

    SSD1351_WriteCommand(0xFD); // COMMANDLOCK
    {
        uint8_t data[] = { 0x12 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xFD); // COMMANDLOCK
    {
        uint8_t data[] = { 0xB1 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xAE); // DISPLAYOFF

    // SSD1351_WriteCommand(0xB2); // DISPLAY ENHANCEMENT
    // {
    //   uint8_t data[] = { 0XA4, 0X00, 0X00 }; // 127
    //   SSD1351_WriteData(data, sizeof(data));  
    // }

    SSD1351_WriteCommand(0xB3); // CLOCKDIV
    {
      uint8_t data[] = { 0xF1 };// 7:4 = Oscillator Frequency, 3:0 = CLK Div Ratio (A[3:0]+1 = 1..16)
      SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xCA); // MUXRATIO
    {
      uint8_t data[] = { 0x7F };
      SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xA0); // SETREMAP
    {
        uint8_t data[] = { 0x26 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0x15); // column
    {
        uint8_t data[] = { 0x00, 0x7F };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0x75); // row
    {
        uint8_t data[] = { 0x00, 0x7F };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xA1); // startline
    {
        uint8_t data[] = { 0x00 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xA2); // DISPLAYOFFSET
    {
        uint8_t data[] = { 0x00 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xB5); // SETGPIO
    {
        uint8_t data[] = { 0x00 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xAB); // FUNCTIONSELECT
    {
        uint8_t data[] = { 0x01 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xB1); // PRECHARGE
    {
        uint8_t data[] = { 0x32 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xBE); // VCOMH
    {
        uint8_t data[] = { 0x05 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xA6); // NORMALDISPLAY (don't invert)
    SSD1351_WriteCommand(0xC1); // CONTRASTABC
    {
        uint8_t data[] = { 0xC8, 0x80, 0xC8 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xC7); // CONTRASTMASTER
    {
        uint8_t data[] = { 0x0F };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xB4); // SETVSL
    {
        uint8_t data[] = { 0xA0, 0xB5, 0x55 };
        SSD1351_WriteData(data, sizeof(data));
    }
    SSD1351_WriteCommand(0xB6); // PRECHARGE2
    {
        uint8_t data[] = { 0x01 };
        SSD1351_WriteData(data, sizeof(data));
    }

    SSD1351_WriteCommand(0xAF); // DISPLAYON
    SSD1351_Unselect();
}

void SSD1351_DrawPixel(uint16_t x, uint16_t y, uint16_t color) {
    if((x >= SSD1351_WIDTH) || (y >= SSD1351_HEIGHT))
        return;
    SSD1351_Select();
    SSD1351_SetAddressWindow(x, y, x+1, y+1);
    uint8_t data[] = { color >> 8, color & 0xFF };
    SSD1351_WriteData(data, sizeof(data));
    SSD1351_Unselect();
}

static void SSD1351_WriteChar(uint16_t x, uint16_t y, char ch, FontDef font, uint16_t color, uint16_t bgcolor) {
    uint32_t i, b, j;

    SSD1351_SetAddressWindow(x, y, x+font.width-1, y+font.height-1);

    for(i = 0; i < font.height; i++) {
        b = font.data[(ch - 32) * font.height + i];
        for(j = 0; j < font.width; j++) {
            if((b << j) & 0x8000)  {
                uint8_t data[] = { color >> 8, color & 0xFF };
                SSD1351_WriteData(data, sizeof(data));
            } else {
                uint8_t data[] = { bgcolor >> 8, bgcolor & 0xFF };
                SSD1351_WriteData(data, sizeof(data));
            }
        }
    }
}

void SSD1351_WriteString(uint16_t x, uint16_t y, const char* str, FontDef font, uint16_t color, uint16_t bgcolor) {
  SSD1351_Select();

    while(*str) {
        if(x + font.width >= SSD1351_WIDTH) {
            x = 0;
            y += font.height;
            if(y + font.height >= SSD1351_HEIGHT) {
                break;
            }

            if(*str == ' ') {
                // skip spaces in the beginning of the new line
                str++;
                continue;
            }
        }

        SSD1351_WriteChar(x, y, *str, font, color, bgcolor);
        x += font.width;
        str++;
    }
    SSD1351_Unselect();
}

void SSD1351_FillRectangle(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color) {
    // clipping
    if((x >= SSD1351_WIDTH) || (y >= SSD1351_HEIGHT)) return;
    if((x + w - 1) >= SSD1351_WIDTH) w = SSD1351_WIDTH - x;
    if((y + h - 1) >= SSD1351_HEIGHT) h = SSD1351_HEIGHT - y;

    SSD1351_Select();
    SSD1351_SetAddressWindow(x, y, x+w-1, y+h-1);

    uint8_t data[] = { color >> 8, color & 0xFF };
    SET_PIN(SSD1351_DC_Pin);
    for(y = h; y > 0; y--) {
        for(x = w; x > 0; x--) {
            SSD1351_WriteData(data, sizeof(data));
        }
    }
    SSD1351_Unselect();
}

void SSD1351_FillScreen(uint16_t color) {
    SSD1351_FillRectangle(0, 0, SSD1351_WIDTH, SSD1351_HEIGHT, color);
}

void SSD1351_DrawImage(uint16_t x, uint16_t y, uint16_t w, uint16_t h, const uint16_t* data) {
    if((x >= SSD1351_WIDTH) || (y >= SSD1351_HEIGHT)) return;
    if((x + w - 1) >= SSD1351_WIDTH) return;
    if((y + h - 1) >= SSD1351_HEIGHT) return;


    SSD1351_Select();
    SSD1351_SetAddressWindow(x, y, x+w-1, y+h-1);
    SSD1351_WriteData((uint8_t*)data, sizeof(uint16_t)*w*h);
    SSD1351_Unselect();

}

void SSD1351_InvertColors(bool invert) {
    SSD1351_Select();
    SSD1351_WriteCommand(invert ? 0xA7 /* INVERTDISPLAY */ : 0xA6 /* NORMALDISPLAY */);
    SSD1351_Unselect();

}

void SSD1351_SetRotation(uint8_t r) {
  // madctl bits:
  // 6,7 Color depth (01 = 64K)
  // 5   Odd/even split COM (0: disable, 1: enable)
  // 4   Scan direction (0: top-down, 1: bottom-up)
  // 3   Reserved
  // 2   Color remap (0: A->B->C, 1: C->B->A)
  // 1   Column remap (0: 0-127, 1: 127-0)
  // 0   Address increment (0: horizontal, 1: vertical)
  uint8_t madctl = 0b01100100; // 64K, enable split, CBA

  uint8_t rotation = r & 3; // Clip input to valid range

  switch (rotation) {
  case 0:
    madctl |= 0b00010000; // Scan bottom-up
    break;
  case 1:
    madctl |= 0b00010011; // Scan bottom-up, column remap 127-0, vertical
    break;
  case 2:
    madctl |= 0b00000010; // Column remap 127-0
    break;
  case 3:
    madctl |= 0b00000001; // Vertical

    break;
  }

  SSD1351_WriteCommand(0xA0); // SETREMAP
  {
      uint8_t data[] = { madctl };
      SSD1351_WriteData(data, sizeof(data));
  }

  uint8_t startline = (rotation < 2) ? SSD1351_HEIGHT : 0;
  SSD1351_WriteCommand(0xA1); // STARTLINE
  {
      uint8_t data[] = { startline };
      SSD1351_WriteData(data, sizeof(data));
  }
}
