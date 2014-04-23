/*----------------------------------------------------------------------------
 * Name:    LCD_4bit.c
 * Purpose: Functions for 2 line 16 character Text LCD (4-bit interface)
 *                connected on MCBSTM32 evaluation board 
 * Version: V1.10
 *----------------------------------------------------------------------------
 * This file is part of the uVision/ARM development tools.
 * This software may only be used under the terms of a valid, current,
 * end user licence from KEIL for a compatible version of KEIL software
 * development tools. Nothing else gives you the right to use this software.
 *
 * Copyright (c) 2005-2007 Keil Software. All rights reserved.
 *---------------------------------------------------------------------------*/

#include <stm32f10x_lib.h>              /* STM32F10x Library Definitions      */

/*********************** Hardware specific configuration **********************/

/*------------------------- Speed dependant settings -------------------------*/

/* If processor works on high frequency delay has to be increased, it can be 
   increased by factor 2^N by this constant                                   */
#define DELAY_2N     0

/*------------------------- Text LCD size definitions ------------------------*/

#define LineLen     16                  /* Width (in characters)              */
#define NumLines     2                  /* Hight (in lines)                   */

/*-------------------- LCD interface hardware definitions --------------------*/

/* PINS: 
   - DB4 = PC3
   - DB5 = PC2
   - DB6 = PC1
   - DB7 = PC0
   - E   = PC10
   - RW  = PC11
   - RS  = PC12                                                               */

#define PIN_E                 (   1 << 10)
#define PIN_RW                (   1 << 11)
#define PIN_RS                (   1 << 12)
#define PINS_CTRL             (0x07 << 10)
#define PINS_DATA             (0x0F <<  0)
#define PINS_ALL              (PINS_CTRL | PINS_DATA)

const unsigned int SWAP_DATA[16] = { 0x0, 0x8, 0x4, 0xC, 0x2, 0xA, 0x6, 0xE, 
                                     0x1, 0x9, 0x5, 0xD, 0x3, 0xB, 0x7, 0xF};

/* Enable Clock for peripheral driving LCD pins                               */
#define LCD_CLOCK_EN         (RCC->APB2ENR |= (1 << 4)); // enable clock for GPIOC

/* pin E  setting to 0 or 1                                                   */
#define LCD_E(x)              GPIOC->ODR = (GPIOC->ODR & ~PIN_E)  | (x ? PIN_E : 0);

/* pin RW setting to 0 or 1                                                   */
#define LCD_RW(x)             GPIOC->ODR = (GPIOC->ODR & ~PIN_RW) | (x ? PIN_RW : 0);

/* pin RS setting to 0 or 1                                                   */
#define LCD_RS(x)             GPIOC->ODR = (GPIOC->ODR & ~PIN_RS) | (x ? PIN_RS : 0);

/* Reading DATA pins                                                          */
#define LCD_DATA_IN           SWAP_DATA[(((GPIOC->IDR & PINS_DATA) >> 0) & 0x0F)]

/* Writing value to DATA pins                                                 */
#define LCD_DATA_OUT(x)       GPIOC->ODR = (GPIOC->ODR & ~PINS_DATA) | ((SWAP_DATA[x]) << 0);

/* Setting all pins to output mode                                            */
#define LCD_ALL_DIR_OUT       GPIOC->CRL = (GPIOC->CRL & 0xFFFF0000) | 0x00003333; \
                              GPIOC->CRH = (GPIOC->CRH & 0xFFF000FF) | 0x00033300;
 
/* Setting DATA pins to input mode                                            */
#define LCD_DATA_DIR_IN       GPIOC->CRL = (GPIOC->CRL & 0xFFFF0000) | 0x00004444;

/* Setting DATA pins to output mode                                           */
#define LCD_DATA_DIR_OUT      GPIOC->CRL = (GPIOC->CRL & 0xFFFF0000) | 0x00003333;

/******************************************************************************/


/* 8 user defined characters to be loaded into CGRAM (used for bargraph)      */
const char UserFont[8][8] = {
  { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
  { 0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10 },
  { 0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18 },
  { 0x1C,0x1C,0x1C,0x1C,0x1C,0x1C,0x1C,0x1C },
  { 0x1E,0x1E,0x1E,0x1E,0x1E,0x1E,0x1E,0x1E },
  { 0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F },
  { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
  { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }
};


/************************ Global function definitions *************************/


/*******************************************************************************
* Delay in while loop cycles                                                   *
*   Parameter:    cnt:    number of while cycles to delay                      *
*   Return:                                                                    *
*******************************************************************************/

static void delay (int cnt)
{
  cnt <<= DELAY_2N;

  while (cnt--);
}


/*******************************************************************************
* Read status of LCD controller                                                *
*   Parameter:    none                                                         *
*   Return:       Status byte contains busy flag and address pointer           *
*******************************************************************************/

static unsigned char lcd_read_status (void)
{
  unsigned char status;

  LCD_DATA_DIR_IN
  LCD_RS(0)
  LCD_RW(1)
  delay(10);
  LCD_E(1)
  delay(10);
  status  = LCD_DATA_IN << 4;
  LCD_E(0)
  delay(10);
  LCD_E(1)
  delay(10);
  status |= LCD_DATA_IN;
  LCD_E(0)
  LCD_DATA_DIR_OUT
  return (status);
}


/*******************************************************************************
* Wait until LCD controller busy flag is 0                                     *
*   Parameter:                                                                 *
*   Return:       Status byte of LCD controller (busy + address)               *
*******************************************************************************/

static unsigned char wait_while_busy (void)
{
  unsigned char status;

  do  {
    status = lcd_read_status();
  }  while (status & 0x80);             /* Wait for busy flag                 */

  return (status);
}


/*******************************************************************************
* Write 4-bits to LCD controller                                               *
*   Parameter:    c:      command to be written                                *
*   Return:                                                                    *
*******************************************************************************/

void lcd_write_4bit (unsigned char c)
{
  LCD_RW(0)
  LCD_E(1)
  LCD_DATA_OUT(c&0x0F)
  delay(10);
  LCD_E(0)
  delay(10);
}


/*******************************************************************************
* Write command to LCD controller                                              *
*   Parameter:    c:      command to be written                                *
*   Return:                                                                    *
*******************************************************************************/

void lcd_write_cmd (unsigned char c)
{
  wait_while_busy();

  LCD_RS(0)
  lcd_write_4bit (c>>4);
  lcd_write_4bit (c);
}


/*******************************************************************************
* Write data to LCD controller                                                 *
*   Parameter:    c:      data to be written                                   *
*   Return:                                                                    *
*******************************************************************************/

static void lcd_write_data (unsigned char c)
{
  wait_while_busy();

  LCD_RS(1)
  lcd_write_4bit (c>>4);
  lcd_write_4bit (c);
}


/*******************************************************************************
* Print Character to current cursor position                                   *
*   Parameter:    c:      character to be printed                              *
*   Return:                                                                    *
*******************************************************************************/

void lcd_putchar (char c)
{ 
  lcd_write_data (c);
}


/*******************************************************************************
* Initialize the LCD controller                                                *
*   Parameter:                                                                 *
*   Return:                                                                    *
*******************************************************************************/

void lcd_init (void)
{ 
  int i;
  char const *p;

  LCD_CLOCK_EN                          /* Enable clock for peripheral        */

  /* Set all pins for LCD as outputs                                          */
  LCD_ALL_DIR_OUT

  delay (15000);
  LCD_RS(0)
  lcd_write_4bit (0x3);                 /* Select 4-bit interface             */
  delay (4100);
  lcd_write_4bit (0x3);
  delay (100);
  lcd_write_4bit (0x3);
  lcd_write_4bit (0x2);

  lcd_write_cmd (0x28);                 /* 2 lines, 5x8 character matrix      */
  lcd_write_cmd (0x0C);                 /* Display ctrl:Disp=ON,Curs/Blnk=OFF */
  lcd_write_cmd (0x06);                 /* Entry mode: Move right, no shift   */

  /* Load user-specific characters into CGRAM                                 */
  lcd_write_cmd(0x40);                  /* Set CGRAM address counter to 0     */
  p = &UserFont[0][0];
  for (i = 0; i < sizeof(UserFont); i++, p++)
    lcd_putchar (*p);

  lcd_write_cmd(0x80);                  /* Set DDRAM address counter to 0     */
}



/*******************************************************************************
* Set cursor position on LCD display                                           *
*   Parameter:    column: column position                                      *
*                 line:   line position                                        *
*   Return:                                                                    *
*******************************************************************************/

void set_cursor (int column, int line)
{
  unsigned char address;

  address = (line * 40) + column;
  address = 0x80 + (address & 0x7F);
  lcd_write_cmd(address);               /* Set DDRAM address counter to 0     */
}

/*******************************************************************************
* Clear the LCD display                                                        *
*   Parameter:                                                                 *
*   Return:                                                                    *
*******************************************************************************/

void lcd_clear (void)
{
  lcd_write_cmd(0x01);                  /* Display clear                      */
  set_cursor (0, 0);
}


/*******************************************************************************
* Print sting to LCD display                                                   *
*   Parameter:    string: pointer to output string                             *
*   Return:                                                                    *
*******************************************************************************/

void lcd_print (char *string)
{
  while (*string)  {
    lcd_putchar (*string++);
  }
}


/*******************************************************************************
* Print a bargraph to LCD display                                              *
*   Parameter:     val:  value 0..100 %                                        *
*                  size: size of bargraph 1..16                                *
*   Return:                                                                    *
*******************************************************************************/
void lcd_bargraph (int value, int size) {
   int i;

   value = value * size / 20;            /* Display matrix 5 x 8 pixels       */
   for (i = 0; i < size; i++) {
      if (value > 5) {
         lcd_putchar (0x05);
         value -= 5;
      }
      else {
         lcd_putchar (value);
         break;
      }
   }
}


/*******************************************************************************
* Display bargraph on LCD display                                              *
*   Parameter:     pos_x: horizontal position of bargraph start                *
*                  pos_y: vertical position of bargraph                        *
*                  value: size of bargraph active field (in pixels)            *
*   Return:                                                                    *
*******************************************************************************/

void lcd_bargraphXY (int pos_x, int pos_y, int value) {
  int i;

  set_cursor (pos_x, pos_y);
  for (i = 0; i < 16; i++)  {
    if (value > 5) {
      lcd_putchar (0x05);
      value -= 5;
    } else {
      lcd_putchar (value);
      while (i++ < 16) lcd_putchar (0);
    }
  }
}

/******************************************************************************/
