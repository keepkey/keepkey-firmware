/* STM32F205RG - 1MB Flash, 128K RAM */
/* program starts at 0x08060100 (FLASH_APP_START) */
/* 1MB = 0x00100000 ;640K=0x000A0000; 384K = 0x00060000 ; 256K = 0x00040000; 128K = 0x00020000  */

MEMORY
{
	rom (rx)   : ORIGIN = 0x08060100, LENGTH = 0x00100000 - 0x00060100
        ram (rwx)  : ORIGIN = 0x20000000, LENGTH = 0x00020000
}

INCLUDE libopencm3_stm32f2.ld

_ram_start = ORIGIN(ram);
_ram_end = ORIGIN(ram) + LENGTH(ram);
