MEMORY
{
    /* Bootloader */
    rom (rx) : ORIGIN = 0x08000000, LENGTH = 0x0000C000 

    /* RAM */
    ram (rwx)    : ORIGIN = 0x20000000, LENGTH = 0x00020000
}



INCLUDE libopencm3_stm32f2.ld
