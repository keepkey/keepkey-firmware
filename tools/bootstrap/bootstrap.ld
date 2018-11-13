MEMORY
{
    /* Bootloader */
    rom (rx) : ORIGIN = 0x08000000, LENGTH = 0x00003fff

    /* RAM */
    ram (rwx)    : ORIGIN = 0x20000000, LENGTH = 0x00020000
}



INCLUDE libopencm3_stm32f2.ld

_ram_start = ORIGIN(ram);
_ram_end = ORIGIN(ram) + LENGTH(ram);
_stack = _ram_end - 8;
__stack_chk_guard = _ram_end - 8;

_data_size = SIZEOF(.data);
