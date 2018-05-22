MEMORY
{
    /* Bootloader */
    rom (rx)  : ORIGIN = 0x08020000, LENGTH = 0x00040000 

    /* RAM */
    ram (rwx) : ORIGIN = 0x20000000, LENGTH = 0x00020000
}

SECTIONS
{
    .confidential (NOLOAD) : {
        _confidential_start = .;
        *(confidential)
        ASSERT ((SIZEOF(.confidential) <= 32K), "Error: Confidential section too large");
        _confidential_end = .;
    } >ram
}

INCLUDE libopencm3_stm32f2.ld

_ram_start = ORIGIN(ram);
_ram_end = ORIGIN(ram) + LENGTH(ram);
_stack = _ram_end - 8;
__stack_chk_guard = _ram_end - 8;

_data_size = SIZEOF(.data);
