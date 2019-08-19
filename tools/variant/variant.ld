MEMORY
{
    rom (rx)  : ORIGIN = 0x08010000, LENGTH = 0x0001FFFF
}

SECTIONS
{
    . = ORIGIN(rom);

    .header : ALIGN(4) {
        KEEP(*(.header));
    } >rom AT >rom

    .variant_info : {
        KEEP(*(variant_info))
    } >rom

    .text : {
        *(.text*)    /* Program code */
        . = ALIGN(4);
        *(.rodata*)  /* Read-only data */
        . = ALIGN(4);
    } >rom

    /* variant "code" isn't allowed to have its own state */
    /DISCARD/ : {
        *(.bss)
        *(COMMON)
        *(.eh_frame)
        *(.data*)
    }
}

_codelen = SIZEOF(.variant_info) + SIZEOF(.text);

