/* STM32F205RG - 1MB Flash, 128K RAM */
/* program starts at 0x08060100 (FLASH_APP_START) */ 
/* 1MB = 0x00100000 ;640K=0x000A0000; 384K = 0x00060000 ; 256K = 0x00040000; 128K = 0x00020000  */

MEMORY
{
    /* blupdater ROM */
    rom (rx)   : ORIGIN = 0x08060100, LENGTH = 0x00100000 - 0x00060100

    /* ram shared by bootloader and firmware, contains msp (blupdater does not use psp) */
    ram (rwx) : ORIGIN = 0x20000000, LENGTH = 0x0001FF00

    /* 256 bytes of common block above stacks */
    comram (rwx) : ORIGIN = 0x2001FF00, LENGTH = 0x100
}

INCLUDE libopencm3_stm32f2.ld

SECTIONS
{
    .version : {
        KEEP(*(version))
    } >rom
}

_ram_start = ORIGIN(ram);
_ram_end = ORIGIN(ram) + LENGTH(ram);
_comram_end = ORIGIN(comram) + LENGTH(comram);

/* The blupdater memory layout is similar to the bootloader, however it is located in the */
/* firmware ram. The blupdater must be a standalone app not dependent on the bootloader */
/* vector table. To make maintenance as seemeless as possible, the interrupt architecture */
/* of the blupdater is the same as the firmware/bootloader architecture. This is not the */
/* most straightforward arch that could be used but the blupdater is forward compatible with */
/* potential bootloader/firmware isr vector changes. */

/* this is the msp for the blupdater. Make stacks 8-byte aligned. */
_stack = _ram_end - 24;                
__stack_chk_guard = _ram_end - 24;

/* statics needed for the blupdater */
_debug_1 = _ram_end - 16;
_uisr = _ram_end - 12;
button_sp_ctx = _ram_end - 8;
timer_sp_ctx = _ram_end - 4; 


/* common block vars to support bootloader/firmware isr arch */

_mmhusr_isr = _comram_end - 24;
_param_3 = _comram_end - 20;
_param_2 = _comram_end - 16;
_param_1 = _comram_end - 12;
_timerusr_isr = _comram_end - 8; 
_buttonusr_isr = _comram_end - 4;


_data_size = SIZEOF(.data);





