MEMORY
{
    /* Bootloader ROM */
    rom (rx)  : ORIGIN = 0x08020000, LENGTH = 0x00040000 

    /* ram shared by bootloader and firmware, contains psp */
    ram (rwx) : ORIGIN = 0x20000000, LENGTH = 0x1F800

    /* 2K-256 exclusive protected boot ram contains msp and special bootram statics. */
    /*   Use the origin value for this ram in the MPU setup, must be mem prot size aligned for mpu */
    bram (rwx) : ORIGIN = 0x2001F800, LENGTH = 0x700

    /* 256 bytes of common block above stacks */
    comram (rwx) : ORIGIN = 0x2001FF00, LENGTH = 0x100
}

SECTIONS
{
    .confidential (NOLOAD) : {
        _confidential_start = .;
        LONG(0);
            *(confidential)
        ASSERT ((SIZEOF(.confidential) <= 32K), "Error: Confidential section too large");
        _confidential_end = .;
    } >ram
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
_bram_end = ORIGIN(bram) + LENGTH(bram);
_comram_end = ORIGIN(comram) + LENGTH(comram);

/* this is the msp. Make stack 8-byte aligned */
_stack = _bram_end - 24;                
__stack_chk_guard = _bram_end - 24;

/* protected bootloader statics */
_debug_1 = _bram_end - 16;
_uisr = _bram_end - 12;
button_sp_ctx = _bram_end - 8;
timer_sp_ctx = _bram_end - 4; 


/* common block vars to be accessed by both bootloader and firmware */

_mmhusr_isr = _comram_end - 24;
_param_3 = _comram_end - 20;
_param_2 = _comram_end - 16;
_param_1 = _comram_end - 12;
_timerusr_isr = _comram_end - 8; 
_buttonusr_isr = _comram_end - 4;


_data_size = SIZEOF(.data);



