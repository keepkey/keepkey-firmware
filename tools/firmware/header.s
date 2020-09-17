    .syntax unified

    .section .header, "a"

    .type g_header, %object
    .size g_header, .-g_header

g_header:
    .byte 'K','P','K','Y'
    .word _codelen
    .byte 0                // sigindex1
    .byte 0                // sigindex2
    .byte 0                // sigindex3
    .byte 1                // sig_flag: Preserve
    .word 0                // meta_flags: no update after
    . = . + 48             // reserved
    . = . + 64             // sig1
    . = . + 64             // sig2
    . = . + 64             // sig3
