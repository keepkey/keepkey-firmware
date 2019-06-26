    .syntax unified

    .section .header, "a"

    .type g_header, %object
    .size g_header, .-g_header

g_header:
    .byte 'K','K','W','L'
    .word _codelen
    .byte 0                // sigindex1
    .byte 0                // sigindex2
    .byte 0                // sigindex3
    .byte 0                // flags: none
    . = . + 52             // reserved
    . = . + 64             // sig1
    . = . + 64             // sig2
    . = . + 64             // sig3
