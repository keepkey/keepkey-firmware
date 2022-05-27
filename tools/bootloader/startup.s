  .syntax unified

  .text

  .global memset_reg
  .type memset_reg, STT_FUNC
memset_reg:
  // call with the following (note that the arguments are not validated prior to use):
  // r0 - address of first word to write (inclusive)
  // r1 - address of first word following the address in r0 to NOT write (exclusive)
  // r2 - word value to be written
  // both addresses in r0 and r1 needs to be divisible by 4!
  .L_loop_begin:
    str r2, [r0], 4 // store the word in r2 to the address in r0, post-indexed
    cmp r0, r1
  bne .L_loop_begin
  bx lr

  .global reset_handler
  .type reset_handler, STT_FUNC
reset_handler:
   
  // Initialize msp stack and start using it
  ldr     r0, =vtor
  ldr     r0, [r0]
  ldr     r0, [r0]
  msr     msp, r0

  // Save any reset parameters from the SRAM wipe
  ldr r0, =_param_1
  ldr r3, [r0]
  ldr r0, =_param_2
  ldr r4, [r0]
  ldr r0, =_param_3
  ldr r5, [r0]

  ldr r0, =_ram_start // r0 - point to beginning of SRAM
//  ldr r1, =_ram_end   // r1 - point to byte after the end of SRAM
  ldr r1, =_comram_end
  ldr r2, =0          // r2 - the byte-sized value to be written
  bl memset_reg

  // Restore any reset parameters
  ldr r0, =_param_1
  str r3, [r0]
  ldr r0, =_param_2
  str r4, [r0]
  ldr r0, =_param_3
  str r5, [r0]

  // copy .data section from flash to SRAM
  ldr r0, =_data          // dst addr
  ldr r1, =_data_loadaddr // src addr
  ldr r2, =_data_size     // length in bytes
  bl memcpy

  // enter the application code
  bl main

  // loop forever if the application code returns
  b .

  .global shutdown
  .type shutdown, STT_FUNC
shutdown:
  cpsid f                 // disable interrupts
  ldr r0, =_ram_start
//  ldr r1, =_ram_end
  ldr r1, =_comram_end
  ldr r2, =0
  bl memset_reg
  ldr r0, =0
  mov r1, r0
  mov r2, r0
  mov r3, r0
  mov r4, r0
  mov r5, r0
  mov r6, r0
  mov r7, r0
  mov r8, r0
  mov r9, r0
  mov r10, r0
  mov r11, r0
  mov r12, r0
  ldr lr, =0xffffffff
  b .                     // loop forever


  .set vtor, 0xe000ed08

  .ltorg // dump literal pool (for the ldr ...,=... commands above)

  .end
