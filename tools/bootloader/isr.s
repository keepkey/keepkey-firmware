/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 KeepKey LLC
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

   .syntax unified

  .text

  .global exti9_5_isr
  .type exti9_5_isr STT_FUNC
  .section  .text.exti9_5_isr
  .align 4

/*
 * exti9_5_isr() - supervisor mode button interrupt
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
    // This isr exists in bootloader memory and is reachable from the bootloader
    // as well as the firmware.

	// All interrupts are processed in handler mode with privileged execution.
    // For firmware, we want to allow a user interrupt that executes at lower priority than
    // the timer interrupt executing in the bootloader section.

    // We want to "context switch" to unprivileged handler mode to process
    // user isr code.

    // all code is currently using the msp stack, have user mode code use psp stack.

    // msp stack at entry is {r0-r3,r12,lr,pc,xpsr}, pc is at 0x18 offset from sp

    // Do privilege mode processing first then context switch
    
exti9_5_isr:

    push {r4-r11, lr}               // save 0x24 bytes, rest of context including lr in this stack frame

    // Determine stack pointer of frame from which exception was taken
    tst     lr, #4
    beq     b_using_msp
    bne     b_using_psp

b_using_msp:
    mrs     r0, msp
    mov     r2, r0
    add     r2, r0, #0x24
    b       b_continue

b_using_psp:
    mrs     r0, psp
    mov     r2, r0
    add     r2, r0, #0x00

b_continue:
    // at this point r0 contains the ex. frame sp, r2 points to the ex. frame ctx saved
    // save the sp for context restore later
    ldr   r1, =button_sp_ctx
    str   r0, [r1]

    // duplicate the exception saved stack to make a dummy return for ctx switch
    ldmia r2!, {r4-r11}         // r4-r11 have r0,r1,r2,r3,r12,lr,pc,xpsr 
    ldr   r11, =dummy_xpsr      // xpsr - do not use the actual one for fake "return"
    ldr   r1, =_buttonusr_isr   // pc - load pc slot with address of user isr func
    ldr   r10, [r1] 

    stmdb r0!, {r4-r11}

    // save r0 to appropriate stack pointer
    tst    lr, #4        // bit 4 is exc_return SPSEL - which stack pointer exception frame resides on 0=msp, 1=psp
    ite    eq
    msreq  msp, r0
    msrne  psp, r0


// If exc taken from msp frame: stack is {r0-r3,r12,lr,pc,xpsr} {r4-r11, lr (this frame)} {r0-r3,r12,lr,pc,xpsr}
// If exc taken from psp frame: msp frame {r4-r11, lr (this frame)}
//                              psp frame {r0-r3,r12,lr,pc,xpsr} {r0-r3,r12,lr,pc,xpsr}


// Need to disable interrupts so that the user mode portion does not become reentrant
// disable button and timer interrupts
    ldr     r0, =idis_base 
    ldr     r1, =ibits
    str     r1, [r0]

// flag that we are about to be in a user interrupt routine
    ldr     r0, =_uisr
    mov     r1, #1
    str     r1, [r0]
 

// disable request
    mvns    r0, #button_mask
    ldr     r2, =exti_imr
    ldr     r3, [r2, #0]        // get what is in exti_imr
    ands    r3, r0              // clear the bit
    str     r3, [r2, #0]        // write back to IMR

// disable event
    ldr     r3, =exti_emr
    ldr     r2, [r3, #0]        // get what is in exti_emr
    ands    r0, r2              // clear the bit
    str     r0, [r3, #0]        // write back to IMR

// reset button request, bit 7 in 0x40013c14
    movs    r0, #button_mask
    ldr     r1, =exti_pr    
    str     r0, [r1, #0]    

    bx      lr        // psp frame return, after the exception return psp will contain {r0-r3,r12,lr,pc,xpsr}

    .set iena_base, 0xe000e100  // interrupt enable base register
    .set idis_base, 0xe000e180  // interrupt disable base register
    .set ibits,     0x40800000  // interrupt bits to set or clear, 30 is exti9_5, 23 is tim4



  .global svhandler_button_usr_return
  .type svhandler_button_usr_return, STT_FUNC
  .section  .text.svhandler_button_usr_return
  .align 4

svhandler_button_usr_return:

// re-enable button request
    movs    r0, #button_mask           
    ldr     r2, =exti_imr 
    ldr     r3, [r2, #0]
    orrs    r3, r0              // set the bit
    str     r3, [r2, #0]        // write back to reg
    
    ldr     r3, [r2, #4]        // EXTI_EMR
    orrs    r0, r3
    str     r0, [r2, #4]

    // restore the sp
    ldr   r1, =button_sp_ctx
    ldr   r2, [r1]
    tst   lr, #4
    ite   eq
    msreq msp, r2
    msrne psp, r2

// If exc taken from msp frame: msp is {r4-r11, lr (this frame)} {r0-r3,r12,lr,pc,xpsr}
// If exc taken from psp frame: msp frame {r4-r11, lr (this frame)}
//                              psp frame {r0-r3,r12,lr,pc,xpsr}

    pop {r4-r11, lr}            // clean up msp frame

// flag that we are done with usr interrupt routine
    ldr     r0, =_uisr
    mov     r1, #0
    str     r1, [r0]
 
// enable button and timer interrupts
    ldr     r0, =iena_base 
    ldr     r1, =ibits
    str     r1, [r0]

    bx lr

    .set exti_imr, 0x40013c00
    .set exti_emr, 0x40013c04
    .set exti_pr,  0x40013c14

    .if DEV_DEBUG == 1
    .set button_mask, 512      // BUTTON_EXTI - 0x200
    .else
    .set button_mask, 128      // BUTTON_EXTI - 0X80
    .endif
    

  .global tim4_isr
  .type tim4_isr STT_FUNC
  .section  .text.tim4_isr
  .align 4

/*
 * tim4_isr() - supervisor mode button interrupt
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
    // This isr exists in bootloader memory and is reachable from the bootloader
    // as well as the firmware.

    // All interrupts are processed in handler mode with privileged execution.
    // For firmware, we want to allow a user interrupt that executes at lower priority than
    // the timer interrupt executing in the bootloader section.

    // We want to "context switch" to unprivileged handler mode to process
    // user isr code.

    // all code is currently using the msp stack, have user mode code use psp stack.

    // psp stack at entry is {r0-r3,r12,lr,pc,xpsr}, pc is at 0x18 offset from psp

    // Do privilege mode processing first then context switch
    
tim4_isr:

    push {r4-r11, lr}               // save 0x24 bytes, rest of context including lr in this stack frame

    // Determine stack pointer of frame from which exception was taken
    tst     lr, #4
    beq     t_using_msp
    bne     t_using_psp

t_using_msp:
    mrs     r0, msp
    mov     r2, r0
    add     r2, r0, #0x24
    b       t_continue

t_using_psp:
    mrs     r0, psp
    mov     r2, r0
    add     r2, r0, #0x00

t_continue:
    // save the sp for context restore later
    ldr   r1, =timer_sp_ctx
    str   r0, [r1]

    // duplicate the exception saved stack to make a dummy return for ctx switch
    ldmia r2!, {r4-r11}    // r4-r11 have r0,r1,r2,r3,r12,lr,pc,xpsr 
    ldr   r11, =dummy_xpsr       // xpsr - do not use the actual one for fake "return"
    ldr   r1, =_timerusr_isr   // pc - load pc slot with address of user isr func
    ldr   r10, [r1] 

    stmdb r0!, {r4-r11}

    // save r0 to appropriate stack pointer
    tst    lr, #4        // bit 4 is exc_return SPSEL - which stack pointer exception frame resides on 0=msp, 1=psp
    ite    eq
    msreq  msp, r0
    msrne  psp, r0


// If exc taken from msp frame: msp is {r0-r3,r12,lr,pc,xpsr} {r4-r11, lr (this frame)} {r0-r3,r12,lr,pc,xpsr}
// If exc taken from psp frame: msp frame {r4-r11, lr (this frame)}
//                              psp frame {r0-r3,r12,lr,pc,xpsr} {r0-r3,r12,lr,pc,xpsr}


// Need to disable interrupts so that the user mode portion does not become reentrant
// disable button and timer interrupts
    ldr     r0, =idis_base 
    ldr     r1, =ibits
    str     r1, [r0]

// flag that we are about to be in a user interrupt routine
    ldr     r0, =_uisr
    mov     r1, #1
    str     r1, [r0]

    bx      lr        // psp frame return, after the exception return psp will contain {r0-r3,r12,lr,pc,xpsr}


// This is just a dummy xpsr value that has Z,C,T bits set. This is necessary so that
// the fake "return" to thread mode does not imply a return to an interruptable multiple register operation
// which may have been saved from the real interrupt.
    .set dummy_xpsr, 0x61000000     





  .global svhandler_timer_usr_return
  .type svhandler_timer_usr_return, STT_FUNC
  .section  .text.svhandler_timer_usr_return
  .align 4

svhandler_timer_usr_return:

    push    {lr}

// timer_clear_flag(TIM4, TIM_SR_UIF);
// clear the timer timer_clear_flag
    movs    r1, #1          // TIM_SR_UIF
    ldr     r0, =tim4 
    bl      timer_clear_flag

    pop     {lr}

    // restore the sp
    ldr   r1, =timer_sp_ctx
    ldr   r2, [r1]
    tst   lr, #4
    ite   eq
    msreq msp, r2
    msrne psp, r2

// If exc taken from msp frame: msp is {r4-r11, lr (this frame)} {r0-r3,r12,lr,pc,xpsr}
// If exc taken from psp frame: msp frame {r4-r11, lr (this frame)}
//                              psp frame {r0-r3,r12,lr,pc,xpsr}

    pop {r4-r11, lr}            // clean up msp frame

// flag that we are done with usr interrupt routine
    ldr     r0, =_uisr
    mov     r1, #0
    str     r1, [r0]

// enable button and timer interrupts
    ldr     r0, =iena_base 
    ldr     r1, =ibits
    str     r1, [r0]

    bx lr

    .set tim4,      0x40000800     // TIM4
 


  .global mem_manage_handler
  .type mem_manage_handler STT_FUNC
  .section  .text.mem_manage_handler
  .align 4
/*
 * mem_manage_handler() - try to display memory manager exception info
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */

mem_manage_handler:

    push {r4-r11, lr}               // save 0x24 bytes, rest of context including lr in this stack frame

    // read out some regs so that unpriv handler can access them
#ifdef DEBUG_ON
    ldr     r0, =mmfar_reg 
    ldr     r1, [r0, #0]
#else
    eor     r1, r1
#endif
    ldr     r0, =_param_1
    str     r1, [r0]


    // Determine stack pointer of frame from which exception was taken
    tst     lr, #4
    beq     m_using_msp
    bne     m_using_psp

m_using_msp:
    mrs     r0, msp
    mov     r2, r0
    add     r2, r0, #0x24
    b       m_continue

m_using_psp:
    mrs     r0, psp
    mov     r2, r0
    add     r2, r0, #0x00

m_continue:
    // Do not not worry about the sp context, will never return

    // duplicate the exception saved stack to make a dummy return for ctx switch
    ldmia r2!, {r4-r11}      // r4-r11 have r0,r1,r2,r3,r12,lr,pc,xpsr
#ifdef DEBUG_ON
    mov   r1, r10            // pc
#else
    eor   r1, r1
#endif
    ldr   r2, =_param_2
    str   r1, [r2]
    ldr   r11, =dummy_xpsr   // xpsr - do not use the actual one for fake "return"
    ldr   r1, =_mmhusr_isr   // pc - load pc slot with address of user isr func
    ldr   r10, [r1] 

    stmdb r0!, {r4-r11}

    // save r0 to appropriate stack pointer
    tst    lr, #4        // bit 4 is exc_return SPSEL - which stack pointer exception frame resides on 0=msp, 1=psp
    ite    eq
    msreq  msp, r0
    msrne  psp, r0


// If exc taken from msp frame: msp is {r0-r3,r12,lr,pc,xpsr} {r4-r11, lr (this frame)} {r0-r3,r12,lr,pc,xpsr}
// If exc taken from psp frame: msp frame {r4-r11, lr (this frame)}
//                              psp frame {r0-r3,r12,lr,pc,xpsr} {r0-r3,r12,lr,pc,xpsr}
    bx      lr        // psp frame return, after the exception return psp will contain {r0-r3,r12,lr,pc,xpsr}

    .set mmfar_reg, 0xe000ed34
 



    .global svhandler_enable_interrupts
    .type svhandler_enable_interrupts, STT_FUNC
    .section  .text.svhandler_enable_interrupts
    .align 4

// All user interrupts are enabled here
svhandler_enable_interrupts:

// abort enable if in user isr handler
    ldr     r0, =_uisr
    ldr     r0, [r0]
    teq     r0, #1
    beq     enable_ret

// enable button and timer interrupts
    ldr     r0, =iena_base 
    ldr     r1, =ibits
    str     r1, [r0]

enable_ret:
    bx  lr




    .global svhandler_disable_interrupts
    .type svhandler_disable_interrupts, STT_FUNC
    .section  .text.svhandler_disable_interrupts
    .align 4

// All user interrupts except the svc should be disabled
svhandler_disable_interrupts:

// disable button and timer interrupts
    ldr     r0, =idis_base 
    ldr     r1, =ibits
    str     r1, [r0]

    bx  lr



    .global svhandler_start_firmware
    .type svhandler_start_firmware, STT_FUNC
    .section  .text.svhandler_start_firmware
    .align 4

svhandler_start_firmware:

    // r0 contains privilege or unpriv mode indicator
    // duplicate the exception saved on the msp stack to the psp to make a jump to unpriv firmware

    mov     r3, r0                // save parameter in r3
    ldr     r0, =fwsp             // this points to the psp initial value
    ldr     r0, [r0]

    // zero out regs to init state    r4-r11 have r0,r1,r2,r3,r12,lr,pc,xpsr 
    eor     r4, r4
    eor     r5, r5
    eor     r6, r6
    eor     r7, r7
    eor     r8, r8
    eor     r9, r9
       
    ldr     r11, =dummy_xpsr      // xpsr - do not use the actual one for fake "return"
    ldr     r1, =fwreset          // pc - load pc slot with the firmware reset vector
    ldr     r10, [r1]
    bic     r10, r10, #0x01       // clear thumb mode bit 

    stmdb r0!, {r4-r11}

    msr     psp, r0               // initialize the psp here

    mrs     r2, msp               // clean up msp stack pointer
    add     r2, #0x20
    msr     msp, r2

    ldr     lr, =tmpsp            // lr - gets thread mode return use psp 

// set thread mode privilege parameter
    teq     r3, svc_firmware_unpriv
    bne     sf_done
    movs    r3, #0x01
    msr     control, r3          
sf_done: 
    bx      lr


    .set svc_firmware_unpriv, 9    // This must match SVC_FIRMWARE_UNPRIV define in supervise.h
    .set fwsp,    0x08060100
    .set fwreset, 0x08060104
    .set tmpsp,   0xFFFFFFFD



    .global sv_call_handler
    .type sv_call_handler, STT_FUNC
    .section  .text.sv_call_handler
    .align 4

sv_call_handler:
    tst lr, #4        // bit 4 is exc_return SPSEL - which stack pointer exception frame resides on 0=msp, 1=psp
    ite eq            // if-then-else block. equal then next ins else ins 2
    mrseq r0, msp     // eq
    mrsne r0, psp     // neq
    b svc_handler_main


   .ltorg // dump literal pool (for the ldr ...,=... commands above)

    .end

