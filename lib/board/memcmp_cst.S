.text
        .syntax unified

        // Compares up to 256 bytes in constant time.
        // Roughly:
        // int memcmp_cst(const void *lhs, const void *rhs, size_t len) {
        //    char permute[len];
        //
        //    for (int i = 0; i < len; i++) {
        //        permute[i] = i;
        //    }
        //
        //    random_permute_char(permute, len);
        //
        //    char res = 0;
        //    for (int i = 0; i < len; i++) {
        //        res |= lhs[permute[i]] ^ rhs[permute[i]];
        //    }
        //
        //    memzero(permute, len);
        //
        //    return res == 0;
        // }
        .global memcmp_cst
memcmp_cst:
        push    {r4, r5, r6, r7, lr}
        add     r7, sp, #12
        push.w  {r8, r9, r10}
        mov     r6, r0
        adds    r0, r2, #7
        bic     r0, r0, #7
        sub.w   r5, sp, r0
        mov     r4, r2
        mov     r8, r1
        mov     sp, r5

        mov     r0, r5
        mov     r1, r2
        bl      asc_fill               // asc_fill(permute, len)

        mov     r0, r5
        mov     r1, r4
        bl      random_permute_char    // random_permute_char(permute, len)

        mov     r0, r6
        mov     r1, r8
        mov     r2, r5
        mov     r3, r4
        bl      permuted_compare       // res = permuted_compare(lhs, rhs, permute, len)

        mov     r6, r0
        mov     r0, r5
        mov     r1, r4
        bl      memzero                // memzero(permute, len)
        mov     r0, r6

        sub.w   r4, r7, #24
        mov     sp, r4
        pop.w   {r8, r9, r10}
        pop     {r4, r5, r6, r7, pc}

        // Compare two arrays in permuted order
        // int permuted_compare(
        //     const char *lhs,
        //     const char *rhs,
        //     const char *permute,
        //     size_t len)
permuted_compare:
        push    {r4, r5, r7, r8, lr}
        add     r7, sp, #12
        mov     r12, r0
        movs    r0, #0
.permuted_compare.loop:
        ldrb    r8, [r2], #1           // r8 = permute[i]
        subs    r3, #1
        ldrb.w  r5, [r12, r8]          // r5 = lhs[r8]
        ldrb.w  r4, [r1, r8]           // r4 = rhs[r8]
        eor.w   r5, r5, r4             // r5 = r5 ^ r4
        orr.w   r0, r0, r5             // r0 = r0 | r5
        bne     .permuted_compare.loop

        cmp     r0, #0
        it      ne
        movne   r0, #1                 // r0 = !!r0

        pop     {r4, r5, r7, r8, pc}

        // Fill an array with the numbers [0, 1, 2, ... len)
        // void asc_fill(const char *array, size_t len)
        .global asc_fill
asc_fill:
        movs    r2, #0
.asc_fill.loop:
        strb    r2, [r0, r2]
        adds    r2, #1
        cmp     r1, r2
        bne     .asc_fill.loop
        bx      lr
