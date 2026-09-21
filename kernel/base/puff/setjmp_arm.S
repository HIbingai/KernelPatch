/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelPatch AArch32 (ARMv7-A) port — puff setjmp/longjmp.
 *
 * A32 counterpart of base/puff/setjmp_aarch64.S, needed because base/puff/puff.c
 * calls setjmp()/longjmp() and the AArch64 provider cannot be linked into the
 * ARM blob.
 *
 * ABI: puff.c reaches these through base/puff/puff_port.h's
 *      `typedef unsigned long jmp_buf[16];`
 * which is 16 * 4 = 64 bytes on ILP32 — room for the 10 slots used here, so
 * puff_port.h needs NO change for A32.
 *
 * AAPCS callee-saved state is r4-r11, sp and lr (r12/ip and the caller-saved
 * argument registers are explicitly not part of the A32 setjmp contract), so
 * the buffer is used as:
 *
 *   slot  0   4   8   12  16  20  24  28  32  36  40..60
 *   reg   r4  r5  r6  r7  r8  r9  r10 r11 sp  lr  unused
 *
 * setjmp() returns 0; longjmp(env, val) returns val, with val == 0 mapped to 1
 * (same as the AArch64 version's `csinc w0, w1, wzr, ne`).
 *
 * Position-independent by construction: everything that crosses setjmp is
 * PC-relative (`bx lr` / `bx r3`), so there is no absolute address, no literal
 * pool and no GOT entry in this file.
 */
    .arm
    .syntax unified
    .text
    .align 2

    .global setjmp
    .type setjmp, %function
setjmp:
    stmia   r0, {r4-r11}                     @ jmp_buf[0..7]  = r4 .. r11
    add     r1, r0, #32
    mov     r2, sp
    mov     r3, lr
    stmia   r1, {r2, r3}                     @ jmp_buf[8] = sp, [9] = lr
    mov     r0, #0                           @ setjmp() returns 0
    bx      lr
    .size setjmp, .-setjmp

    .global longjmp
    .type longjmp, %function
longjmp:
    ldmia   r0, {r4-r11}                     @ restore the callee-saved set
    add     r2, r0, #32
    ldr     r12, [r2]                        @ saved sp
    ldr     r3, [r2, #4]                     @ saved lr == the setjmp() return site
    mov     sp, r12
    cmp     r1, #0
    moveq   r1, #1                           @ longjmp(env, 0) returns 1, never 0
    mov     r0, r1
    bx      r3                               @ resume as if setjmp() had returned r0
    .size longjmp, .-longjmp