/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelPatch AArch32 (ARMv7-A) port — boot setup stub (M4a).
 * Port of kernel/base/setup1.S (AArch64) to A32 / ARM mode.
 *
 * Target (M0): ARM (A32, not Thumb-2), non-LPAE, PAGE_OFFSET=0xC0000000,
 * boot ABI r0=0 / r1=machine / r2=dtb. Runs MMU OFF (physical) at boot.
 *
 * Flow: kernel entry is overwritten by patch.c with `B setup_entry`.
 *   1. compute load-bias delta (blob runs where injected, not at link addr)
 *   2. set up a private stack (from base/setup.c)
 *   3. map_prepare(kernel_pa, delta): hook paging_init + relocate .map (C)
 *   4. restore the original 8 entry bytes (header_backup) over our branch
 *   5. CP15 D-clean + I-invalidate, then branch to kernel_pa with r0-r3 intact
 *   -> kernel boots; later paging_init jumps into the relocated _paging_init.
 *
 * r4-r6 are callee-saved (survive the map_prepare call); boot args r0-r3 are
 * saved on the private stack and restored just before the jump.
 */

#define __ASSEMBLY__
#include "../base/setup.h"

    .arm
    .syntax unified

    .section .entry.text, "ax"
    .align 2
    .global setup_entry
    .type setup_entry, %function
setup_entry:
    /* delta = runtime(anchor) - linktime(anchor) */
    adr     r12, .Lanchor
    ldr     r11, .Lanchor
    sub     r12, r12, r11
    mov     r4, r12                 @ r4 = delta (callee-saved)

    /* BISECT3: preserve boot args in callee-saved regs (no stack) */
    mov     r8, r0                  @ r8 = r0 (=0)
    mov     r9, r1                  @ r9 = machine id
    mov     r10, r2                 @ r10 = dtb ptr

    /* kernel_pa = runtime(_link_base) - setup_preset.setup_offset */
    ldr     r5, =setup_preset
    add     r5, r5, r4              @ runtime &setup_preset
    ldr     r6, [r5, #setup_setup_offset_offset]
    ldr     r7, =_link_base
    add     r7, r7, r4
    sub     r5, r7, r6              @ r5 = kernel_pa (callee-saved)

    /* Call map_prepare(kernel_pa, delta) with a private stack, but SAVE and
     * RESTORE the original sp around it so the kernel entry runs with the sp the
     * bootloader/decompressor set (changing sp across the jump broke boot). */
    mov     r11, sp                 @ save original sp (callee-saved)
    ldr     r6, =stack
    add     r6, r6, r4              @ runtime &stack
    add     r6, r6, #STACK_SIZE
    mov     sp, r6                  @ private stack for the C call
    mov     r0, r5
    mov     r1, r4
    bl      map_prepare
    mov     sp, r11                 @ restore original sp

    /* restore original first 8 bytes (header_backup) over the injected B */
    ldr     r0, =setup_preset
    add     r0, r0, r4              @ runtime &setup_preset
    add     r0, r0, #setup_header_backup_offset
    ldr     r1, [r0]
    ldr     r2, [r0, #4]
    str     r1, [r5]
    str     r2, [r5, #4]

    /* make the restored entry instructions visible to the I-side (PoC) */
    mcr     p15, 0, r5, c7, c14, 1  @ DCCIMVAC @ kernel_pa
    add     r1, r5, #4
    mcr     p15, 0, r1, c7, c14, 1
    dsb     sy
    mov     r1, #0
    mcr     p15, 0, r1, c7, c5, 0   @ ICIALLU
    mcr     p15, 0, r1, c7, c5, 6   @ BPIALL
    dsb     sy
    isb

    mov     r0, r8                  @ restore boot args (BISECT3: from callee-saved)
    mov     r1, r9
    mov     r2, r10
    bx      r5                      @ enter the real kernel entry

    .align 2
.Lanchor:
    .word   .Lanchor
    .ltorg
    .size setup_entry, .-setup_entry
