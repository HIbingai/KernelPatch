/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelPatch AArch32 (ARMv7-A) port — boot setup / entry assembly.
 *
 * A32 counterpart of base/setup1.S (AArch64).  Same flow, same contracts, but
 * it drives the *already ported* C parts instead of re-implementing them:
 *
 *   1. tools/patch.c overwrites the kernel's first instruction with an A32
 *      `B setup_entry`; setup_entry lives at blob offset SZ_4K (the patcher
 *      branches to `align_kimg_len + SZ_4K`, so .entry.text must be the first
 *      input of .setup.text — exactly as in kpimg.lds / kpimg-arm.lds).
 *   2. setup_entry -> setup, which computes
 *        delta = runtime(.Lanchor) - linktime(.Lanchor)
 *      and converts every link-time symbol with it (the blob runs wherever the
 *      patcher injected it, not at its link address).
 *   3. start_prepare(kernel_pa, delta) — fills base/start.c's start_preset,
 *      backs up the map anchor area and moves the kpimg start image to
 *      kernel_pa + start_offset.
 *   4. map_prepare(kernel_pa, delta) — fills base/map.c's map_data, hooks
 *      paging_init with an A32 B to the relocated _paging_init and copies the
 *      whole .map region into the kernel text hole at kernel_pa + map_offset.
 *   5. restore the original 8 entry bytes from setup_preset.header_backup,
 *      D-clean + I-invalidate, hand the bootloader sp back and branch to
 *      kernel_pa (the real kernel entry, MMU still off).
 *   6. later paging_init runs the injected B and jumps into _paging_init,
 *      which does the relocation work and calls base/start.c's start().
 *
 * WHICH UPSTREAM base/setup1.S HELPERS ARE PORTED
 *   memcpy8       yes — byte copy, identical semantics (n <= 0 copies nothing)
 *   rmemcpy32     yes — reverse 32-bit copy, identical loop/semantics
 *   start_prepare yes — one field-for-field port (see start_prepare)
 *   map_prepare   yes — including the A32 B encoding and the real ARMv7
 *                       cache maintenance
 *   setup         yes — A32 register set only (see below)
 *   setup_entry   yes — A32 boot ABI: r0 = 0, r1 = machine id, r2 =
 *                       atags/DTB, r3 unused (port/PORTING_ROADMAP.md §0)
 *   base/map1.S   NOTHING TO PORT: the upstream file is an empty `// todo:`
 *                       placeholder, so it has no A32 counterpart and the
 *                       linker script's `base/map1.o(.text)` simply matches
 *                       nothing.
 *
 * WHAT IS DROPPED FROM UPSTREAM map_prepare, AND WHY
 *   - The A64 "AUTIASP to NOP" scan (`movk w3,#0xD503` / 0xD503211F): ARMv7-A
 *     has no pointer authentication, so an A32 paging_init prologue can never
 *     start with an A64 `autiasp` and there is nothing to neutralise.  The
 *     whole block is A64 encodings, not a portability question.
 *   - `dsb ish` after backing paging_init up, and the final `dsb ish`: a DSB
 *     does not make a written instruction or a copied code region visible to
 *     the I-side.  On A32 that needs DCCIMVAC by MVA + ICIALLU (+ BPIALL for
 *     the pipeline), which is what map_prepare does instead.
 *   - setup's `stp` save/restore of x0..x28: A32 has 13 usable registers and
 *     the only state that must survive the calls is the boot ABI's r0-r3, the
 *     boot sp and kernel_pa/delta.  Those live in r8-r11 / r7 / r5 / r4 and are
 *     callee-saved across the C helpers, so no register frame is needed.
 *
 * POSITION INDEPENDENCE (hard requirement of the port)
 *   No `movw/movt` of a link-time address, no string literal, no GOT/PLT:
 *   `ldr Rt, =sym` is only ever used together with `add Rt, Rt, delta`.  The
 *   one unavoidable link-time word (the anchor) is placed in .text, never in
 *   .entry.text, so .entry.text carries a single PC-relative branch.
 *   A32 reads the PC as instruction address + 8, so the A32 B displacement
 *   computed in map_prepare subtracts 8 (the A64 formula does not) — the same
 *   formula the QEMU-verified kernel/arm/map.c oracle uses.
 *
 * LINKER SCRIPT CONTRACT
 *   .setup.text : base/setup_arm.o(.entry.text) FIRST, then
 *                 base/setup_arm.o(.text), then base/setup.o(.text)
 *   .setup.map  : base/map.o(.map.data), base/map.o(.map.text) AND
 *                 base/map.o(.text).  The last one is not optional: _paging_init
 *                 is emitted into map.o's plain .text (only get_myva carries
 *                 __section(.map.text)), and the relocated _paging_init calls
 *                 get_data/copy_map_data/... which must be copied together with
 *                 it or those PC-relative calls land outside the hole.
 */

#define __ASSEMBLY__
#include "setup.h"
#include "start.h"

    .arm
    .syntax unified

/* ======================================================================== */
/* Entry.  First thing in .setup.text == blob offset 0x1000 == text_offset. */
/* ======================================================================== */
    .section .entry.text, "ax"
    .align 2
    .global setup_entry
    .type setup_entry, %function
setup_entry:
    /* r0..r3 are the ARM boot protocol arguments and must reach the kernel
     * entry unchanged; this stub only advances into the setup flow.  It
     * references no symbol address, so .entry.text needs no absolute
     * relocation at all — just this PC-relative branch. */
    b       setup
    .size setup_entry, .-setup_entry

/* ======================================================================== */
    .text
    .align 2

/* ------------------------------------------------------------------------
 * void memcpy8(void *dst, const void *src, int64_t n)
 *   byte copy, upstream semantics (n <= 0 copies nothing)
 * ---------------------------------------------------------------------- */
    .global memcpy8
    .type memcpy8, %function
memcpy8:
    cmp     r2, #0
    bxle    lr
1:  ldrb    r3, [r1], #1
    strb    r3, [r0], #1
    subs    r2, r2, #1
    bne     1b
    bx      lr
    .size memcpy8, .-memcpy8

/* ------------------------------------------------------------------------
 * void rmemcpy32(void *dst, const void *src, int64_t n)
 *   reverse 32-bit copy: copies the words at n-4, n-8, ... 0 (as upstream)
 * ---------------------------------------------------------------------- */
    .global rmemcpy32
    .type rmemcpy32, %function
rmemcpy32:
    subs    r2, r2, #4
    bmi     2f
1:  ldr     r3, [r1, r2]
    str     r3, [r0, r2]
    subs    r2, r2, #4
    bpl     1b
2:  bx      lr
    .size rmemcpy32, .-rmemcpy32

/* ------------------------------------------------------------------------
 * Copy a 64-bit preset field pair (low word + high word).
 *   A64 keeps these in one 64-bit register; A32 has to move both halves.
 *   The high halves are always 0 for the kernel offsets/pointers carried
 *   here, but they are written explicitly so the C view matches a plain
 *   64-bit assignment.
 * ---------------------------------------------------------------------- */
    .macro CP64 src, soff, dst, doff
    ldr     r9, [\src, #(\soff)]
    ldr     r0, [\src, #(\soff) + 4]
    str     r9, [\dst, #(\doff)]
    str     r0, [\dst, #(\doff) + 4]
    .endm

/* ------------------------------------------------------------------------
 * void start_prepare(uint32_t kernel_pa, uint32_t delta)
 *
 * A32 port of base/setup1.S:start_prepare, field for field.  Writes
 * base/start.c's start_preset (the structure start() reads) from the
 * patcher-written setup_preset, copies the header/superkeys/patch config,
 * backs up the sacrificed map anchor region and moves
 *   [_kp_start, _kp_start + start_img_size + extra_size)
 * to kernel_pa + start_offset with the upstream reverse copy.
 * ---------------------------------------------------------------------- */
    .global start_prepare
    .type start_prepare, %function
start_prepare:
    push    {r4-r11, lr}
    sub     sp, sp, #4                       @ 9 regs + 4 == 8-byte aligned
    mov     r4, r0                           @ kernel_pa
    mov     r8, r1                           @ delta

    ldr     r5, =map_data
    add     r5, r5, r8                       @ runtime &map_data
    ldr     r6, =setup_preset
    add     r6, r6, r8                       @ runtime &setup_preset
    ldr     r7, =start_preset
    add     r7, r7, r8                       @ runtime &start_preset

    /* start_preset.kernel_version = setup_preset.kernel_version (4 bytes) */
    ldr     r9, [r6, #setup_kernel_version_offset]
    str     r9, [r7, #start_kernel_version_offset]

    CP64    r6, setup_kallsyms_lookup_name_offset_offset, r7, start_kallsyms_lookup_name_offset_offset
    CP64    r6, setup_kernel_size_offset,                 r7, start_kernel_size_offset
    CP64    r6, setup_start_offset_offset,                r7, start_start_offset_offset
    ldr     r10, [r6, #setup_start_offset_offset]        @ keep start_offset
    CP64    r6, setup_extra_size_offset,                  r7, start_extra_size_offset
    CP64    r6, setup_map_offset_offset,                  r7, start_map_offset_offset
    ldr     r11, [r6, #setup_map_offset_offset]          @ keep map_offset
    CP64    r6, setup_sprintf_offset_offset,              r7, start_sprintf_offset_offset
    CP64    r6, setup_symbol_lookup_anchor_offset_offset, r7, start_symbol_lookup_anchor_offset_offset
    CP64    r6, setup_kconfig_offset_offset,              r7, start_kconfig_offset_offset
    CP64    r6, setup_kconfig_size_offset,                r7, start_kconfig_size_offset

    /* start_preset.kernel_pa = kernel_pa (uint64_t) */
    str     r4, [r7, #start_kernel_pa_offset]
    mov     r9, #0
    str     r9, [r7, #start_kernel_pa_offset + 4]

    /* memcpy8(&start_preset.header, &header, KP_HEADER_SIZE) */
    add     r0, r7, #start_header_offset
    ldr     r1, =header
    add     r1, r1, r8
    mov     r2, #KP_HEADER_SIZE
    bl      memcpy8

    /* memcpy8(start_preset.superkey, setup_preset.superkey, SUPER_KEY_LEN) */
    ldr     r9, =start_superkey_offset
    add     r0, r7, r9
    add     r1, r6, #setup_superkey_offset
    mov     r2, #SUPER_KEY_LEN
    bl      memcpy8

    /* ... root_superkey (ROOT_SUPER_KEY_HASH_LEN) */
    ldr     r9, =start_root_superkey_offset
    add     r0, r7, r9
    add     r1, r6, #setup_root_superkey_offset
    mov     r2, #ROOT_SUPER_KEY_HASH_LEN
    bl      memcpy8

    /* ... patch_config (PATCH_CONFIG_LEN) */
    ldr     r9, =start_patch_config_offset
    add     r0, r7, r9
    ldr     r9, =setup_patch_config_offset
    add     r1, r6, r9
    mov     r2, #PATCH_CONFIG_LEN
    bl      memcpy8

    /* Backup the map anchor area:
     *   backup_len = max(_map_end - _map_start, setup_preset.map_max_size)
     * kptools NOP-syncs map_max_size bytes at map_offset, so the backup has to
     * cover that as well as the map section copy itself. */
    ldr     r0, =_map_end
    add     r0, r0, r8
    ldr     r1, =_map_start
    add     r1, r1, r8
    sub     r2, r0, r1                       @ map section size
    ldr     r3, [r6, #setup_map_max_size_offset]
    cmp     r2, r3
    movlo   r2, r3                           @ r2 = max(...)
    str     r2, [r7, #start_map_backup_len_offset]
    mov     r0, #0
    str     r0, [r7, #start_map_backup_len_offset + 4]
    add     r0, r7, #start_map_backup_offset
    add     r1, r4, r11                      @ kernel_pa + map_offset
    bl      memcpy8

    /* start_img_size = setup_preset.kpimg_size - (_kp_start - _link_base)
     * (both terms are link-time, so the delta cancels in the subtraction) */
    ldr     r9, [r6, #setup_kpimg_size_offset]
    ldr     r0, =_kp_start
    add     r0, r0, r8
    ldr     r1, =_link_base
    add     r1, r1, r8
    sub     r0, r0, r1                       @ _kp_start - _link_base
    sub     r9, r9, r0                       @ start_img_size
    str     r9, [r5, #map_start_img_size_offset]
    mov     r0, #0
    str     r0, [r5, #map_start_img_size_offset + 4]

    /* rmemcpy32(kernel_pa + start_offset, _kp_start,
     *           start_img_size + setup_preset.extra_size) */
    add     r0, r4, r10                      @ kernel_pa + start_offset
    ldr     r1, =_kp_start
    add     r1, r1, r8                       @ runtime _kp_start
    ldr     r2, [r6, #setup_extra_size_offset]
    add     r2, r2, r9
    bl      rmemcpy32

    add     sp, sp, #4
    pop     {r4-r11, pc}
    .size start_prepare, .-start_prepare
    .ltorg

/* ------------------------------------------------------------------------
 * void map_prepare(uint32_t kernel_pa, uint32_t delta)
 *
 * A32 port of base/setup1.S:map_prepare.  Fills base/map.c's map_data, backs
 * up and rewrites the first instruction of paging_init with an A32 B to the
 * relocated _paging_init, copies the whole .map region into the kernel text
 * hole and makes both visible to the instruction side.
 * ---------------------------------------------------------------------- */
    .global map_prepare
    .type map_prepare, %function
map_prepare:
    push    {r4-r11, lr}
    sub     sp, sp, #4
    mov     r4, r0                           @ kernel_pa
    mov     r8, r1                           @ delta

    ldr     r5, =map_data
    add     r5, r5, r8                       @ runtime &map_data
    ldr     r6, =setup_preset
    add     r6, r6, r8                       @ runtime &setup_preset

    /* map_data.kernel_pa = kernel_pa */
    str     r4, [r5, #map_kernel_pa_offset]
    mov     r9, #0
    str     r9, [r5, #map_kernel_pa_offset + 4]

    /* map_data.kernel_version = setup_preset.kernel_version */
    ldr     r9, [r6, #setup_kernel_version_offset]
    str     r9, [r5, #map_kernel_version_offset]

    /* map_data.map_offset = setup_preset.map_offset (kept in r10) */
    ldr     r10, [r6, #setup_map_offset_offset]
    str     r10, [r5, #map_map_offset_offset]
    mov     r9, #0
    str     r9, [r5, #map_map_offset_offset + 4]

    /* map_data.paging_init_relo = setup_preset.paging_init_offset (kept in r11) */
    ldr     r11, [r6, #setup_paging_init_offset_offset]
    str     r11, [r5, #map_paging_init_relo_offset]
    mov     r9, #0
    str     r9, [r5, #map_paging_init_relo_offset + 4]

    /* map_data.map_symbol = setup_preset.map_symbol */
    add     r0, r5, #map_map_symbol_offset
    add     r1, r6, #setup_map_symbol_offset
    mov     r2, #MAP_SYMBOL_SIZE
    bl      memcpy8

#ifdef MAP_DEBUG
    /* map_data.printk_relo = setup_preset.printk_offset */
    ldr     r9, [r6, #setup_printk_offset_offset]
    str     r9, [r5, #map_printk_relo_offset]
    mov     r9, #0
    str     r9, [r5, #map_printk_relo_offset + 4]
#endif

    /* map_data.start_offset = setup_preset.start_offset */
    ldr     r9, [r6, #setup_start_offset_offset]
    str     r9, [r5, #map_start_offset_offset]
    mov     r0, #0
    str     r0, [r5, #map_start_offset_offset + 4]

    /* map_data.start_size = _kp_end - _kp_start */
    ldr     r0, =_kp_end
    add     r0, r0, r8
    ldr     r1, =_kp_start
    add     r1, r1, r8
    sub     r0, r0, r1
    str     r0, [r5, #map_start_size_offset]
    mov     r0, #0
    str     r0, [r5, #map_start_size_offset + 4]

    /* map_data.extra_size = setup_preset.extra_size */
    ldr     r9, [r6, #setup_extra_size_offset]
    str     r9, [r5, #map_extra_size_offset]
    mov     r0, #0
    str     r0, [r5, #map_extra_size_offset + 4]

    /* map_data.alloc_size = HOOK_ALLOC_SIZE + MEMORY_ROX_SIZE + MEMORY_RW_SIZE
     *                      = (1 << 20) + (4 << 20) + (2 << 20) = 0x700000 */
    ldr     r9, =0x700000
    str     r9, [r5, #map_alloc_size_offset]
    mov     r0, #0
    str     r0, [r5, #map_alloc_size_offset + 4]

    /* Back up paging_init's first instruction (32-bit container). */
    add     r3, r4, r11                      @ paging_init_pa
    ldr     r0, [r3]
    str     r0, [r5, #map_paging_init_backup_offset]
    dsb     sy

    /* replace_offset = (_paging_init - _map_start) + map_offset
     * A32 B: disp = replace_offset - paging_init_offset - 8  (PC = insn + 8)
     *        insn = 0xEA000000 | ((disp >> 2) & 0x00FFFFFF) */
    ldr     r0, =_paging_init
    add     r0, r0, r8
    ldr     r1, =_map_start
    add     r1, r1, r8
    sub     r0, r0, r1                       @ _paging_init - _map_start
    add     r0, r0, r10                      @ + map_offset == replace_offset
    sub     r0, r0, r11                      @ - paging_init_offset
    sub     r0, r0, #8
    asr     r0, r0, #2
    bic     r0, r0, #0xFF000000              @ low 24 bits of disp >> 2
    orr     r0, r0, #0xEA000000              @ A32 B
    str     r0, [r3]

    /* memcpy8(kernel_pa + map_offset, _map_start, _map_end - _map_start)
     *
     * M5-D fix: memcpy8 takes its length in r2 (AAPCS), not r9.  The length
     * is kept in r9 because it must survive the call for the cache loop
     * below, but it has to be moved into r2 as well.  Without this the copy
     * silently reused the previous r2 value (MAP_SYMBOL_SIZE = 56, left over
     * from the map_symbol copy above), so only the first 56 bytes reached the
     * hole: _paging_init stayed behind at its old contents, the paging_init
     * hook branched straight into that stale code (observed as `pop {r4,pc}`
     * + garbage) and the kernel hung silently right after the cma line. */
    ldr     r0, =_map_end
    add     r0, r0, r8
    ldr     r1, =_map_start
    add     r1, r1, r8
    sub     r9, r0, r1                       @ len (r9 survives memcpy8)
    add     r0, r4, r10                      @ dst = kernel_pa + map_offset
    mov     r2, r9                           @ n = len
    bl      memcpy8

    /* Coherency: clean+invalidate the rewritten instruction and the whole
     * copied region to the PoC by MVA, then invalidate the I-cache and the
     * branch predictor so the new code is fetched.  A 16-byte step cannot
     * miss an ARMv7 D-cache line (min DminLine is 4 words). */
    add     r3, r4, r11                      @ paging_init_pa
    mcr     p15, 0, r3, c7, c14, 1           @ DCCIMVAC @ paging_init
    dsb     sy
    add     r3, r4, r10                      @ dst
    add     r2, r3, r9                       @ dst + len
9:  mcr     p15, 0, r3, c7, c14, 1           @ DCCIMVAC per line
    add     r3, r3, #16
    cmp     r3, r2
    blo     9b
    dsb     sy
    mov     r0, #0
    mcr     p15, 0, r0, c7, c5, 0            @ ICIALLU
    mcr     p15, 0, r0, c7, c5, 6            @ BPIALL
    dsb     sy
    isb

    add     sp, sp, #4
    pop     {r4-r11, pc}
    .size map_prepare, .-map_prepare
    .ltorg

/* ------------------------------------------------------------------------
 * void setup(void)
 *
 * Entered from setup_entry with the bootloader's sp and the boot ABI's
 * r0..r3 untouched.
 * ---------------------------------------------------------------------- */
    .global setup
    .type setup, %function
setup:
    /* delta = runtime(.Lanchor) - linktime(.Lanchor) */
    adr     r12, .Lanchor
    ldr     r11, .Lanchor
    sub     r4, r12, r11                     @ r4 = delta

    /* Preserve the boot arguments across the C calls */
    mov     r8, r0
    mov     r9, r1
    mov     r10, r2
    mov     r11, r3

    /* M4b BISECT3: the kernel entry must run on the sp the bootloader set, so
     * the private stack is only used around the setup C helpers. */
    mov     r7, sp                           @ r7 = boot sp
    ldr     r6, =stack
    add     r6, r6, r4                       @ runtime &stack
    add     r6, r6, #STACK_SIZE
    mov     sp, r6

    /* kernel_pa = runtime(_link_base) - setup_preset.setup_offset */
    ldr     r6, =setup_preset
    add     r6, r6, r4
    ldr     r5, [r6, #setup_setup_offset_offset]
    ldr     r6, =_link_base
    add     r6, r6, r4
    sub     r5, r6, r5                       @ r5 = kernel_pa

    mov     r0, r5
    mov     r1, r4
    bl      start_prepare

    mov     r0, r5
    mov     r1, r4
    bl      map_prepare

    /* Restore the original first 8 bytes (header_backup) over the injected B */
    ldr     r0, =setup_preset
    add     r0, r0, r4
    add     r0, r0, #setup_header_backup_offset
    ldr     r1, [r0]
    ldr     r2, [r0, #4]
    str     r1, [r5]
    str     r2, [r5, #4]

    /* D-clean + I-invalidate the restored words, then ICIALLU + BPIALL */
    mcr     p15, 0, r5, c7, c14, 1           @ DCCIMVAC @ kernel_pa
    add     r1, r5, #4
    mcr     p15, 0, r1, c7, c14, 1           @ DCCIMVAC @ kernel_pa + 4
    dsb     sy
    mov     r1, #0
    mcr     p15, 0, r1, c7, c5, 0            @ ICIALLU
    mcr     p15, 0, r1, c7, c5, 6            @ BPIALL
    dsb     sy
    isb

    mov     sp, r7                           @ boot sp back (BISECT3)
    mov     r0, r8
    mov     r1, r9
    mov     r2, r10
    mov     r3, r11
    bx      r5                               @ enter the real kernel entry
    .size setup, .-setup

    .align 2
/* Link-time anchor for the load bias.  It lives in .text on purpose: this one
 * word needs an absolute relocation, and .entry.text is kept relocation-free. */
.Lanchor:
    .word   .Lanchor
    .ltorg