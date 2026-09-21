/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * KernelPatch AArch32 (ARMv7-A) port — forced-include visibility policy.
 *
 * WHY THIS FILE EXISTS (do not delete, do not inline it "for tidiness")
 * ---------------------------------------------------------------
 * The A32 blob is linked at _link_base (0xd000) but its .kp.text/.kp.data are
 * copied at boot to a *runtime* address.  Everything that ends up in the blob
 * therefore has to be position independent, and ONE specific expression depends
 * on that for correctness rather than performance:
 *
 *     base/start.c:  runtime_base_addr = (unsigned long)_link_base;
 *
 * `_link_base` is a *section* symbol (nm reports it as `D`, not `A`), so with
 * PC-relative codegen this expression yields _link_base's RUNTIME address — the
 * single value link2runtime() needs:
 *
 *     include/symbol.h: addr - link_base_addr + runtime_base_addr
 *
 * With -fno-pic the literal pool bakes the link-time constant 0xd000 into that
 * expression, runtime_base_addr ends up equal to link_base_addr, and
 * link2runtime() silently degenerates to the identity.  The 161 link addresses
 * in `.kp.symbol` (fixed by symbol_init()) and the 703 in `.data.rel.local`
 * (fixed by syscall_init()) then stay unfixed and the kernel faults on a low
 * virtual address.  AArch64 never hit this: `adrp/add` is PC-relative by
 * construction, so (uint64_t)_link_base is already the runtime address there.
 *
 * NOTE: -fvisibility=hidden ALONE IS NOT ENOUGH.  Measured on base/start.c:
 *   -fPIC                              -> 55 GOT_BREL + 7 BASE_PREL   (creates .got)
 *   -fPIC -fvisibility=hidden          ->  7 GOT_BREL + 2 BASE_PREL   (still .got)
 *   -fPIC -fvisibility=hidden + this   -> 88 REL32 + 42 CALL + ABS32, 0 GOT
 * Only hiding the *declarations themselves* (which is what the pragma below
 * does, before any header declares anything) lets GCC resolve KP's own globals
 * to plain `add rX, pc, rY`.  Otherwise `ld` stops the build with
 * "Unexpected GOT/PLT entries detected!" from kpimg-arm-full.lds.
 *
 * Applied only to the full-port rules (ARM_FULL_CFLAGS) in Makefile.arm, so the
 * frozen M4b oracle target `kpimg-arm` is unaffected.
 */

#ifndef __ASSEMBLY__
#pragma GCC visibility push(hidden)
#endif