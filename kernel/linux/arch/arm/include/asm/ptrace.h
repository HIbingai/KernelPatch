/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AArch32 (ARMv7-A) ptrace.h.
 *
 * Unlike arm64 -- which needs one struct pt_regs layout per kernel generation
 * (lt4419 / lt4140 / lt5100) and picks between them at runtime -- the AArch32
 * layout has been a single stable array of 18 32-bit words since forever:
 *
 *   uregs[0..15] = r0..r15 (r13=sp, r14=lr, r15=pc)
 *   uregs[16]    = CPSR
 *   uregs[17]    = ORIG_r0 (syscall argument 0)
 *
 * so there is exactly one definition to port.
 */
#ifndef __ASM_PTRACE_H
#define __ASM_PTRACE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * 18 * 4 bytes == 72.  The arm64 spellings (regs[] / syscallno / orig_x0 /
 * pstate) and the native AArch32 spellings alias the *same* storage, so the
 * patch layer needs no CONFIG_ARM fork:
 *
 *   regs[N]   == uregs[N]     r0..r15
 *   syscallno == uregs[7]     AArch32 EABI puts the syscall number in r7,
 *                             arm64 puts it in x8 (== regs[8]) -- consumers
 *                             that index regs[8] must be CONFIG_ARM aware.
 *   orig_x0   == uregs[17]    ARM_ORIG_r0, saved r0 across the syscall
 *   pstate    == uregs[16]    CPSR
 */
struct pt_regs {
    union {
        unsigned long uregs[18];          /* native AArch32 naming        */
        unsigned long regs[18];           /* arm64: regs[0..15] == r0..r15 */
        struct {
            unsigned long arm_r0_r6[7];   /* uregs[0..6]                  */
            union {
                long syscallno;           /* EABI: r7 == uregs[7]         */
                unsigned long arm_r7;
            };
            unsigned long arm_r8_r12[5];  /* uregs[8..12]                 */
            union { unsigned long sp;     unsigned long arm_r13; };
            union { unsigned long lr;     unsigned long arm_r14; };
            union { unsigned long pc;     unsigned long arm_r15; };
            union { unsigned long pstate; unsigned long arm_cpsr; };
            unsigned long orig_x0;        /* == uregs[17]                 */
        };
    };
};

#define ARM_r0 uregs[0]
#define ARM_r1 uregs[1]
#define ARM_r2 uregs[2]
#define ARM_r3 uregs[3]
#define ARM_r4 uregs[4]
#define ARM_r5 uregs[5]
#define ARM_r6 uregs[6]
#define ARM_r7 uregs[7]
#define ARM_r8 uregs[8]
#define ARM_r9 uregs[9]
#define ARM_r10 uregs[10]
#define ARM_fp uregs[11]
#define ARM_ip uregs[12]
#define ARM_sp uregs[13]
#define ARM_lr uregs[14]
#define ARM_pc uregs[15]
#define ARM_cpsr uregs[16]
#define ARM_ORIG_r0 uregs[17]

#define PSR_T_BIT 0x00000020
#define PSR_F_BIT 0x00000040
#define PSR_I_BIT 0x00000080
#define PSR_A_BIT 0x00000100
#define PSR_E_BIT 0x00000200
#define PSR_J_BIT 0x01000000
#define PSR_Q_BIT 0x08000000
#define PSR_V_BIT 0x10000000
#define PSR_C_BIT 0x20000000
#define PSR_Z_BIT 0x40000000
#define PSR_N_BIT 0x80000000

#define PSR_MODE_MASK 0x0000001f
#define PSR_MODE_USR 0x00000010
#define PSR_MODE_FIQ 0x00000011
#define PSR_MODE_IRQ 0x00000012
#define PSR_MODE_SVC 0x00000013
#define PSR_MODE_MON 0x00000016
#define PSR_MODE_ABT 0x00000017
#define PSR_MODE_HYP 0x0000001a
#define PSR_MODE_UND 0x0000001b
#define PSR_MODE_SYS 0x0000001f

#define user_mode(regs) (((regs)->ARM_cpsr & PSR_MODE_MASK) == PSR_MODE_USR)

#define MAX_REG_OFFSET offsetof(struct pt_regs, ARM_pc)

static inline bool in_syscall(struct pt_regs const *regs)
{
    return true;
}

static inline void forget_syscall(struct pt_regs *regs)
{
    regs->ARM_ORIG_r0 = ~0UL;
}

static inline unsigned long user_stack_pointer(struct pt_regs *regs)
{
    return regs->ARM_sp;
}

#endif /* __ASM_PTRACE_H */