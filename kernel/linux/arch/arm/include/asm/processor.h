/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AArch32 (ARMv7-A) processor.h.
 *
 * Mirrors linux/arch/arm64/include/asm/processor.h of this port (which is in
 * turn based on arch/arm/include/asm/processor.h).  The actual pt_regs
 * placement is probed at runtime on AArch32 (`pt_regs_offset`), so
 * task_pt_regs() forwards to _task_pt_reg() in patch/common/utils.c.
 */
#ifndef __ASM_PROCESSOR_H
#define __ASM_PROCESSOR_H

#include <asm/current.h>
#include <asm/ptrace.h>

#define task_stack_page(task) (get_stack(task))

extern int16_t pt_regs_offset;

struct pt_regs *_task_pt_reg(struct task_struct *task);

#define task_pt_regs(p) _task_pt_reg(p)

#endif