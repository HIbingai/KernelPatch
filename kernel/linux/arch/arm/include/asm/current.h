/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AArch32 (ARMv7-A) current.h — port of the port's arm64 current.h.
 *
 * The arm64 version has two ways to reach `current`: SP_EL0 (when it holds the
 * task pointer) or the thread_info at the base of the kernel stack. AArch32 has
 * the same two shapes:
 *
 *   - CONFIG_THREAD_INFO_IN_TASK=y : the task pointer lives in TPIDRPRW
 *     (CP15 c13, c0, 3), which the kernel sets on context switch.
 *   - otherwise                    : thread_info sits at the base of the
 *     kernel stack, and current == thread_info->task.
 *
 * As on arm64 the choice is a *runtime* probe, because the same kpimg has to
 * work on kernels built either way. `tpidrprw_is_current` and the offset
 * variables are filled in by predata.c.
 */
#ifndef __ASM_CURRENT_H
#define __ASM_CURRENT_H

#include <stdint.h>
#include <stdbool.h>
#include <compiler.h>
#include <pgtable.h>

struct task_struct;
struct thread_info;
struct task_ext;

#define THREAD_SIZE 8192

extern int thread_size;              /* actual kernel stack size */
extern int thread_info_in_task;      /* thread_info embedded in task_struct */
extern int tpidrprw_is_current;      /* TPIDRPRW holds the task pointer */
extern int task_in_thread_info_offset;
extern int stack_in_task_offset;
extern int stack_end_offset;

register uint32_t current_stack_pointer asm("sp");

/* CP15 c13, c0, 3 == TPIDRPRW on ARMv7 (privileged write, always readable). */
static inline uint32_t read_tpidrprw(void)
{
    uint32_t v;
    asm volatile("mrc p15, 0, %0, c13, c0, 3" : "=r"(v));
    return v;
}

static inline void write_tpidrprw(uint32_t v)
{
    asm volatile("mcr p15, 0, %0, c13, c0, 3" ::"r"(v) : "memory");
}

static __always_inline struct thread_info *current_thread_info_sp(void)
{
    return (struct thread_info *)(current_stack_pointer & ~(thread_size - 1));
}

static inline struct thread_info *current_thread_info(void)
{
    if (thread_info_in_task) return (struct thread_info *)read_tpidrprw();
    return current_thread_info_sp();
}

static inline struct task_struct *get_current(void)
{
    if (tpidrprw_is_current) return (struct task_struct *)read_tpidrprw();
    uint32_t addr = (uint32_t)current_thread_info() + task_in_thread_info_offset;
    return *(struct task_struct **)addr;
}
#define current get_current()

static inline unsigned long *get_stack(const struct task_struct *task)
{
    uint32_t addr = (uint32_t)task + stack_in_task_offset;
    return *(unsigned long **)addr;
}

static inline unsigned long *end_of_stack(const struct task_struct *task)
{
    unsigned long sp_end = (unsigned long)get_stack(task);
    sp_end = sp_end + stack_end_offset;
    return (unsigned long *)sp_end;
}

static inline unsigned long *get_current_stack(void)
{
    return get_stack(current);
}

struct task_ext *kf_get_task_ext(const struct task_struct *task);
struct task_ext *kf_task_ext_ensure(struct task_struct *task);

static inline struct task_ext *get_task_ext(const struct task_struct *task)
{
    return kf_get_task_ext(task);
}

static inline struct task_ext *get_current_task_ext(void)
{
    return get_task_ext(current);
}

static inline struct thread_info *get_task_thread_info(const struct task_struct *task)
{
    if (thread_info_in_task) return (struct thread_info *)task;
    return (struct thread_info *)get_stack(task);
}

#define current_ext get_current_task_ext()

static inline const struct task_struct *override_current(struct task_struct *task)
{
    if (tpidrprw_is_current) {
        uint32_t old = read_tpidrprw();
        write_tpidrprw((uint32_t)task);
        return (struct task_struct *)old;
    }
    uint32_t addr = (uint32_t)current_thread_info() + task_in_thread_info_offset;
    struct task_struct *old = *(struct task_struct **)addr;
    *(struct task_struct **)addr = (struct task_struct *)task;
    return old;
}

static inline void revert_current(const struct task_struct *old)
{
    if (tpidrprw_is_current) {
        write_tpidrprw((uint32_t)old);
        return;
    }
    uint32_t addr = (uint32_t)current_thread_info() + task_in_thread_info_offset;
    *(struct task_struct **)addr = (struct task_struct *)old;
}

#endif /* __ASM_CURRENT_H */
