/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AArch32 (ARMv7-A) thread_info.h.
 *
 * Only arch/arm64 is vendored in this port, but the patch layer still needs
 * `struct thread_info` to type-check under CONFIG_ARM:
 *
 *   - patch/common/accctl.c:  current_thread_info()->flags,
 *                             get_task_thread_info(task)->flags
 *   - linux/include/linux/uaccess.h: get_fs() == current_thread_info()->addr_limit
 *   - linux/include/linux/thread_info.h: #include <asm/thread_info.h>
 *   - patch/android/sepolicy_flags.c: #include <asm/thread_info.h>
 *
 * The layout mirrors mainline arch/arm/include/asm/thread_info.h: flags at
 * offset 0, preempt_count at 4, addr_limit at 8 and the task pointer at 12.
 * Those prefixes are what patch/ksyms/task_cred.c probes at runtime (see
 * task_in_thread_info_offset) and what makes the ->flags / ->addr_limit
 * accesses above land on the real fields of an AArch32 kernel's thread_info.
 *
 * The rest of the upstream struct (cpu_context, tp_value, vfp/iwmmxt state,
 * ...) is deliberately not modelled: no code in the patch layer dereferences
 * those members, and the real kernel's offsets are discovered at runtime rather
 * than assumed at compile time.
 *
 * As in mainline ARM32, <asm/current.h> is included at the *end*: current.h
 * forward-declares `struct thread_info` and owns THREAD_SIZE,
 * current_thread_info() and friends, so pulling it in last lets consumers use
 * both halves with no circular include.
 */
#ifndef __ASM_THREAD_INFO_H
#define __ASM_THREAD_INFO_H

struct task_struct;

typedef unsigned long mm_segment_t;

/*
 * Thread information flags.
 *
 * NOTE: these are the *AArch32* bit numbers, which differ from arm64 (e.g.
 * TIF_SECCOMP is 7 here, 11 there).  accctl.c clears _TIF_SECCOMP in the
 * running task's flags, so the numbering must match the 32-bit kernel this
 * kpimg is injected into -- not the arm64 lineage of this port.
 */
#define TIF_SIGPENDING 0 /* signal pending */
#define TIF_NEED_RESCHED 1 /* rescheduling necessary */
#define TIF_NOTIFY_RESUME 2 /* callback before returning to user */
#define TIF_UPROBE 3 /* breakpointed or singlestepping */
#define TIF_SYSCALL_TRACE 4 /* syscall trace active */
#define TIF_SYSCALL_AUDIT 5 /* syscall auditing active */
#define TIF_SYSCALL_TRACEPOINT 6 /* syscall tracepoint instrumentation */
#define TIF_SECCOMP 7 /* seccomp syscall filtering active */
#define TIF_SYSCALL_EMU 8 /* syscall emulation active */
#define TIF_NOTIFY_SIGNAL 9 /* signal notifications exist */
#define TIF_USING_IWMMXT 17 /* iWMMXt context in use */
#define TIF_MEMDIE 18 /* is terminating due to OOM killer */
#define TIF_RESTORE_SIGMASK 20 /* restore signal mask in do_signal() */

#define _TIF_SIGPENDING (1 << TIF_SIGPENDING)
#define _TIF_NEED_RESCHED (1 << TIF_NEED_RESCHED)
#define _TIF_NOTIFY_RESUME (1 << TIF_NOTIFY_RESUME)
#define _TIF_UPROBE (1 << TIF_UPROBE)
#define _TIF_SYSCALL_TRACE (1 << TIF_SYSCALL_TRACE)
#define _TIF_SYSCALL_AUDIT (1 << TIF_SYSCALL_AUDIT)
#define _TIF_SYSCALL_TRACEPOINT (1 << TIF_SYSCALL_TRACEPOINT)
#define _TIF_SECCOMP (1 << TIF_SECCOMP)
#define _TIF_SYSCALL_EMU (1 << TIF_SYSCALL_EMU)
#define _TIF_NOTIFY_SIGNAL (1 << TIF_NOTIFY_SIGNAL)
#define _TIF_USING_IWMMXT (1 << TIF_USING_IWMMXT)
#define _TIF_MEMDIE (1 << TIF_MEMDIE)
#define _TIF_RESTORE_SIGMASK (1 << TIF_RESTORE_SIGMASK)

#define _TIF_WORK_MASK \
    (_TIF_SIGPENDING | _TIF_NEED_RESCHED | _TIF_NOTIFY_RESUME | _TIF_UPROBE | _TIF_NOTIFY_SIGNAL)

#define _TIF_SYSCALL_WORK \
    (_TIF_SYSCALL_TRACE | _TIF_SYSCALL_AUDIT | _TIF_SYSCALL_TRACEPOINT | _TIF_SECCOMP | _TIF_SYSCALL_EMU)

/*
 * Low level task data needed by the patch layer.  Prefix matches AArch32
 * mainline so that field offsets line up with the injected kernel.
 */
struct thread_info
{
    unsigned long flags; /* low level flags */
    int preempt_count; /* 0 => preemptable, <0 => bug */
    mm_segment_t addr_limit; /* address limit */
    struct task_struct *task; /* main task structure */
};

/* current.h owns the real (constant) definition; keep this identical. */
#ifndef THREAD_SIZE
#define THREAD_SIZE 8192
#endif

#define test_ti_thread_flag(ti, flag) (!!((ti)->flags & (1UL << (flag))))
#define set_ti_thread_flag(ti, flag) ((ti)->flags |= (1UL << (flag)))
#define clear_ti_thread_flag(ti, flag) ((ti)->flags &= ~(1UL << (flag)))

#define test_thread_flag(tif) test_ti_thread_flag(current_thread_info(), tif)
#define set_thread_flag(tif) set_ti_thread_flag(current_thread_info(), tif)
#define clear_thread_flag(tif) clear_ti_thread_flag(current_thread_info(), tif)

#include <asm/current.h>

#endif /* __ASM_THREAD_INFO_H */
