/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <kp_spinlock.h>

#include <asm/cmpxchg.h>

static inline bool kp_native_spin_irq_pair_available(void)
{
    return kfunc(_raw_spin_lock_irqsave) && kfunc(_raw_spin_unlock_irqrestore);
}

static inline unsigned long kp_local_irq_save(void)
{
    unsigned long flags;

#if defined(CONFIG_ARM)
    /* AArch32: no DAIF register.  Save CPSR, then mask IRQ only (`cpsid i`
     * clears CPSR.I) -- the AArch32 counterpart of arm64's `daifset, #2`. */
    asm volatile("mrs %0, cpsr\n\t"
                 "cpsid i"
                 : "=r"(flags)
                 :
                 : "memory");
#elif defined(CONFIG_X86_64)
    asm volatile("pushfq\n\t"
                 "popq %0\n\t"
                 "cli"
                 : "=r"(flags)
                 :
                 : "memory");
#else
    asm volatile("mrs %0, daif\n\t"
                 "msr daifset, #2"
                 : "=r"(flags)
                 :
                 : "memory");
#endif
    return flags;
}

static inline void kp_local_irq_restore(unsigned long flags)
{
#if defined(CONFIG_ARM)
    /* Restore the CPSR control byte (mode + I/F), as mainline arch/arm
     * arch_local_irq_restore() does; condition flags stay untouched. */
    asm volatile("msr cpsr_c, %0" : : "r"(flags) : "memory");
#elif defined(CONFIG_X86_64)
    asm volatile("pushq %0\n\t"
                 "popfq"
                 :
                 : "r"(flags)
                 : "memory", "cc");
#else
    asm volatile("msr daif, %0" : : "r"(flags) : "memory");
#endif
}

static inline void kp_local_raw_spin_lock(raw_spinlock_t *lock)
{
    while (cmpxchg(&lock->raw_lock.counter, 0, 1) != 0) {
        while (__atomic_load_n(&lock->raw_lock.counter, __ATOMIC_RELAXED))
            asm volatile("yield" ::: "memory");
    }
}

static inline void kp_local_raw_spin_unlock(raw_spinlock_t *lock)
{
    smp_store_release(&lock->raw_lock.counter, 0);
}

unsigned long kp_private_spin_lock(spinlock_t *lock)
{
    raw_spinlock_t *raw_lock = &lock->rlock;
    unsigned long flags;

    if (likely(kp_native_spin_irq_pair_available()))
        return kfunc(_raw_spin_lock_irqsave)(raw_lock);

    /* Target preempt-count layouts vary, so the local fallback masks IRQs instead. */
    flags = kp_local_irq_save();
    kp_local_raw_spin_lock(raw_lock);
    return flags;
}

void kp_private_spin_unlock(spinlock_t *lock, unsigned long flags)
{
    raw_spinlock_t *raw_lock = &lock->rlock;

    if (likely(kp_native_spin_irq_pair_available())) {
        kfunc(_raw_spin_unlock_irqrestore)(raw_lock, flags);
        return;
    }

    kp_local_raw_spin_unlock(raw_lock);
    kp_local_irq_restore(flags);
}
