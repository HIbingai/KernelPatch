#ifndef _KP_BARRIER_H_
#define _KP_BARRIER_H_

#ifdef CONFIG_ARM

/*
 * AArch32 (ARMv7-A). ARMv7 has DSB/DMB/ISB but no acquire/release loads
 * (LDAR/STLR are ARMv8-only), so smp_load_acquire/smp_store_release are
 * built from a DMB plus an ordinary access, which is what arch/arm does.
 * The full-system barriers use "sy"; the SMP ones use the inner-shareable
 * domain, matching arch/arm/include/asm/barrier.h.
 */
/*
 * ARMv7 only implements the SY / ST / ISH / ISHST / NSH / NSHST / OSH / OSHST
 * forms of DMB and DSB. The "load-limited" variants (dmb ishld, dmb oshld) and
 * the plain "dsb ld" are ARMv8 additions and do NOT assemble under
 * -march=armv7-a, so the read barriers use the full barrier instead.
 */
#define mb() asm volatile("dsb sy" ::: "memory")
#define wmb() asm volatile("dsb st" ::: "memory")
#define rmb() asm volatile("dsb sy" ::: "memory")

#define smp_mb() asm volatile("dmb ish" ::: "memory")
#define smp_wmb() asm volatile("dmb ishst" ::: "memory")
#define smp_rmb() asm volatile("dmb ish" ::: "memory")

#define dma_wmb() asm volatile("dmb oshst" ::: "memory")
#define dma_rmb() asm volatile("dmb osh" ::: "memory")
#define dma_mb() asm volatile("dmb osh" ::: "memory")

#define smp_store_release(p, v) \
    do {                        \
        smp_mb();               \
        *(p) = (v);             \
    } while (0)

#define smp_load_acquire(p)      \
    ({                           \
        typeof(*(p)) __v = *(p); \
        smp_mb();                \
        __v;                     \
    })

/* ARMv7 has no single instruction for a release store; use DMB + store. */
#define __smp_store_release(p, v) smp_store_release(p, v)
#define __smp_load_acquire(p) smp_load_acquire(p)

#elif defined(CONFIG_X86_64)

#define mb()  asm volatile("mfence" ::: "memory")
#define wmb() asm volatile("sfence" ::: "memory")
#define rmb() asm volatile("lfence" ::: "memory")

#define smp_mb()  mb()
#define smp_wmb() wmb()
#define smp_rmb() rmb()

#define smp_store_release(p, v)   \
    do {                          \
        barrier();                \
        *(p) = (v);               \
    } while (0)

#define smp_load_acquire(p)       \
    ({                            \
        typeof(*(p)) __v = *(p);  \
        barrier();                \
        __v;                      \
    })

#else /* ARM64 */

#define mb() asm volatile("dmb ish" ::: "memory")
#define wmb() asm volatile("dmb ishst" ::: "memory")
#define rmb() asm volatile("dmb ishld" ::: "memory")

/*
 * Kernel uses dmb variants on arm64 for smp_*() barriers. Pretty much the same
 * implementation as above mb()/wmb()/rmb(), though for the latter kernel uses
 * dsb. In any case, should above mb()/wmb()/rmb() change, make sure the below
 * smp_*() don't.
 */
#define smp_mb() asm volatile("dmb ish" ::: "memory")
#define smp_wmb() asm volatile("dmb ishst" ::: "memory")
#define smp_rmb() asm volatile("dmb ishld" ::: "memory")

#define smp_store_release(p, v)                                                         \
    do {                                                                                \
        union                                                                           \
        {                                                                               \
            typeof(*p) __val;                                                           \
            char __c[1];                                                                \
        } __u = { .__val = (v) };                                                       \
        compiletime_assert_atomic_type(*p);                                             \
                                                                                        \
        switch (sizeof(*p)) {                                                           \
        case 1:                                                                         \
            asm volatile("stlrb %w1, %0" : "=Q"(*p) : "r"(*(u8 *)__u.__c) : "memory");  \
            break;                                                                      \
        case 2:                                                                         \
            asm volatile("stlrh %w1, %0" : "=Q"(*p) : "r"(*(u16 *)__u.__c) : "memory"); \
            break;                                                                      \
        case 4:                                                                         \
            asm volatile("stlr %w1, %0" : "=Q"(*p) : "r"(*(u32 *)__u.__c) : "memory");  \
            break;                                                                      \
        case 8:                                                                         \
            asm volatile("stlr %1, %0" : "=Q"(*p) : "r"(*(u64 *)__u.__c) : "memory");   \
            break;                                                                      \
        default:                                                                        \
            /* Only to shut up gcc ... */                                               \
            mb();                                                                       \
            break;                                                                      \
        }                                                                               \
    } while (0)

#define smp_load_acquire(p)                                                             \
    ({                                                                                  \
        union                                                                           \
        {                                                                               \
            typeof(*p) __val;                                                           \
            char __c[1];                                                                \
        } __u = { .__c = { 0 } };                                                       \
        compiletime_assert_atomic_type(*p);                                             \
                                                                                        \
        switch (sizeof(*p)) {                                                           \
        case 1:                                                                         \
            asm volatile("ldarb %w0, %1" : "=r"(*(u8 *)__u.__c) : "Q"(*p) : "memory");  \
            break;                                                                      \
        case 2:                                                                         \
            asm volatile("ldarh %w0, %1" : "=r"(*(u16 *)__u.__c) : "Q"(*p) : "memory"); \
            break;                                                                      \
        case 4:                                                                         \
            asm volatile("ldar %w0, %1" : "=r"(*(u32 *)__u.__c) : "Q"(*p) : "memory");  \
            break;                                                                      \
        case 8:                                                                         \
            asm volatile("ldar %0, %1" : "=r"(*(u64 *)__u.__c) : "Q"(*p) : "memory");   \
            break;                                                                      \
        default:                                                                        \
            /* Only to shut up gcc ... */                                               \
            mb();                                                                       \
            break;                                                                      \
        }                                                                               \
        __u.__val;                                                                      \
    })

#endif /* CONFIG_ARM / CONFIG_X86_64 / ARM64 */

#endif