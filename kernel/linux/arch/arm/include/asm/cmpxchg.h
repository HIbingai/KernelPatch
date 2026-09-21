/*
 * AArch32 (ARMv7-A, non-LPAE) cmpxchg/xchg.
 *
 * Based on arch/arm64/include/asm/cmpxchg.h, which is itself based on
 * arch/arm/include/asm/cmpxchg.h.
 *
 * The AArch64 exclusives used there (ldxr/stxr, ldxrb/stlxrb, ldxrh/stlxrh)
 * have no AArch32 encoding; the ARMv7-A equivalents used here are
 *
 *     ldrex/strex    word (32 bit)
 *     ldrexb/strexb  byte
 *     ldrexh/strexh  halfword
 *
 * AArch32 has no LDAR/STLR, so acquire/release ordering comes from the
 * DMB-based smp_mb() in <asm/barrier.h> (the KP CONFIG_ARM branch): the
 * aarch64 version gets the release half from stlxr and the acquire half from
 * ldaxr, here a full smp_mb() is issued on both sides of the operation.  Every
 * operation is replayed until the exclusive store is accepted by the monitor.
 *
 * 64-bit note -- ARMv7-A *without* LPAE:
 *   There is no 64-bit exclusive access that is safe to depend on for this
 *   target, so the 8-byte entry points (xchg() of a 64-bit object and
 *   cmpxchg64()) are deliberately implemented as NON-ATOMIC fallbacks and are
 *   documented as such.  Nothing in this port relies on them: `atomic64_t` is
 *   `{ long counter; }` and AArch32 `long` is 32 bits (see <ktypes.h>), so all
 *   atomic64_* helpers are single-word operations.  The 64-bit entry points
 *   exist only so that generic kernel headers keep compiling.  Choosing the
 *   fallback over ldrexd/strexd also matches mainline arch/arm, which selects
 *   GENERIC_ATOMIC64 instead of a 64-bit exclusive loop for 32-bit ARM.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ASM_CMPXCHG_H
#define __ASM_CMPXCHG_H

#include <asm/barrier.h>
#include <ktypes.h>

/*
 * __xchg() for 1/2/4-byte objects.  Returns the previous value of *ptr.
 * The 8-byte case is not handled here because an `unsigned long` result
 * cannot carry it on AArch32; xchg() below routes that size elsewhere.
 */
static inline unsigned long __xchg(unsigned long x, volatile void *ptr, int size)
{
    unsigned long ret, tmp;

    switch (size) {
    case 1:
        asm volatile("//	__xchg1\n"
                     "1:	ldrexb	%0, [%2]\n"
                     "	strexb	%1, %3, [%2]\n"
                     "	teq	%1, #0\n"
                     "	bne	1b"
                     : "=&r"(ret), "=&r"(tmp)
                     : "r"(ptr), "r"(x)
                     : "cc", "memory");
        break;
    case 2:
        asm volatile("//	__xchg2\n"
                     "1:	ldrexh	%0, [%2]\n"
                     "	strexh	%1, %3, [%2]\n"
                     "	teq	%1, #0\n"
                     "	bne	1b"
                     : "=&r"(ret), "=&r"(tmp)
                     : "r"(ptr), "r"(x)
                     : "cc", "memory");
        break;
    case 4:
        asm volatile("//	__xchg4\n"
                     "1:	ldrex	%0, [%2]\n"
                     "	strex	%1, %3, [%2]\n"
                     "	teq	%1, #0\n"
                     "	bne	1b"
                     : "=&r"(ret), "=&r"(tmp)
                     : "r"(ptr), "r"(x)
                     : "cc", "memory");
        break;
    default:
        /* 8-byte requests are handled by the non-atomic path in xchg(). */
        ret = 0;
        break;
    }

    smp_mb();
    return ret;
}

/*
 * 8-byte exchange -- NON-ATOMIC, see the 64-bit note at the top of the file.
 * Kept in a u64-typed helper so the full 64 bits survive on AArch32.
 */
static inline u64 __xchg64_nonatomic(u64 x, volatile void *ptr)
{
    u64 old;

    old = *(volatile u64 *)ptr;
    *(volatile u64 *)ptr = x;
    smp_mb();
    return old;
}

#define xchg(ptr, x)                                                             \
    ({                                                                           \
        __typeof__(*(ptr)) __ret;                                                \
        __ret = (__typeof__(*(ptr)))__builtin_choose_expr(                        \
            sizeof(*(ptr)) == 8, __xchg64_nonatomic((u64)(x), (ptr)),             \
            (u64)__xchg((unsigned long)(x), (ptr), sizeof(*(ptr))));              \
        __ret;                                                                   \
    })

/*
 * __cmpxchg() for 1/2/4-byte objects.  Returns the value read before the
 * store was attempted; the caller compares it against `old`.  All three
 * widths use the same shape: load exclusive, clear the result, compare, and
 * store exclusively only when the comparison matched.
 */
static inline unsigned long __cmpxchg(volatile void *ptr, unsigned long old, unsigned long new, int size)
{
    unsigned long oldval = 0, res;

    switch (size) {
    case 1:
        do {
            asm volatile("// __cmpxchg1\n"
                         "	ldrexb	%1, [%2]\n"
                         "	mov	%0, #0\n"
                         "	teq	%1, %3\n"
                         "	strexbeq	%0, %4, [%2]\n"
                         : "=&r"(res), "=&r"(oldval)
                         : "r"(ptr), "Ir"(old), "r"(new)
                         : "cc", "memory");
        } while (res);
        break;

    case 2:
        do {
            asm volatile("// __cmpxchg2\n"
                         "	ldrexh	%1, [%2]\n"
                         "	mov	%0, #0\n"
                         "	teq	%1, %3\n"
                         "	strexheq	%0, %4, [%2]\n"
                         : "=&r"(res), "=&r"(oldval)
                         : "r"(ptr), "Ir"(old), "r"(new)
                         : "cc", "memory");
        } while (res);
        break;

    case 4:
        do {
            asm volatile("// __cmpxchg4\n"
                         "	ldrex	%1, [%2]\n"
                         "	mov	%0, #0\n"
                         "	teq	%1, %3\n"
                         "	strexeq	%0, %4, [%2]\n"
                         : "=&r"(res), "=&r"(oldval)
                         : "r"(ptr), "Ir"(old), "r"(new)
                         : "cc", "memory");
        } while (res);
        break;

    default:
        /* 8-byte requests are handled by the non-atomic path in cmpxchg64(). */
        break;
    }

    return oldval;
}

static inline unsigned long __cmpxchg_mb(volatile void *ptr, unsigned long old, unsigned long new, int size)
{
    unsigned long ret;

    smp_mb();
    ret = __cmpxchg(ptr, old, new, size);
    smp_mb();

    return ret;
}

#define cmpxchg(ptr, o, n)                                                                                       \
    ({                                                                                                           \
        __typeof__(*(ptr)) __ret;                                                                                \
        __ret = (__typeof__(*(ptr)))__cmpxchg_mb((ptr), (unsigned long)(o), (unsigned long)(n), sizeof(*(ptr))); \
        __ret;                                                                                                   \
    })

#define cmpxchg_local(ptr, o, n)                                                                              \
    ({                                                                                                        \
        __typeof__(*(ptr)) __ret;                                                                             \
        __ret = (__typeof__(*(ptr)))__cmpxchg((ptr), (unsigned long)(o), (unsigned long)(n), sizeof(*(ptr))); \
        __ret;                                                                                                \
    })

/*
 * 64-bit compare-and-exchange -- NON-ATOMIC, see the 64-bit note at the top.
 * The read-compare-write sequence is not indivisible; it is only correct for
 * single-threaded use and is provided for API completeness.
 */
static inline u64 __cmpxchg64_nonatomic(volatile void *ptr, u64 old, u64 new)
{
    u64 oldval;

    oldval = *(volatile u64 *)ptr;
    if (oldval == old)
        *(volatile u64 *)ptr = new;
    smp_mb();
    return oldval;
}

#define cmpxchg64(ptr, o, n)                                                          \
    ({                                                                                \
        __typeof__(*(ptr)) __ret;                                                     \
        smp_mb();                                                                      \
        __ret = (__typeof__(*(ptr)))__cmpxchg64_nonatomic((ptr), (u64)(o), (u64)(n));  \
        smp_mb();                                                                      \
        __ret;                                                                         \
    })

#define cmpxchg64_local(ptr, o, n)                                                    \
    ({                                                                                \
        __typeof__(*(ptr)) __ret;                                                     \
        __ret = (__typeof__(*(ptr)))__cmpxchg64_nonatomic((ptr), (u64)(o), (u64)(n));  \
        __ret;                                                                         \
    })

#define cmpxchg64_relaxed(ptr, o, n) cmpxchg64_local((ptr), (o), (n))

#endif /* __ASM_CMPXCHG_H */
