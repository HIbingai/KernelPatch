/*
 * AArch32 (ARMv7-A, non-LPAE) atomic operations.
 *
 * Based on arch/arm64/include/asm/atomic.h, which is based on
 * arch/arm/include/asm/atomic.h.
 *
 * The AArch64 load/store-exclusive forms (ldxr/stxr, ldxrb/stxrb) are
 * replaced with the ARMv7-A ones (ldrex/strex, ldrexb/strexb, ldrexh/strexh).
 * Because AArch32 has no acquire/release loads or stores (LDAR/STLR are
 * ARMv8-only), the ordering that stlxr provides on arm64 is supplied here by
 * an explicit smp_mb() after the exclusive store, and __atomic_add_unless()
 * relies on atomic_cmpxchg()'s full barriers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ASM_ATOMIC_H
#define __ASM_ATOMIC_H

#include <asm/barrier.h>
#include <asm/cmpxchg.h>
#include <linux/compiler.h>

/* Provided by linux/include/linux/compiler.h in the full build. */
#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#endif

/*
 * <ktypes.h> already defines ATOMIC_INIT identically; keep the arm64 spelling
 * for any translation unit that somehow reaches this header first.
 */
#ifndef ATOMIC_INIT
#define ATOMIC_INIT(i) \
    {                  \
        (i)            \
    }
#endif

/*
 * On ARM, ordinary assignment (str instruction) doesn't clear the local
 * strex/ldrex monitor on some implementations. The reason we can use it for
 * atomic_set() is the clrex or dummy strex done on every exception return.
 */
#define atomic_read(v) ACCESS_ONCE((v)->counter)
#define atomic_set(v, i) (((v)->counter) = (i))

/*
 * ARMv7-A UP and SMP safe atomic ops.  We use load exclusive and
 * store exclusive to ensure that these are atomic.  We may loop
 * to ensure that the update happens.
 *
 * `"+Qo"(v->counter)` lets the compiler pick either a single base register
 * memory operand (Q) or an offsettable one (o) for the exclusive address,
 * which is what arch/arm does; the address is also passed separately as a
 * plain register operand because ldrex/strex take it in brackets.
 */
#define ATOMIC_OP(op, asm_op)                                          \
    static inline void atomic_##op(int i, atomic_t *v)                 \
    {                                                                  \
        unsigned long tmp;                                             \
        int result;                                                    \
                                                                       \
        asm volatile("// atomic_" #op "\n"                             \
                     "1:	ldrex	%0, [%3]\n"                           \
                     "	" #asm_op "	%0, %0, %4\n"                     \
                     "	strex	%1, %0, [%3]\n"                       \
                     "	teq	%1, #0\n"                             \
                     "	bne	1b"                                   \
                     : "=&r"(result), "=&r"(tmp), "+Qo"(v->counter) \
                     : "r"(&v->counter), "Ir"(i)                    \
                     : "cc");                                       \
    }

#define ATOMIC_OP_RETURN(op, asm_op)                                   \
    static inline int atomic_##op##_return(int i, atomic_t *v)         \
    {                                                                  \
        unsigned long tmp;                                             \
        int result;                                                    \
                                                                       \
        asm volatile("// atomic_" #op "_return\n"                      \
                     "1:	ldrex	%0, [%3]\n"                           \
                     "	" #asm_op "	%0, %0, %4\n"                     \
                     "	strex	%1, %0, [%3]\n"                       \
                     "	teq	%1, #0\n"                             \
                     "	bne	1b"                                   \
                     : "=&r"(result), "=&r"(tmp), "+Qo"(v->counter) \
                     : "r"(&v->counter), "Ir"(i)                    \
                     : "cc", "memory");                             \
                                                                       \
        smp_mb();                                                      \
        return result;                                                 \
    }

#define ATOMIC_OPS(op, asm_op) \
    ATOMIC_OP(op, asm_op)      \
    ATOMIC_OP_RETURN(op, asm_op)

ATOMIC_OPS(add, add)
ATOMIC_OPS(sub, sub)

#undef ATOMIC_OPS
#undef ATOMIC_OP_RETURN
#undef ATOMIC_OP

static inline int atomic_cmpxchg(atomic_t *ptr, int old, int new)
{
    unsigned long oldval, res;

    smp_mb();

    do {
        asm volatile("// atomic_cmpxchg\n"
                     "	ldrex	%1, [%2]\n"
                     "	teq	%1, %3\n"
                     "	strexeq	%0, %4, [%2]\n"
                     : "=&r"(res), "=&r"(oldval)
                     : "r"(&ptr->counter), "Ir"(old), "r"(new)
                     : "cc");
    } while (res);

    smp_mb();
    return oldval;
}

#define atomic_xchg(v, new) (xchg(&((v)->counter), new))

static inline int __atomic_add_unless(atomic_t *v, int a, int u)
{
    int c, old;

    c = atomic_read(v);
    while (c != u && (old = atomic_cmpxchg((v), c, c + a)) != c)
        c = old;
    return c;
}

#define atomic_inc(v) atomic_add(1, v)
#define atomic_dec(v) atomic_sub(1, v)

#define atomic_inc_and_test(v) (atomic_add_return(1, v) == 0)
#define atomic_dec_and_test(v) (atomic_sub_return(1, v) == 0)
#define atomic_inc_return(v) (atomic_add_return(1, v))
#define atomic_dec_return(v) (atomic_sub_return(1, v))
#define atomic_sub_and_test(i, v) (atomic_sub_return(i, v) == 0)

#define atomic_add_negative(i, v) (atomic_add_return(i, v) < 0)

/*
 * 64-bit atomic operations.
 *
 * NOTE: in this port `atomic64_t` is `{ long counter; }`, and AArch32 `long`
 * is 32 bits (see <ktypes.h>), so these are single-word (32-bit) exclusive
 * operations carrying the arm64 names/signatures.  A true 64-bit atomic needs
 * a 64-bit exclusive, which this non-LPAE ARMv7 target does not provide; see
 * the 64-bit note in <asm/cmpxchg.h>.
 */
#define ATOMIC64_INIT(i) \
    {                    \
        (i)              \
    }

#define atomic64_read(v) ACCESS_ONCE((v)->counter)
#define atomic64_set(v, i) (((v)->counter) = (i))

#define ATOMIC64_OP(op, asm_op)                                        \
    static inline void atomic64_##op(long i, atomic64_t *v)            \
    {                                                                  \
        long result;                                                   \
        unsigned long tmp;                                             \
                                                                       \
        asm volatile("// atomic64_" #op "\n"                           \
                     "1:	ldrex	%0, [%3]\n"                           \
                     "	" #asm_op "	%0, %0, %4\n"                     \
                     "	strex	%1, %0, [%3]\n"                       \
                     "	teq	%1, #0\n"                             \
                     "	bne	1b"                                   \
                     : "=&r"(result), "=&r"(tmp), "+Qo"(v->counter) \
                     : "r"(&v->counter), "Ir"(i)                    \
                     : "cc");                                       \
    }

#define ATOMIC64_OP_RETURN(op, asm_op)                                 \
    static inline long atomic64_##op##_return(long i, atomic64_t *v)   \
    {                                                                  \
        long result;                                                   \
        unsigned long tmp;                                             \
                                                                       \
        asm volatile("// atomic64_" #op "_return\n"                    \
                     "1:	ldrex	%0, [%3]\n"                           \
                     "	" #asm_op "	%0, %0, %4\n"                     \
                     "	strex	%1, %0, [%3]\n"                       \
                     "	teq	%1, #0\n"                             \
                     "	bne	1b"                                   \
                     : "=&r"(result), "=&r"(tmp), "+Qo"(v->counter) \
                     : "r"(&v->counter), "Ir"(i)                    \
                     : "cc", "memory");                             \
                                                                       \
        smp_mb();                                                      \
        return result;                                                 \
    }

#define ATOMIC64_OPS(op, asm_op) \
    ATOMIC64_OP(op, asm_op)      \
    ATOMIC64_OP_RETURN(op, asm_op)

ATOMIC64_OPS(add, add)
ATOMIC64_OPS(sub, sub)

#undef ATOMIC64_OPS
#undef ATOMIC64_OP_RETURN
#undef ATOMIC64_OP

static inline long atomic64_cmpxchg(atomic64_t *ptr, long old, long new)
{
    unsigned long oldval, res;

    smp_mb();

    do {
        asm volatile("// atomic64_cmpxchg\n"
                     "	ldrex	%1, [%2]\n"
                     "	teq	%1, %3\n"
                     "	strexeq	%0, %4, [%2]\n"
                     : "=&r"(res), "=&r"(oldval)
                     : "r"(&ptr->counter), "Ir"(old), "r"(new)
                     : "cc");
    } while (res);

    smp_mb();
    return oldval;
}

#define atomic64_xchg(v, new) (xchg(&((v)->counter), new))

/*
 * Decrement unless the value is already <= 0, returning the value before the
 * decrement when no decrement happened and the decremented value otherwise
 * (same contract as the arm64 version).  Built on atomic64_cmpxchg() so it
 * works on any ARMv7-A core.
 */
static inline long atomic64_dec_if_positive(atomic64_t *v)
{
    long old, new;

    smp_mb();
    old = atomic64_read(v);
    while (old > 0) {
        new = old - 1;
        if (atomic64_cmpxchg(v, old, new) == old) {
            old = new;
            break;
        }
        old = atomic64_read(v);
    }
    smp_mb();

    return old;
}

static inline int atomic64_add_unless(atomic64_t *v, long a, long u)
{
    long c, old;

    c = atomic64_read(v);
    while (c != u && (old = atomic64_cmpxchg((v), c, c + a)) != c)
        c = old;

    return c != u;
}

#define atomic64_add_negative(a, v) (atomic64_add_return((a), (v)) < 0)
#define atomic64_inc(v) atomic64_add(1L, (v))
#define atomic64_inc_return(v) atomic64_add_return(1L, (v))
#define atomic64_inc_and_test(v) (atomic64_inc_return(v) == 0)
#define atomic64_sub_and_test(a, v) (atomic64_sub_return((a), (v)) == 0)
#define atomic64_dec(v) atomic64_sub(1L, (v))
#define atomic64_dec_return(v) atomic64_sub_return(1L, (v))
#define atomic64_dec_and_test(v) (atomic64_dec_return((v)) == 0)
#define atomic64_inc_not_zero(v) atomic64_add_unless((v), 1L, 0L)

#endif /* __ASM_ATOMIC_H */
