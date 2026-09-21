/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_HOOK_H_
#define _KP_HOOK_H_

#include <stdint.h>
#include <log.h>

#define HOOK_INTO_BRANCH_FUNC

typedef enum
{
    HOOK_NO_ERR = 0,
    HOOK_BAD_ADDRESS = 4095,
    HOOK_DUPLICATED = 4094,
    HOOK_NO_MEM = 4093,
    HOOK_BAD_RELO = 4092,
    HOOK_TRANSIT_NO_MEM = 4091,
    HOOK_CHAIN_FULL = 4090,
} hook_err_t;

enum hook_type
{
    NONE = 0,
    INLINE,
    INLINE_CHAIN,
    FUNCTION_POINTER_CHAIN,
};

typedef int8_t chain_item_state;

#define CHAIN_ITEM_STATE_EMPTY 0
#define CHAIN_ITEM_STATE_READY 1
#define CHAIN_ITEM_STATE_BUSY 2

#define local_offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#define local_container_of(ptr, type, member) ({ (type *)((char *)(ptr) - local_offsetof(type, member)); })

#define HOOK_MEM_REGION_NUM 4
#define TRAMPOLINE_MAX_NUM 6
#define RELOCATE_INST_NUM (4 * 8 + 8 - 4)

#define HOOK_CHAIN_NUM 0x10
/*
 * Words reserved for ONE transit body, plus the 6-word chain header.
 * Both hook.c:1077 and fphook.c:197 reject with -HOOK_TRANSIT_NO_MEM when
 *      transit_num + 6 > TRANSIT_INST_NUM
 * and this constant is also the array dimension at hook.h:260 and :278, so it
 * must cover the LARGEST body on every architecture.
 *
 * MEASURED on the linked AArch32 blob (arm-linux-gnueabi-nm on
 * kernel/kpimg-arm-full.elf; body size = _transitN_end - _transitN):
 *      _transit0   252 B =  63 words
 *      _transit4   308 B =  77 words
 *      _transit8   428 B = 107 words
 *      _transit12  612 B = 153 words   <- largest (0x264 bytes)
 *   _fp_transit12 = _fp_transit12_end - _fp_transit12 = 0x264 B = 153 words
 * So the requirement is 153 + 6 = 159 = 0x9f.  The previous value 0x70 (112)
 * made every chain that has 8 or 12 args fail with -HOOK_TRANSIT_NO_MEM: that
 * is the `err: -4091` seen on arm32 at hook_wrap12() during patch().
 * AArch64's `_transit12` under GCC 14 is ~100 words, which is why 0x60/0x70
 * was enough there -- A32 simply emits a longer body.
 * 0xC0 (192) leaves 33 words of headroom for a taller body from a different
 * compiler; the cost is (0xC0-0x70)*4 = 320 B per hook_chain_t /
 * fp_hook_chain_t (HOOK_CHAIN_NUM 0x10 + FP_HOOK_CHAIN_NUM 0x20 copies).
 */
#define TRANSIT_INST_NUM 0xC0

#define FP_HOOK_CHAIN_NUM 0x20

#define ARM64_NOP 0xd503201f
#define ARM64_BTI_C 0xd503245f
#define ARM64_BTI_J 0xd503249f
#define ARM64_BTI_JC 0xd50324df
#define ARM64_PACIASP 0xd503233f
#define ARM64_PACIBSP 0xd503237f

/*
 * Inline-hook "chain" scratch-register convention.
 *
 * kp_chain_transit_header() emits the 6-word prologue of chain->transit[]: it puts
 * the address of the hook_chain_t into a scratch register and then falls through
 * into the _transitN body (copied to transit[6]), which reads that register back
 * via current_inline_hook_chain().
 *
 *   AArch64: x16 (IP0).  LDR X16, #12 loads the 64-bit literal at transit[4..5];
 *            B #16 skips over it into the body.
 *   AArch32: r12 (IP).   LDR r12, [pc, #0] loads the 32-bit literal at transit[2];
 *            B transit[6] skips over the remaining header words.
 *
 * An AArch32 virtual address fits in 32 bits, so the literal shrinks to one word.
 * The header stays 6 words on every architecture so the body offset (transit[6])
 * and the TRANSIT_INST_NUM accounting are unchanged.
 */
#if defined(CONFIG_ARM)
#define KP_CHAIN_REG "r12"
#define ARM32_NOP    0xE1A00000u /* mov r0, r0 */
#else
#define KP_CHAIN_REG "x16"
#endif

/*
 * ILP32 (arm32): a uint64_t parameter occupies a *register pair* under AAPCS
 * (arg0 = r0:r1, arg1 = r2:r3, further args on the stack, 8-byte aligned).
 * The arm64-style uint64_t transit signatures therefore decoded a 32-bit
 * caller's registers wrongly -- with arguments in r0-r3 (and the rest on the
 * stack) the transit read arg1 from r2 and arg2 from the first stack slot,
 * silently dropping r1.  Use word-sized parameters on ILP32 so a transit
 * follows the same convention as the function it fronts, widening into the
 * uint64_t hook_fargs*_t slots.  The transit is entered by a
 * register-preserving jump from the trampoline (KP_CHAIN_REG carries the
 * chain), so on arm32 this is the kernel's own convention: AAPCS for inline
 * hooks, r0-r6 for sys_call_table entries -- args 0..3 (r0-r3) are exact;
 * syscall args 4..6 live in r4-r6 and are not visible to an AAPCS callee.
 */
#if defined(CONFIG_ARM)
typedef uint32_t kp_transit_arg_t;
typedef uint32_t kp_transit_ret_t;
#else
typedef uint64_t kp_transit_arg_t;
typedef uint64_t kp_transit_ret_t;
#endif

static inline void kp_chain_transit_header(uint32_t *transit, void *chain)
{
#if defined(CONFIG_ARM)
    transit[0] = 0xE59FC000u; /* ldr r12, [pc, #0]      -> loads transit[2] */
    transit[1] = 0xEA000003u; /* b   transit[1] + 20    -> transit[6] */
    transit[2] = (uint32_t)(uintptr_t)chain;
    transit[3] = ARM32_NOP;
    transit[4] = ARM32_NOP;
    transit[5] = ARM32_NOP;
#else
    transit[0] = ARM64_BTI_JC;
    transit[1] = 0x58000070; /* LDR X16, #12 */
    transit[2] = 0x14000004; /* B #16 */
    transit[3] = ARM64_NOP;
    transit[4] = ((uint64_t)(uintptr_t)chain) & 0xFFFFFFFF;
    transit[5] = ((uint64_t)(uintptr_t)chain) >> 32u;
#endif
}

typedef struct
{
    // in
    uint64_t func_addr;
    uint64_t origin_addr;
    uint64_t replace_addr;
    uint64_t relo_addr;
    // out
    int32_t tramp_insts_num;
    int32_t relo_insts_num;
    uint32_t origin_insts[TRAMPOLINE_MAX_NUM] __attribute__((aligned(8)));
    uint32_t tramp_insts[TRAMPOLINE_MAX_NUM] __attribute__((aligned(8)));
    uint32_t relo_insts[RELOCATE_INST_NUM] __attribute__((aligned(8)));
} hook_t __attribute__((aligned(8)));

struct _hook_chain;

#define HOOK_LOCAL_DATA_NUM 8

typedef struct
{
    union
    {
        struct
        {
            uint64_t data0;
            uint64_t data1;
            uint64_t data2;
            uint64_t data3;
            uint64_t data4;
            uint64_t data5;
            uint64_t data6;
            uint64_t data7;
        };
        uint64_t data[HOOK_LOCAL_DATA_NUM];
    };
} hook_local_t;

typedef struct
{
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union
    {
        struct
        {
        };
        uint64_t args[0];
    };
} hook_fargs0_t __attribute__((aligned(8)));

typedef struct
{
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union
    {
        struct
        {
            uint64_t arg0;
            uint64_t arg1;
            uint64_t arg2;
            uint64_t arg3;
        };
        uint64_t args[4];
    };
} hook_fargs4_t __attribute__((aligned(8)));

typedef hook_fargs4_t hook_fargs1_t;
typedef hook_fargs4_t hook_fargs2_t;
typedef hook_fargs4_t hook_fargs3_t;

typedef struct
{
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union
    {
        struct
        {
            uint64_t arg0;
            uint64_t arg1;
            uint64_t arg2;
            uint64_t arg3;
            uint64_t arg4;
            uint64_t arg5;
            uint64_t arg6;
            uint64_t arg7;
        };
        uint64_t args[8];
    };
} hook_fargs8_t __attribute__((aligned(8)));

typedef hook_fargs8_t hook_fargs5_t;
typedef hook_fargs8_t hook_fargs6_t;
typedef hook_fargs8_t hook_fargs7_t;

typedef struct
{
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union
    {
        struct
        {
            uint64_t arg0;
            uint64_t arg1;
            uint64_t arg2;
            uint64_t arg3;
            uint64_t arg4;
            uint64_t arg5;
            uint64_t arg6;
            uint64_t arg7;
            uint64_t arg8;
            uint64_t arg9;
            uint64_t arg10;
            uint64_t arg11;
        };
        uint64_t args[12];
    };
} hook_fargs12_t __attribute__((aligned(8)));

typedef hook_fargs12_t hook_fargs9_t;
typedef hook_fargs12_t hook_fargs10_t;
typedef hook_fargs12_t hook_fargs11_t;

typedef void (*hook_chain0_callback)(hook_fargs0_t *fargs, void *udata);
typedef void (*hook_chain1_callback)(hook_fargs1_t *fargs, void *udata);
typedef void (*hook_chain2_callback)(hook_fargs2_t *fargs, void *udata);
typedef void (*hook_chain3_callback)(hook_fargs3_t *fargs, void *udata);
typedef void (*hook_chain4_callback)(hook_fargs4_t *fargs, void *udata);
typedef void (*hook_chain5_callback)(hook_fargs5_t *fargs, void *udata);
typedef void (*hook_chain6_callback)(hook_fargs6_t *fargs, void *udata);
typedef void (*hook_chain7_callback)(hook_fargs7_t *fargs, void *udata);
typedef void (*hook_chain8_callback)(hook_fargs8_t *fargs, void *udata);
typedef void (*hook_chain9_callback)(hook_fargs9_t *fargs, void *udata);
typedef void (*hook_chain10_callback)(hook_fargs10_t *fargs, void *udata);
typedef void (*hook_chain11_callback)(hook_fargs11_t *fargs, void *udata);
typedef void (*hook_chain12_callback)(hook_fargs12_t *fargs, void *udata);

typedef struct _hook_chain
{
    // must be the first element
    hook_t hook;
    int32_t chain_items_max;
    chain_item_state states[HOOK_CHAIN_NUM];
    void *udata[HOOK_CHAIN_NUM];
    void *befores[HOOK_CHAIN_NUM];
    void *afters[HOOK_CHAIN_NUM];
    uint32_t transit[TRANSIT_INST_NUM];
} hook_chain_t __attribute__((aligned(8)));

typedef struct
{
    uintptr_t fp_addr;
    uint64_t replace_addr;
    uint64_t origin_fp;
} fp_hook_t __attribute__((aligned(8)));

typedef struct _fphook_chain
{
    fp_hook_t hook;
    int32_t chain_items_max;
    chain_item_state states[FP_HOOK_CHAIN_NUM];
    void *udata[FP_HOOK_CHAIN_NUM];
    void *befores[FP_HOOK_CHAIN_NUM];
    void *afters[FP_HOOK_CHAIN_NUM];
    uint32_t transit[TRANSIT_INST_NUM];
} fp_hook_chain_t __attribute__((aligned(8)));

static inline int is_bad_address(void *addr)
{
    return ((uint64_t)addr & 0x8000000000000000) != 0x8000000000000000;
}

int32_t branch_from_to(uint32_t *tramp_buf, uint64_t src_addr, uint64_t dst_addr);
int32_t branch_relative(uint32_t *buf, uint64_t src_addr, uint64_t dst_addr);
int32_t branch_absolute(uint32_t *buf, uint64_t addr);
int32_t ret_absolute(uint32_t *buf, uint64_t addr);

hook_err_t hook_prepare(hook_t *hook);
void hook_install(hook_t *hook);
void hook_uninstall(hook_t *hook);

/**
 * @brief Inline-hook function which address is @param func with function @param replace, 
 * after hook, original @param func is backuped in @param backup.
 * 
 * @note If multiple modules hook this function simultaneously, 
 * it will cause abnormality when unload the modules. Please use hook_wrap instead
 * 
 * @see hook_wrap
 * 
 * @param func 
 * @param replace 
 * @param backup 
 * @return hook_err_t 
 */
hook_err_t hook(void *func, void *replace, void **backup);

/**
 * @brief unhook of hooked function
 * 
 * @param func 
 */
void unhook(void *func);

/**
 * @brief 
 * 
 * @param chain 
 * @param before 
 * @param after 
 * @param udata 
 * @return hook_err_t 
 */
hook_err_t hook_chain_add(hook_chain_t *chain, void *before, void *after, void *udata);
/**
 * @brief 
 * 
 * @param chain 
 * @param before 
 * @param after 
 */
void hook_chain_remove(hook_chain_t *chain, void *before, void *after);

/**
 * @brief Wrap a function with before and after function. 
 * The same function can do hook and unhook multiple times 
 * 
 * @see hook_chain0_callback
 * @see hook_fargs0_t
 * 
 * @param func The address of function 
 * @param argno The number of method arguments
 * @param before This function will be called before hooked function, 
 * the type of before is hook_chain{n}_callback which n is equal to argno.
 * @param after The same as before but will be call after hooked function
 * @param udata 
 * @return hook_err_t 
 */
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata);

/**
 * @brief 
 * 
 * @param func 
 * @param before 
 * @param after 
 * @param remove 
 */
void hook_unwrap_remove(void *func, void *before, void *after, int remove);

static inline void hook_unwrap(void *func, void *before, void *after)
{
    return hook_unwrap_remove(func, before, after, 1);
}

/**
 * @param hook_args
 */
static inline void *wrap_get_origin_func(void *hook_args)
{
    hook_fargs0_t *args = (hook_fargs0_t *)hook_args;
    hook_chain_t *chain = (hook_chain_t *)args->chain;
    return (void *)chain->hook.relo_addr;
}

/**
 * @brief 
 * 
 * @param fp_addr 
 * @param replace 
 * @param backup 
 */
void fp_hook(uintptr_t fp_addr, void *replace, void **backup);

/**
 * @brief 
 * 
 * @param fp_addr 
 * @param backup 
 */
void fp_unhook(uintptr_t fp_addr, void *backup);

/**
 * @brief 
 * 
 * @param fp_addr 
 * @param argno 
 * @param before 
 * @param after 
 * @param udata 
 * @return hook_err_t 
 */
hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata);

/**
 * @brief 
 * 
 * @param fp_addr 
 * @param before 
 * @param after 
 */
void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after);

/**
 * 
 */
static inline void *fp_get_origin_func(void *hook_args)
{
    hook_fargs0_t *args = (hook_fargs0_t *)hook_args;
    fp_hook_chain_t *chain = (fp_hook_chain_t *)args->chain;
    return (void *)chain->hook.origin_fp;
}

static inline void hook_chain_install(hook_chain_t *chain)
{
    hook_install(&chain->hook);
}

static inline void hook_chain_uninstall(hook_chain_t *chain)
{
    hook_uninstall(&chain->hook);
}

static inline hook_err_t hook_wrap0(void *func, hook_chain0_callback before, hook_chain0_callback after, void *udata)
{
    return hook_wrap(func, 0, before, after, udata);
}

static inline hook_err_t hook_wrap1(void *func, hook_chain1_callback before, hook_chain1_callback after, void *udata)
{
    return hook_wrap(func, 1, before, after, udata);
}

static inline hook_err_t hook_wrap2(void *func, hook_chain2_callback before, hook_chain2_callback after, void *udata)
{
    return hook_wrap(func, 2, before, after, udata);
}

static inline hook_err_t hook_wrap3(void *func, hook_chain3_callback before, hook_chain3_callback after, void *udata)
{
    return hook_wrap(func, 3, before, after, udata);
}

static inline hook_err_t hook_wrap4(void *func, hook_chain4_callback before, hook_chain4_callback after, void *udata)
{
    return hook_wrap(func, 4, before, after, udata);
}

static inline hook_err_t hook_wrap5(void *func, hook_chain5_callback before, hook_chain5_callback after, void *udata)
{
    return hook_wrap(func, 5, before, after, udata);
}

static inline hook_err_t hook_wrap6(void *func, hook_chain6_callback before, hook_chain6_callback after, void *udata)
{
    return hook_wrap(func, 6, before, after, udata);
}

static inline hook_err_t hook_wrap7(void *func, hook_chain7_callback before, hook_chain7_callback after, void *udata)
{
    return hook_wrap(func, 7, before, after, udata);
}

static inline hook_err_t hook_wrap8(void *func, hook_chain8_callback before, hook_chain8_callback after, void *udata)
{
    return hook_wrap(func, 8, before, after, udata);
}

static inline hook_err_t hook_wrap9(void *func, hook_chain9_callback before, hook_chain9_callback after, void *udata)
{
    return hook_wrap(func, 9, before, after, udata);
}

static inline hook_err_t hook_wrap10(void *func, hook_chain10_callback before, hook_chain10_callback after, void *udata)
{
    return hook_wrap(func, 10, before, after, udata);
}

static inline hook_err_t hook_wrap11(void *func, hook_chain11_callback before, hook_chain11_callback after, void *udata)
{
    return hook_wrap(func, 11, before, after, udata);
}

static inline hook_err_t hook_wrap12(void *func, hook_chain12_callback before, hook_chain12_callback after, void *udata)
{
    return hook_wrap(func, 12, before, after, udata);
}

static inline hook_err_t fp_hook_wrap0(uintptr_t fp_addr, hook_chain0_callback before, hook_chain0_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 0, before, after, udata);
}

static inline hook_err_t fp_hook_wrap1(uintptr_t fp_addr, hook_chain1_callback before, hook_chain1_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 1, before, after, udata);
}

static inline hook_err_t fp_hook_wrap2(uintptr_t fp_addr, hook_chain2_callback before, hook_chain2_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 2, before, after, udata);
}

static inline hook_err_t fp_hook_wrap3(uintptr_t fp_addr, hook_chain3_callback before, hook_chain3_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 3, before, after, udata);
}

static inline hook_err_t fp_hook_wrap4(uintptr_t fp_addr, hook_chain4_callback before, hook_chain4_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 4, before, after, udata);
}

static inline hook_err_t fp_hook_wrap5(uintptr_t fp_addr, hook_chain5_callback before, hook_chain5_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 5, before, after, udata);
}

static inline hook_err_t fp_hook_wrap6(uintptr_t fp_addr, hook_chain6_callback before, hook_chain6_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 6, before, after, udata);
}

static inline hook_err_t fp_hook_wrap7(uintptr_t fp_addr, hook_chain7_callback before, hook_chain7_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 7, before, after, udata);
}

static inline hook_err_t fp_hook_wrap8(uintptr_t fp_addr, hook_chain8_callback before, hook_chain8_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 8, before, after, udata);
}

static inline hook_err_t fp_hook_wrap9(uintptr_t fp_addr, hook_chain9_callback before, hook_chain9_callback after,
                                       void *udata)
{
    return fp_hook_wrap(fp_addr, 9, before, after, udata);
}

static inline hook_err_t fp_hook_wrap10(uintptr_t fp_addr, hook_chain10_callback before, hook_chain10_callback after,
                                        void *udata)
{
    return fp_hook_wrap(fp_addr, 10, before, after, udata);
}

static inline hook_err_t fp_hook_wrap11(uintptr_t fp_addr, hook_chain11_callback before, hook_chain11_callback after,
                                        void *udata)
{
    return fp_hook_wrap(fp_addr, 11, before, after, udata);
}

static inline hook_err_t fp_hook_wrap12(uintptr_t fp_addr, hook_chain12_callback before, hook_chain12_callback after,
                                        void *udata)
{
    return fp_hook_wrap(fp_addr, 12, before, after, udata);
}

#endif
