/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <hook.h>
#include <io.h>
#include <symbol.h>
#include <pgtable.h>
#include <hotpatch.h>
#include <kpmalloc.h>
#include "hmem.h"

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)
#define align_ceil(x, align) (((u64)(x) + (u64)(align) - 1) & ~((u64)(align) - 1))

typedef uint32_t inst_type_t;
typedef uint32_t inst_mask_t;

#define INST_B 0x14000000
#define INST_BC 0x54000000
#define INST_BL 0x94000000
#define INST_ADR 0x10000000
#define INST_ADRP 0x90000000
#define INST_LDR_32 0x18000000
#define INST_LDR_64 0x58000000
#define INST_LDRSW_LIT 0x98000000
#define INST_PRFM_LIT 0xD8000000
#define INST_LDR_SIMD_32 0x1C000000
#define INST_LDR_SIMD_64 0x5C000000
#define INST_LDR_SIMD_128 0x9C000000
#define INST_CBZ 0x34000000
#define INST_CBNZ 0x35000000
#define INST_TBZ 0x36000000
#define INST_TBNZ 0x37000000
#define INST_HINT 0xD503201F
#define INST_IGNORE 0x0

#define MASK_B 0xFC000000
#define MASK_BC 0xFF000010
#define MASK_BL 0xFC000000
#define MASK_ADR 0x9F000000
#define MASK_ADRP 0x9F000000
#define MASK_LDR_32 0xFF000000
#define MASK_LDR_64 0xFF000000
#define MASK_LDRSW_LIT 0xFF000000
#define MASK_PRFM_LIT 0xFF000000
#define MASK_LDR_SIMD_32 0xFF000000
#define MASK_LDR_SIMD_64 0xFF000000
#define MASK_LDR_SIMD_128 0xFF000000
#define MASK_CBZ 0x7F000000u
#define MASK_CBNZ 0x7F000000u
#define MASK_TBZ 0x7F000000u
#define MASK_TBNZ 0x7F000000u
#define MASK_HINT 0xFFFFF01F
#define MASK_IGNORE 0x0

#if !defined(CONFIG_ARM)
static inst_mask_t masks[] = {
    MASK_B,      MASK_BC,        MASK_BL,       MASK_ADR,         MASK_ADRP,        MASK_LDR_32,
    MASK_LDR_64, MASK_LDRSW_LIT, MASK_PRFM_LIT, MASK_LDR_SIMD_32, MASK_LDR_SIMD_64, MASK_LDR_SIMD_128,
    MASK_CBZ,    MASK_CBNZ,      MASK_TBZ,      MASK_TBNZ,        MASK_IGNORE,
};
static inst_type_t types[] = {
    INST_B,      INST_BC,        INST_BL,       INST_ADR,         INST_ADRP,        INST_LDR_32,
    INST_LDR_64, INST_LDRSW_LIT, INST_PRFM_LIT, INST_LDR_SIMD_32, INST_LDR_SIMD_64, INST_LDR_SIMD_128,
    INST_CBZ,    INST_CBNZ,      INST_TBZ,      INST_TBNZ,        INST_IGNORE,
};

static int32_t relo_len[] = { 6, 8, 8, 4, 4, 6, 6, 6, 8, 8, 8, 8, 6, 6, 6, 6, 2 };
#endif /* !CONFIG_ARM */

#if defined(CONFIG_ARM)

/* --- KP_A32_RELOC_BEGIN --- */
/*
 * Pure AArch32 (A32) relocation core.
 *
 * This block is deliberately free of kernel types, hook_t, arch asm and any
 * CONFIG_* preprocessor dependency: the exact text between the markers above
 * and below is extracted mechanically into
 * port/task7_verify/gen_a32_reloc.c, compiled with host gcc, and the words it
 * emits are disassembled with `arm-linux-gnueabi-objdump -D -b binary -m arm`.
 * Keep it self-contained.
 *
 * Every class emits a FIXED word count, because relo_in_tramp() must be able to
 * recompute the VA of any original instruction from class lengths alone.
 */

/* relocation classes */
#define A32_CLS_IGNORE  0
#define A32_CLS_B       1
#define A32_CLS_BC      2
#define A32_CLS_BL      3
#define A32_CLS_LDR_LIT 4
#define A32_CLS_ADR     5
#define A32_CLS_BAD     6 /* fail loudly; never emit */

/* A32 instruction words.  In A32 the PC reads as instruction address + 8. */
#define A32_LDR_PC_PC_M4 0xE51FF004u /* ldr pc, [pc, #-4]  -> literal at +0 */
#define A32_LDR_LR_PC_P4 0xE59FE004u /* ldr lr, [pc, #4]   -> literal at +12 */
#define A32_NOP          0xE1A00000u /* mov r0, r0 */
#define A32_B_OP         0x0A000000u /* unconditional branch opcode field */

#define KP_A32_OK  0
#define KP_A32_BAD (-1)

/* Minimal context: mirrors the hook_t fields the AArch64 relocator reads. */
typedef struct
{
    uint64_t origin_addr;         /* VA of origin_insts[0] */
    uint64_t relo_addr;           /* VA of relo_insts[0] */
    int32_t tramp_insts_num;      /* number of relocated instructions */
    int32_t relo_insts_num;       /* words already emitted into relo_insts[] */
    const uint32_t *origin_insts; /* the original instruction words */
} kp_a32_ctx_t;

static int32_t kp_a32_sext24(uint32_t v)
{
    return (int32_t)(v << 8) >> 8;
}

/* ARM immediate encoding: an 8-bit value rotated right by 2*rot inside 32 bits.
 * The result is a full 32-bit word (e.g. 0xFF,rot=14 -> 0xFF0), NOT a byte. */
static uint32_t kp_a32_ror8(uint32_t v, uint32_t r)
{
    v &= 0xFFu;
    r &= 31u;
    if (!r) return v;
    return (v >> r) | (v << (32u - r));
}

/*
 * Single source of truth for instruction classification, shared by
 * kp_a32_relo_len() (address bookkeeping in relo_in_tramp) and
 * kp_a32_relocate_inst() (word emission), so the two can never drift.
 *
 * Anything whose PC-relative behaviour we cannot encode faithfully is reported
 * as A32_CLS_BAD: unported classes must fail loudly, never be copied silently.
 */
static int32_t kp_a32_classify(uint32_t inst)
{
    uint32_t cond = inst >> 28;
    uint32_t grp = (inst >> 25) & 7u;
    uint32_t rn = (inst >> 16) & 0xFu;

    /* bits[27:25] == 101: B / BL / BLX (immediate) */
    if ((inst & 0x0E000000u) == 0x0A000000u) {
        uint32_t op = (inst >> 24) & 0xFu;
        if (cond == 0xFu) return A32_CLS_BAD; /* BLX imm: H-bit/state switch, unverifiable */
        if (op == 0xBu) return (cond == 0xEu) ? A32_CLS_BL : A32_CLS_BAD; /* cond BL -> unverifiable */
        return (cond == 0xEu) ? A32_CLS_B : ((cond < 0xEu) ? A32_CLS_BC : A32_CLS_BAD);
    }

    /* bits[27:26] == 01: LDR/STR (word/byte), media, PLD/PLI */
    if ((inst & 0x0C000000u) == 0x04000000u) {
        if (cond == 0xFu) {
            /* Unconditional encoding in the LDR/STR space.  Per the agreed
             * decision rule only bit20(L)==0 is copied.  Real PLD/PLI are
             * 1111 0101 U1_1 Rn 1111 imm12 with L=1, so they classify as BAD
             * and hook_prepare() fails loudly instead of silently copying. */
            return ((inst >> 20) & 1u) ? A32_CLS_BAD : A32_CLS_IGNORE;
        }
        if (inst & 0x02000000u) { /* bit25 = 1 */
            if (!(inst & 0x10u)) { /* bit4 = 0: register offset LDR/STR */
                uint32_t rm = inst & 0xFu;
                if (rn == 15u || rm == 15u) return A32_CLS_BAD;
                return A32_CLS_IGNORE;
            }
            return A32_CLS_IGNORE; /* media: PC not meaningfully addressable */
        }
        /* bit25 = 0: immediate offset */
        {
            uint32_t P = (inst >> 24) & 1u;
            uint32_t W = (inst >> 21) & 1u;
            uint32_t Bb = (inst >> 22) & 1u;
            uint32_t L = (inst >> 20) & 1u;
            if (rn != 15u) return A32_CLS_IGNORE; /* not PC-relative */
            if (P == 1u && W == 0u && Bb == 0u && L == 1u) return A32_CLS_LDR_LIT;
            return A32_CLS_BAD; /* LDRB/LDRH literal, STR to PC, post-indexed, ... */
        }
    }

    if (grp <= 1u) { /* data-processing / misc */
        if (inst & 0x02000000u) { /* bit25 = 1: DP immediate */
            uint32_t opcode = (inst >> 21) & 0xFu;
            if (opcode == 0x4u || opcode == 0x2u) { /* ADD / SUB immediate */
                if (rn == 15u) {
                    if (inst & 0x00100000u) return A32_CLS_BAD; /* S=1 with Rn=15: UNPREDICTABLE */
                    return A32_CLS_ADR;
                }
                return A32_CLS_IGNORE;
            }
            if (rn == 15u) return A32_CLS_BAD; /* other PC-based DP immediate */
            return A32_CLS_IGNORE;
        }
        if (!(inst & 0x10u)) { /* bit4 = 0: DP register form */
            uint32_t rm = inst & 0xFu;
            uint32_t rs = (inst >> 8) & 0xFu;
            if (rn == 15u || rm == 15u || rs == 15u) return A32_CLS_BAD;
            return A32_CLS_IGNORE;
        }
        /* bit4 = 1: multiply / extra load-store / misc */
        {
            uint32_t op4 = (inst >> 4) & 0xFu;
            uint32_t rm = inst & 0xFu;
            uint32_t rs = (inst >> 8) & 0xFu;
            if (op4 == 0x9u) { /* MUL/MLA/MLS/UMULL/... */
                if (rm == 15u || rs == 15u) return A32_CLS_BAD;
                return A32_CLS_IGNORE;
            }
            if (op4 == 0xBu || op4 == 0xDu || op4 == 0xFu) { /* extra load/store */
                uint32_t I = (inst >> 22) & 1u; /* 1 = immediate offset */
                if (rn == 15u || (I == 0u && rm == 15u)) return A32_CLS_BAD;
                return A32_CLS_IGNORE;
            }
            if (rm == 15u) return A32_CLS_BAD; /* BX/BLX reg, CLZ, misc with PC */
            return A32_CLS_IGNORE;
        }
    }

    if (grp == 4u) { /* LDM/STM */
        if (rn == 15u) return A32_CLS_BAD; /* PC base = branch/literal */
        return A32_CLS_IGNORE;
    }

    if (grp == 6u) { /* LDC/STC, MCRR/MRRC, VFP VLDR/VSTR */
        if ((inst & 0x0F000000u) == 0x0D000000u) return A32_CLS_BAD; /* VLDR/VSTR: PC-addressable */
        if (rn == 15u) return A32_CLS_BAD;
        return A32_CLS_IGNORE;
    }

    return A32_CLS_IGNORE; /* grp == 7: coprocessor DP / SVC: no PC-relative address */
}

static int32_t kp_a32_relo_len(uint32_t inst)
{
    switch (kp_a32_classify(inst)) {
    case A32_CLS_BC:
    case A32_CLS_BL:
        return 4;
    default:
        return 2; /* IGNORE / B / LDR_LIT / ADR / BAD */
    }
}

static uint64_t kp_a32_relo_in_tramp(const kp_a32_ctx_t *ctx, uint64_t addr)
{
    uint64_t start = ctx->origin_addr;
    uint64_t end = start + (uint64_t)ctx->tramp_insts_num * 4u;
    uint64_t fix;
    uint32_t idx, i;

    if (!(addr >= start && addr < end)) return addr;
    idx = (uint32_t)((addr - start) / 4u);
    fix = ctx->relo_addr;
    for (i = 0; i < idx; i++) {
        fix += (uint64_t)kp_a32_relo_len(ctx->origin_insts[i]) * 4u;
    }
    return fix;
}

static uint32_t kp_a32_can_b_rel(uint64_t src, uint64_t dst)
{
    int64_t off = (int64_t)dst - ((int64_t)src + 8);
    return (off & 3) == 0 && off >= -0x08000000LL && off <= 0x07FFFFFCLL;
}

static int32_t kp_a32_branch_relative(uint32_t *buf, uint64_t src, uint64_t dst)
{
    int64_t off;
    if (!kp_a32_can_b_rel(src, dst)) return 0;
    off = (int64_t)dst - ((int64_t)src + 8);
    buf[0] = 0xEA000000u | (uint32_t)((off >> 2) & 0x00FFFFFF);
    buf[1] = A32_NOP;
    return 2;
}

static int32_t kp_a32_branch_absolute(uint32_t *buf, uint64_t addr)
{
    buf[0] = A32_LDR_PC_PC_M4;
    buf[1] = (uint32_t)addr;
    return 2;
}

static int32_t kp_a32_ret_absolute(uint32_t *buf, uint64_t addr)
{
    return kp_a32_branch_absolute(buf, addr);
}

static int32_t kp_a32_branch_from_to(uint32_t *buf, uint64_t src, uint64_t dst)
{
    int32_t len = kp_a32_branch_relative(buf, src, dst);
    if (len) return len;
    return kp_a32_ret_absolute(buf, dst);
}

/*
 * Emit the relocation of one original A32 instruction into buf.
 * Returns KP_A32_OK, or KP_A32_BAD for any class we cannot encode faithfully.
 */
static int32_t kp_a32_relocate_inst(const kp_a32_ctx_t *ctx, uint32_t *buf, uint64_t inst_addr, uint32_t inst)
{
    int32_t cls = kp_a32_classify(inst);
    uint32_t cond = inst >> 28;
    uint64_t buf_va = ctx->relo_addr + (uint64_t)ctx->relo_insts_num * 4u;
    uint64_t target;

    switch (cls) {
    case A32_CLS_IGNORE:
        buf[0] = inst;
        buf[1] = A32_NOP;
        return KP_A32_OK;

    case A32_CLS_B:
        target = kp_a32_relo_in_tramp(ctx, inst_addr + 8 + (uint64_t)(kp_a32_sext24(inst & 0xFFFFFFu) * 4));
        buf[0] = A32_LDR_PC_PC_M4; /* ldr pc, [pc, #-4] -> buf[1] */
        buf[1] = (uint32_t)target;
        return KP_A32_OK;

    case A32_CLS_BC: {
        uint32_t inv = (cond ^ 1u) & 0xFu; /* A32 condition inversion is XOR 1 */
        target = kp_a32_relo_in_tramp(ctx, inst_addr + 8 + (uint64_t)(kp_a32_sext24(inst & 0xFFFFFFu) * 4));
        buf[0] = (inv << 28) | A32_B_OP | 0x2u; /* B<inv> +8  -> buf[3] (fall-through) */
        buf[1] = A32_LDR_PC_PC_M4;              /* ldr pc, [pc, #-4] -> buf[2] */
        buf[2] = (uint32_t)target;
        buf[3] = A32_NOP;
        return KP_A32_OK;
    }

    case A32_CLS_BL:
        target = kp_a32_relo_in_tramp(ctx, inst_addr + 8 + (uint64_t)(kp_a32_sext24(inst & 0xFFFFFFu) * 4));
        buf[0] = A32_LDR_LR_PC_P4; /* ldr lr, [pc, #4]  -> buf[3] = buf_va+16 (return addr) */
        buf[1] = A32_LDR_PC_PC_M4; /* ldr pc, [pc, #-4] -> buf[2] = target */
        buf[2] = (uint32_t)target;
        buf[3] = (uint32_t)(buf_va + 16u); /* end of this expansion == start of next */
        return KP_A32_OK;

    case A32_CLS_LDR_LIT: {
        uint32_t rt = (inst >> 12) & 0xFu;
        uint32_t imm12 = inst & 0xFFFu;
        uint64_t lit = (inst & 0x00800000u) ? (inst_addr + 8 + imm12) : (inst_addr + 8 - imm12);
        uint32_t value = *(const uint32_t *)(uintptr_t)lit; /* literal read at prepare time */
        buf[0] = 0xE51F0004u | (rt << 12); /* ldr Rt, [pc, #-4] -> buf[1] */
        buf[1] = value;
        return KP_A32_OK;
    }

    case A32_CLS_ADR: {
        uint32_t rd = (inst >> 12) & 0xFu;
        uint32_t opcode = (inst >> 21) & 0xFu;
        uint32_t imm32 = kp_a32_ror8(inst & 0xFFu, ((inst >> 8) & 0xFu) * 2u);
        uint64_t addr = (opcode == 0x4u) ? (inst_addr + 8 + imm32) : (inst_addr + 8 - imm32);
        buf[0] = 0xE51F0004u | (rd << 12); /* ldr Rd, [pc, #-4] -> buf[1] */
        buf[1] = (uint32_t)addr;
        return KP_A32_OK;
    }

    case A32_CLS_BAD:
    default:
        return KP_A32_BAD;
    }
}
/* --- KP_A32_RELOC_END --- */

#endif /* CONFIG_ARM */

// static uint64_t sign_extend(uint64_t x, uint32_t len)
// {
//     char sign_bit = bit(x, len - 1);
//     unsigned long sign_mask = 0 - sign_bit;
//     x |= ((sign_mask >> len) << len);
//     return x;
// }

#if !defined(CONFIG_ARM)
static int is_in_tramp(hook_t *hook, uint64_t addr)
{
    uint64_t tramp_start = hook->origin_addr;
    uint64_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (addr >= tramp_start && addr < tramp_end) {
        return 1;
    }
    return 0;
}
#endif /* !CONFIG_ARM */

#if defined(CONFIG_ARM)

static kp_a32_ctx_t a32_ctx_from_hook(hook_t *hook)
{
    kp_a32_ctx_t ctx;
    ctx.origin_addr = hook->origin_addr;
    ctx.relo_addr = hook->relo_addr;
    ctx.tramp_insts_num = hook->tramp_insts_num;
    ctx.relo_insts_num = hook->relo_insts_num;
    ctx.origin_insts = hook->origin_insts;
    return ctx;
}

/*
 * Arch-neutral entry point retained for symmetry with the AArch64 path: on
 * ARM32 every tramp fixup happens inside kp_a32_relocate_inst() via the shared
 * kp_a32_relo_in_tramp(), so this wrapper currently has no in-tree caller.
 */
static uint64_t relo_in_tramp(hook_t *hook, uint64_t addr) __attribute__((unused));

static uint64_t relo_in_tramp(hook_t *hook, uint64_t addr)
{
    kp_a32_ctx_t ctx = a32_ctx_from_hook(hook);
    return kp_a32_relo_in_tramp(&ctx, addr);
}

#else

static uint64_t relo_in_tramp(hook_t *hook, uint64_t addr)
{
    uint64_t tramp_start = hook->origin_addr;
    uint64_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (!(addr >= tramp_start && addr < tramp_end)) return addr;
    uint32_t addr_inst_index = (addr - tramp_start) / 4;
    uint64_t fix_addr = hook->relo_addr;
    for (int i = 0; i < addr_inst_index; i++) {
        inst_type_t inst = hook->origin_insts[i];
        for (int j = 0; j < sizeof(relo_len) / sizeof(relo_len[0]); j++) {
            if ((inst & masks[j]) == types[j]) {
                fix_addr += relo_len[j] * 4;
                break;
            }
        }
    }
    return fix_addr;
}

#endif /* CONFIG_ARM */

#ifdef HOOK_INTO_BRANCH_FUNC

static uint64_t branch_func_addr_once(uint64_t addr)
{
    uint64_t ret = addr;
    uint32_t inst = *(uint32_t *)addr;
#if defined(CONFIG_ARM)
    /* Follow a plain A32 B at the entry; other entry forms stay as-is. */
    if ((inst & 0xFF000000u) == 0xEA000000u) {
        ret = addr + 8 + (uint64_t)(kp_a32_sext24(inst & 0xFFFFFFu) * 4);
    }
#else
    if ((inst & MASK_B) == INST_B) {
        uint64_t imm26 = bits32(inst, 25, 0);
        uint64_t imm64 = sign64_extend(imm26 << 2u, 28u);
        ret = addr + imm64;
    } else if (inst == ARM64_BTI_C || inst == ARM64_BTI_J ||
               (inst == ARM64_BTI_JC && !hook_get_mem_from_origin(addr))) {
        ret = addr + 4;
    } else {
    }
#endif
    return ret;
}

uint64_t branch_func_addr(uint64_t addr)
{
    uint64_t ret;
    for (;;) {
        ret = branch_func_addr_once(addr);
        if (ret == addr) break;
        addr = ret;
    }
    return ret;
}

#endif

#if !defined(CONFIG_ARM)

static __noinline hook_err_t relo_b(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    uint64_t imm64;
    if (type == INST_BC) {
        uint64_t imm19 = bits32(inst, 23, 5);
        imm64 = sign64_extend(imm19 << 2u, 21u);
    } else {
        uint64_t imm26 = bits32(inst, 25, 0);
        imm64 = sign64_extend(imm26 << 2u, 28u);
    }
    uint64_t addr = inst_addr + imm64;
    addr = relo_in_tramp(hook, addr);

    uint32_t idx = 0;
    if (type == INST_BC) {
        buf[idx++] = (inst & 0xFF00001F) | 0x40u; // B.<cond> #8
        buf[idx++] = 0x14000006; // B #24
    }
    buf[idx++] = 0x58000051; // LDR X17, #8
    buf[idx++] = 0x14000003; // B #12
    buf[idx++] = addr & 0xFFFFFFFF;
    buf[idx++] = addr >> 32u;
    if (type == INST_BL) {
        buf[idx++] = 0x1000001E; // ADR X30, .
        buf[idx++] = 0x910033DE; // ADD X30, X30, #12
        buf[idx++] = 0xD65F0220; // RET X17
    } else {
        buf[idx++] = 0xD65F0220; // RET X17
    }
    buf[idx++] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_adr(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t xd = bits32(inst, 4, 0);
    uint64_t immlo = bits32(inst, 30, 29);
    uint64_t immhi = bits32(inst, 23, 5);
    uint64_t addr;

    if (type == INST_ADR) {
        addr = inst_addr + sign64_extend((immhi << 2u) | immlo, 21u);
    } else {
        addr = (inst_addr + sign64_extend((immhi << 14u) | (immlo << 12u), 33u)) & 0xFFFFFFFFFFFFF000;
        if (is_in_tramp(hook, addr)) return -HOOK_BAD_RELO;
    }
    buf[0] = 0x58000040u | xd; // LDR Xd, #8
    buf[1] = 0x14000003; // B #12
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_ldr(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t rt = bits32(inst, 4, 0);
    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uint64_t addr = inst_addr + offset;

    if (is_in_tramp(hook, addr) && type != INST_PRFM_LIT) return -HOOK_BAD_RELO;

    addr = relo_in_tramp(hook, addr);

    if (type == INST_LDR_32 || type == INST_LDR_64 || type == INST_LDRSW_LIT) {
        buf[0] = 0x58000060u | rt; // LDR Xt, #12
        if (type == INST_LDR_32) {
            buf[1] = 0xB9400000 | rt | (rt << 5u); // LDR Wt, [Xt]
        } else if (type == INST_LDR_64) {
            buf[1] = 0xF9400000 | rt | (rt << 5u); // LDR Xt, [Xt]
        } else {
            // LDRSW_LIT
            buf[1] = 0xB9800000 | rt | (rt << 5u); // LDRSW Xt, [Xt]
        }
        buf[2] = 0x14000004; // B #16
        buf[3] = ARM64_NOP;
        buf[4] = addr & 0xFFFFFFFF;
        buf[5] = addr >> 32u;
    } else {
        buf[0] = 0xA93F47F0; // STP X16, X17, [SP, -0x10]
        buf[1] = 0x58000091; // LDR X17, #16
        if (type == INST_PRFM_LIT) {
            buf[2] = 0xF9800220 | rt; // PRFM Rt, [X17]
        } else if (type == INST_LDR_SIMD_32) {
            buf[2] = 0xBD400220 | rt; // LDR St, [X17]
        } else if (type == INST_LDR_SIMD_64) {
            buf[2] = 0xFD400220 | rt; // LDR Dt, [X17]
        } else {
            // LDR_SIMD_128
            buf[2] = 0x3DC00220u | rt; // LDR Qt, [X17]
        }
        buf[3] = 0xF85F83F1; // LDR X17, [SP, -0x8]
        buf[4] = 0x14000004; // B #16
        buf[5] = ARM64_NOP;
        buf[6] = addr & 0xFFFFFFFF;
        buf[7] = addr >> 32u;
    }
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_cb(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uint64_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFF00001F) | 0x40u; // CB(N)Z Rt, #8
    buf[1] = 0x14000005; // B #20
    buf[2] = 0x58000051; // LDR X17, #8
    buf[3] = 0xD65F0220; // RET X17
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_tb(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint64_t imm14 = bits32(inst, 18, 5);
    uint64_t offset = sign64_extend((imm14 << 2u), 16u);
    uint64_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFFF8001F) | 0x40u; // TB(N)Z Rt, #<imm>, #8
    buf[1] = 0x14000005; // B #20
    buf[2] = 0x58000051; // LDR X17, #8
    buf[3] = 0xd61f0220; // RET X17
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_ignore(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    buf[0] = inst;
    buf[1] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static uint32_t can_b_rel(uint64_t src_addr, uint64_t dst_addr)
{
#define B_REL_RANGE ((1 << 25) << 2)
    return ((dst_addr >= src_addr) & (dst_addr - src_addr <= B_REL_RANGE)) ||
           ((src_addr >= dst_addr) & (src_addr - dst_addr <= B_REL_RANGE));
}

int32_t branch_relative(uint32_t *buf, uint64_t src_addr, uint64_t dst_addr)
{
    if (can_b_rel(src_addr, dst_addr)) {
        buf[0] = 0x14000000u | (((dst_addr - src_addr) & 0x0FFFFFFFu) >> 2u); // B <label>
        buf[1] = ARM64_NOP;
        return 2;
    }
    return 0;
}
KP_EXPORT_SYMBOL(branch_relative);

int32_t branch_absolute(uint32_t *buf, uint64_t addr)
{
    buf[0] = 0x58000051; // LDR X17, #8
    buf[1] = 0xd61f0220; // BR X17
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 4;
}
KP_EXPORT_SYMBOL(branch_absolute);

int32_t ret_absolute(uint32_t *buf, uint64_t addr)
{
    buf[0] = 0x58000051; // LDR X17, #8
    buf[1] = 0xD65F0220; // RET X17
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 4;
}
KP_EXPORT_SYMBOL(ret_absolute);

int32_t branch_from_to(uint32_t *tramp_buf, uint64_t src_addr, uint64_t dst_addr)
{
    int32_t len = branch_relative(tramp_buf, src_addr, dst_addr);
    if (len) return len;
    return ret_absolute(tramp_buf, dst_addr);
}

#else /* CONFIG_ARM */

/*
 * AArch32 jump-stub emitters.
 *
 * `branch_absolute`/`ret_absolute` expand to `ldr pc, [pc, #-4]` + the target
 * literal: two words, PC-relative, so no scratch register is clobbered.  The
 * literal is read from the word immediately after the ldr, i.e. PC (instr+8)
 * minus 4.  `branch_relative` uses a plain A32 B when the destination is within
 * +/-32MB and word aligned, and reports 0 otherwise.
 *
 * All four delegate to the pure A32 core above so hook.c cannot drift from the
 * implementation that the host objdump test actually verifies.
 */
int32_t branch_relative(uint32_t *buf, uint64_t src_addr, uint64_t dst_addr)
{
    return kp_a32_branch_relative(buf, src_addr, dst_addr);
}
KP_EXPORT_SYMBOL(branch_relative);

int32_t branch_absolute(uint32_t *buf, uint64_t addr)
{
    return kp_a32_branch_absolute(buf, addr);
}
KP_EXPORT_SYMBOL(branch_absolute);

int32_t ret_absolute(uint32_t *buf, uint64_t addr)
{
    return kp_a32_ret_absolute(buf, addr);
}
KP_EXPORT_SYMBOL(ret_absolute);

int32_t branch_from_to(uint32_t *tramp_buf, uint64_t src_addr, uint64_t dst_addr)
{
    return kp_a32_branch_from_to(tramp_buf, src_addr, dst_addr);
}

#endif /* CONFIG_ARM */

/*
 * ILP32 (arm32): a uint64_t parameter occupies a *register pair* under AAPCS
 * (arg0 = r0:r1, arg1 = r2:r3, further args on the stack, 8-byte aligned).
 * The arm64-style uint64_t transit signatures therefore decoded a 32-bit
 * caller's registers wrongly: with args in r0-r3 (+ stack) the transit read
 * arg1 from r2 and arg2 from the first stack slot, silently dropping r1.
 * Use word-sized parameters on ILP32 so the transit follows the same calling
 * convention as the hooked function, widening into the uint64_t fargs slots.
 * (The transit is entered by register-preserving jumps from the trampoline,
 * so on arm32 this is the kernel's own convention: AAPCS for inline hooks,
 * r0-r6 for sys_call_table entries.)
 */

// transit0
typedef kp_transit_ret_t (*transit0_func_t)();

#define current_inline_hook_chain() ({ \
    uintptr_t chain_va; \
    asm volatile("mov %0, " KP_CHAIN_REG : "=r"(chain_va)); \
    (hook_chain_t *)chain_va; \
})

kp_transit_ret_t __attribute__((section(".transit0.text"))) __attribute__((__noinline__)) _transit0()
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain) return 0;
    hook_fargs0_t fargs;
    fargs.skip_origin = 0;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain0_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit0_func_t origin_func = (transit0_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func();
    }
    for (int32_t i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain0_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    return (kp_transit_ret_t)fargs.ret;
}
#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit0_end();
#endif

// transit4
typedef kp_transit_ret_t (*transit4_func_t)(kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t);

kp_transit_ret_t __attribute__((section(".transit4.text"))) __attribute__((__noinline__))
_transit4(kp_transit_arg_t arg0, kp_transit_arg_t arg1, kp_transit_arg_t arg2, kp_transit_arg_t arg3)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain) return 0;
    hook_fargs4_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain4_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit4_func_t origin_func = (transit4_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
    }
    for (int32_t i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain4_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    return (kp_transit_ret_t)fargs.ret;
}

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit4_end();
#endif

// transit8:
typedef kp_transit_ret_t (*transit8_func_t)(kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t);

kp_transit_ret_t __attribute__((section(".transit8.text"))) __attribute__((__noinline__))
_transit8(kp_transit_arg_t arg0, kp_transit_arg_t arg1, kp_transit_arg_t arg2, kp_transit_arg_t arg3, kp_transit_arg_t arg4, kp_transit_arg_t arg5, kp_transit_arg_t arg6,
          kp_transit_arg_t arg7)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain) return 0;
    hook_fargs8_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain8_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit8_func_t origin_func = (transit8_func_t)hook_chain->hook.relo_addr;
        fargs.ret =
            origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7);
    }
    for (int32_t i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain8_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    return (kp_transit_ret_t)fargs.ret;
}

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit8_end();
#endif

// transit12:
typedef kp_transit_ret_t (*transit12_func_t)(kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t,
                                     kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t, kp_transit_arg_t);

kp_transit_ret_t __attribute__((section(".transit12.text"))) __attribute__((__noinline__))
_transit12(kp_transit_arg_t arg0, kp_transit_arg_t arg1, kp_transit_arg_t arg2, kp_transit_arg_t arg3, kp_transit_arg_t arg4, kp_transit_arg_t arg5, kp_transit_arg_t arg6,
           kp_transit_arg_t arg7, kp_transit_arg_t arg8, kp_transit_arg_t arg9, kp_transit_arg_t arg10, kp_transit_arg_t arg11)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain) return 0;
    hook_fargs12_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.arg8 = arg8;
    fargs.arg9 = arg9;
    fargs.arg10 = arg10;
    fargs.arg11 = arg11;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain12_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit12_func_t origin_func = (transit12_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6,
                                fargs.arg7, fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
    }
    for (int32_t i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain12_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    return (kp_transit_ret_t)fargs.ret;
}

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit12_end();
#endif

static __noinline hook_err_t relocate_inst(hook_t *hook, uint64_t inst_addr, uint32_t inst)
{
    hook_err_t rc = HOOK_NO_ERR;
#if defined(CONFIG_ARM)
    kp_a32_ctx_t ctx = a32_ctx_from_hook(hook);
    int len = kp_a32_relo_len(inst);

    if (kp_a32_relocate_inst(&ctx, hook->relo_insts + hook->relo_insts_num, inst_addr, inst) != KP_A32_OK) {
        logkv("A32 relocate FAILED: unported/unverifiable instruction word %08x at VA %llx\n", inst, inst_addr);
        rc = -HOOK_BAD_RELO;
    }
#else
    inst_type_t it = INST_IGNORE;
    int len = 1;

    for (int j = 0; j < sizeof(relo_len) / sizeof(relo_len[0]); j++) {
        if ((inst & masks[j]) == types[j]) {
            it = types[j];
            len = relo_len[j];
            break;
        }
    }

    switch (it) {
    case INST_B:
    case INST_BC:
    case INST_BL:
        rc = relo_b(hook, inst_addr, inst, it);
        break;
    case INST_ADR:
    case INST_ADRP:
        rc = relo_adr(hook, inst_addr, inst, it);
        break;
    case INST_LDR_32:
    case INST_LDR_64:
    case INST_LDRSW_LIT:
    case INST_PRFM_LIT:
    case INST_LDR_SIMD_32:
    case INST_LDR_SIMD_64:
    case INST_LDR_SIMD_128:
        rc = relo_ldr(hook, inst_addr, inst, it);
        break;
    case INST_CBZ:
    case INST_CBNZ:
        rc = relo_cb(hook, inst_addr, inst, it);
        break;
    case INST_TBZ:
    case INST_TBNZ:
        rc = relo_tb(hook, inst_addr, inst, it);
        break;
    case INST_IGNORE:
    default:
        rc = relo_ignore(hook, inst_addr, inst, it);
        break;
    }
#endif /* CONFIG_ARM */

    hook->relo_insts_num += len;

    return rc;
}

hook_err_t hook_prepare(hook_t *hook)
{
    if (is_bad_address((void *)hook->func_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->origin_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->replace_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->relo_addr)) return -HOOK_BAD_ADDRESS;

    // backup origin instruction
    for (int i = 0; i < TRAMPOLINE_MAX_NUM; i++) {
        hook->origin_insts[i] = *((uint32_t *)hook->origin_addr + i);
    }
    // trampline to replace_addr
#if defined(CONFIG_ARM)
    hook->tramp_insts_num = branch_absolute(hook->tramp_insts, hook->replace_addr);
#else
    if (hook->origin_insts[0] == ARM64_PACIASP || hook->origin_insts[0] == ARM64_PACIBSP) {
        hook->tramp_insts_num = branch_absolute(&hook->tramp_insts[1], hook->replace_addr);
        hook->tramp_insts[0] = ARM64_BTI_JC;
        hook->tramp_insts_num++;
    } else {
        hook->tramp_insts_num = branch_absolute(hook->tramp_insts, hook->replace_addr);
    }
#endif

    // relocate
    for (int i = 0; i < sizeof(hook->relo_insts) / sizeof(hook->relo_insts[0]); i++) {
#if defined(CONFIG_ARM)
        hook->relo_insts[i] = A32_NOP;
#else
        hook->relo_insts[i] = ARM64_NOP;
#endif
    }

    for (int i = 0; i < hook->tramp_insts_num; i++) {
        uint64_t inst_addr = hook->origin_addr + i * 4;
        uint32_t inst = hook->origin_insts[i];
        hook_err_t relo_res = relocate_inst(hook, inst_addr, inst);
        if (relo_res) {
            return -HOOK_BAD_RELO;
        }
    }

    // jump back
    uint64_t back_src_addr = hook->relo_addr + hook->relo_insts_num * 4;
    uint64_t back_dst_addr = hook->origin_addr + hook->tramp_insts_num * 4;
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    hook->relo_insts_num += branch_from_to(buf, back_src_addr, back_dst_addr);
    return HOOK_NO_ERR;
}
KP_EXPORT_SYMBOL(hook_prepare);

void hook_install(hook_t *hook)
{
    void *addrs[TRAMPOLINE_MAX_NUM];
    for (int32_t i = 0; i < hook->tramp_insts_num; ++i) {
        addrs[i] = (uint32_t *)hook->origin_addr + i;
    }
    hotpatch(addrs, hook->tramp_insts, hook->tramp_insts_num);
}
KP_EXPORT_SYMBOL(hook_install);

void hook_uninstall(hook_t *hook)
{
    void *addrs[TRAMPOLINE_MAX_NUM];
    for (int32_t i = 0; i < hook->tramp_insts_num; ++i) {
        addrs[i] = (uint32_t *)hook->origin_addr + i;
    }
    hotpatch(addrs, hook->origin_insts, hook->tramp_insts_num);
}
KP_EXPORT_SYMBOL(hook_uninstall);

hook_err_t hook(void *func, void *replace, void **backup)
{
    hook_err_t err = HOOK_NO_ERR;
    if (!func || !replace || !backup) {
        return -HOOK_BAD_ADDRESS;
    }
    uint64_t origin_addr = branch_func_addr((uintptr_t)func);
    hook_t *hook = (hook_t *)hook_mem_zalloc(origin_addr, INLINE);
    if (!hook) return -HOOK_NO_MEM;
    hook->func_addr = (uint64_t)func;
    hook->origin_addr = origin_addr;
    hook->replace_addr = (uint64_t)replace;
    hook->relo_addr = (uint64_t)hook->relo_insts;
    *backup = (void *)hook->relo_addr;
    logkv("Hook func: %llx, origin: %llx, replace: %llx, relocate: %llx, chain: %llx\n", hook->func_addr,
          hook->origin_addr, hook->replace_addr, hook->relo_addr, (uint64_t)hook);
    err = hook_prepare(hook);
    if (err) goto out;
    hook_install(hook);
    logkv("Hook func: %llx succsseed\n", hook->func_addr);
    return HOOK_NO_ERR;
out:
    hook_mem_free(hook);
    logkv("Hook func: %llx failed, err: %d\n", hook->func_addr, err);
    return err;
}
KP_EXPORT_SYMBOL(hook);

void unhook(void *func)
{
    uint64_t origin = branch_func_addr((uint64_t)func);
    hook_t *hook = hook_get_mem_from_origin(origin);
    if (!hook) return;
    hook_uninstall(hook);
    hook_mem_free(hook);
    logkv("Unhook func: %llx\n", (uint64_t)func);
}
KP_EXPORT_SYMBOL(unhook);

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno)
{
    uint64_t transit_start, transit_end;
    switch (argno) {
    case 0:
        transit_start = (uint64_t)_transit0;
        transit_end = (uint64_t)_transit0_end;
        break;
    case 1:
    case 2:
    case 3:
    case 4:
        transit_start = (uint64_t)_transit4;
        transit_end = (uint64_t)_transit4_end;
        break;
    case 5:
    case 6:
    case 7:
    case 8:
        transit_start = (uint64_t)_transit8;
        transit_end = (uint64_t)_transit8_end;
        break;
    default:
        transit_start = (uint64_t)_transit12;
        transit_end = (uint64_t)_transit12_end;
        break;
    }

    int32_t transit_num = (transit_end - transit_start) / 4;
    // todo:assert
    if (transit_num + 6 > TRANSIT_INST_NUM) return -HOOK_TRANSIT_NO_MEM;

    hook_chain_t *chain = local_container_of(transit, hook_chain_t, transit);
    kp_chain_transit_header(transit, chain);
    for (int i = 0; i < transit_num; i++) {
        transit[i + 6] = ((uint32_t *)transit_start)[i];
    }
    return HOOK_NO_ERR;
}
#else
static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno);
#endif

hook_err_t hook_chain_add(hook_chain_t *chain, void *before, void *after, void *udata)
{
    for (int i = 0; i < HOOK_CHAIN_NUM; i++) {
        if ((before && chain->befores[i] == before) || (after && chain->afters[i] == after)) return -HOOK_DUPLICATED;

        // todo: atomic or lock
        if (chain->states[i] == CHAIN_ITEM_STATE_EMPTY) {
            chain->states[i] = CHAIN_ITEM_STATE_BUSY;
            dsb(ish);
            chain->udata[i] = udata;
            chain->befores[i] = before;
            chain->afters[i] = after;
            if (i + 1 > chain->chain_items_max) {
                chain->chain_items_max = i + 1;
            }
            dsb(ish);
            chain->states[i] = CHAIN_ITEM_STATE_READY;
            logkv("Wrap chain add: %llx, %llx, %llx successed\n", chain->hook.func_addr, (uint64_t)before, (uint64_t)after);
            return HOOK_NO_ERR;
        }
    }
    logkv("Wrap chain add: %llx, %llx, %llx failed\n", chain->hook.func_addr, (uint64_t)before, (uint64_t)after);
    return -HOOK_CHAIN_FULL;
}
KP_EXPORT_SYMBOL(hook_chain_add);

void hook_chain_remove(hook_chain_t *chain, void *before, void *after)
{
    for (int i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (chain->states[i] == CHAIN_ITEM_STATE_READY)
            if ((before && chain->befores[i] == before) || (after && chain->afters[i] == after)) {
                chain->states[i] = CHAIN_ITEM_STATE_BUSY;
                dsb(ish);
                chain->udata[i] = 0;
                chain->befores[i] = 0;
                chain->afters[i] = 0;
                dsb(ish);
                chain->states[i] = CHAIN_ITEM_STATE_EMPTY;
                break;
            }
    }
    logkv("Wrap chain remove: %llx, %llx, %llx\n", chain->hook.func_addr, (uint64_t)before, (uint64_t)after);
}
KP_EXPORT_SYMBOL(hook_chain_remove);

// todo: lock
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata)
{
    if (is_bad_address(func)) return -HOOK_BAD_ADDRESS;
    uint64_t faddr = (uint64_t)func;
    uint64_t origin = branch_func_addr(faddr);
    if (is_bad_address(func)) return -HOOK_BAD_ADDRESS;
    hook_chain_t *chain = (hook_chain_t *)hook_get_mem_from_origin(origin);
    if (chain) return hook_chain_add(chain, before, after, udata);
    chain = (hook_chain_t *)hook_mem_zalloc(origin, INLINE_CHAIN);
    if (!chain) return -HOOK_NO_MEM;
    chain->chain_items_max = 0;
    hook_t *hook = &chain->hook;
    hook->func_addr = faddr;
    hook->origin_addr = origin;
    hook->replace_addr = (uint64_t)chain->transit;
    hook->relo_addr = (uint64_t)hook->relo_insts;
    logkv("Wrap func: %llx, origin: %llx, replace: %llx, relocate: %llx, chain: %llx\n", hook->func_addr,
          hook->origin_addr, hook->replace_addr, hook->relo_addr, (uint64_t)chain);
    hook_err_t err = hook_prepare(hook);
    if (err) goto err;
    err = hook_chain_prepare(chain->transit, argno);
    if (err) goto err;
    err = hook_chain_add(chain, before, after, udata);
    if (err) goto err;
    hook_chain_install(chain);
    logkv("Wrap func: %llx succsseed\n", hook->func_addr);
    return HOOK_NO_ERR;
err:
    hook_mem_free(chain);
    logkv("Wrap func: %llx failed, err: %d\n", hook->func_addr, err);
    return err;
}
KP_EXPORT_SYMBOL(hook_wrap);

void hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
    if (is_bad_address(func)) return;
    uint64_t faddr = (uint64_t)func;
    uint64_t origin = branch_func_addr(faddr);
    if (is_bad_address(func)) return;
    hook_chain_t *chain = (hook_chain_t *)hook_get_mem_from_origin(origin);
    if (!chain) return;
    hook_chain_remove(chain, before, after);
    if (!remove) return;
    // todo:
    for (int i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (chain->states[i] != CHAIN_ITEM_STATE_EMPTY) return;
    }
    hook_chain_uninstall(chain);
    // todo: unsafe
    hook_mem_free(chain);
    logkv("Unwrap func: %llx\n", (uint64_t)func);
}
KP_EXPORT_SYMBOL(hook_unwrap_remove);
