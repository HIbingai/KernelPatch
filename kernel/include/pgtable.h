/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_PGTABLE_H_
#define _KP_PGTABLE_H_

#include <ktypes.h>

#if defined(CONFIG_ARM)

/* =====================================================================
 * AArch32 / ARMv7-A, non-LPAE: short-descriptor ("VMSA") page tables.
 *
 * Short descriptors are one 32-bit word, so every entry below is a uintptr_t
 * (32 bits on AArch32) and a walk is at most two levels.  There is no
 * PUD/PMD/four-level-table/TCR_EL1 concept at all; those arm64 notions are
 * collapsed, never emulated (see the notes on the individual names).
 *
 * Measured on the target -- port/device_facts.md, M4b.  Do not re-derive:
 *   - TTBCR == 0.  The 4.9.193 image never writes TTBCR (`mcr p15,0,Rt,c2,c0,2`
 *     has zero sites), so N keeps its reset value 0 and TTBR0 covers the whole
 *     4 GB: ONE 4096-entry L1 table indexed by `va >> 20` (1 MB sections),
 *     NOT the `va >> 21` TTBR0/TTBR1 split.
 *   - L1 base VA = (TTBR0 & 0xFFFFC000) + linear_voffset.
 *   - 1 MB section: [1:0]=0b10 type, [4]=XN, [11:10]=AP[1:0], [15]=AP[2],
 *     [31:20]=base.  A live kernel RWX section reads 0x41911c0e, i.e.
 *     attributes 0x11c0e: TEX=001, C=1, B=1, AP[1:0]=11, AP[2]=0, XN=0, S=1,
 *     domain=0.  XN (bit 4) is the bit that controls executability.
 *   - paging_init() runs BEFORE map_lowmem(), so the L1 slot of a freshly
 *     memblock-allocated page still reads 0 (unmapped): such a mapping must
 *     be self-installed -- write the descriptor, then DSB + TLBIALL
 *     (kp_l1_install_section() below).
 * ===================================================================== */

/* ---- descriptor type, bits[1:0] (L1 section/table, L2 small page) ---- */
#define PTE_TYPE_MASK  (3lu << 0)
#define PTE_TYPE_FAULT (0lu << 0) /* not present */
#define PTE_TYPE_TABLE (1lu << 0) /* L1 entry -> L2 coarse page table */
#define PTE_TYPE_SECT  (2lu << 0) /* 1 MB section: the kernel-image leaf */
#define PTE_TYPE_PAGE  (2lu << 0) /* L2 small page (4 KB): same type field */

/* arm64's `PTE_VALID == bit 0` test does not transfer: a 1 MB section (type
 * 0b10) has bit 0 clear.  "Present" is a type test here, so PTE_VALID and
 * PTE_TABLE_BIT are deliberately not defined -- use this instead. */
#define pte_valid(pte) (((pte) & PTE_TYPE_MASK) != 0)

/* ---- 1 MB section attributes ---- */
#define PTE_B              (1lu << 2)              /* B */
#define PTE_C              (1lu << 3)              /* C */
#define PTE_XN             (1lu << 4)              /* XN: execute-never */
#define PTE_DOMAIN_SHIFT   5
#define PTE_DOMAIN_MASK    (0xful << 5)            /* domain[3:0] */
#define PTE_DOMAIN(dom)    (((dom) & 0xful) << PTE_DOMAIN_SHIFT)
#define PTE_AP0            (1lu << 10)             /* AP[0] */
#define PTE_AP1            (1lu << 11)             /* AP[1] */
#define PTE_AP2            (1lu << 15)             /* AP[2]: 1 = PL1 RO */
#define PTE_S              (1lu << 16)             /* S: shareable */
#define PTE_NG             (1lu << 17)             /* nG: not global */
#define PTE_TEX(tex)       (((tex) & 0x7ul) << 12) /* TEX[2:0], bits[14:12] */
#define PTE_SECT_BASE_MASK (0xfff00000lu)          /* base, bits[31:20] */

/* Attributes of a live, known-good kernel RWX section (XN already clear). */
#define KP_SECTION_ATTR_RWX 0x11c0eu

/* ---- arm64 names -> AArch32 short-descriptor equivalents ----
 * The shared code uses PTE_RDONLY/PTE_DBM (base/hotpatch.c) and PTE_SHARED/
 * PTE_PXN/PTE_GP/PTE_RDONLY/PTE_DBM (base/start.c). */
#define PTE_RDONLY PTE_AP2 /* AP[2] denies PL1 writes -- same sense as arm64 */
#define PTE_USER   PTE_AP1 /* AP[1] grants PL0 access */
#define PTE_SHARED PTE_S   /* arm64 SH[1:0] inner-shareable -> ARMv7 S bit */
#define PTE_PXN    PTE_XN  /* arm64 privileged-XN -> ARMv7 XN; a section has a
                            * single XN bit and it applies to every privilege */
#define PTE_UXN    PTE_XN
/*
 * Collapsed to 0 -- no AArch32 counterpart, the same approach the x86 branch
 * above takes:
 *   PTE_DBM / PTE_WRITE  there is no dirty-bit management: writability *is*
 *                        AP[2]==0, which is exactly what `| PTE_DBM` plus
 *                        `& ~PTE_RDONLY` expresses.
 *   PTE_GP               no BTI-guarded page concept.
 *   PTE_AF               short descriptors have no Access Flag field.
 *   PTE_CONT             short descriptors have no contiguous hint.
 * (PTE_NG is NOT collapsed: it exists at bit 17 -- arm64 puts it at bit 11.)
 */
#define PTE_DBM   0
#define PTE_WRITE 0
#define PTE_GP    0
#define PTE_AF    0
#define PTE_CONT  0

/*
 * No contiguous hint.  Upstream hotpatch.c only asks pte_valid_cont() whether
 * it must touch a whole contiguous run, so "never" makes it take its
 * single-entry path, which is right for one 32-bit L1 entry.
 */
#define pte_valid_cont(pte) 0
#define CONT_PTES      1
#define CONT_PTE_SIZE  (CONT_PTES * page_size)
#define CONT_PTE_MASK  (~0ul)

#define sev() asm volatile("sev" ::: "memory")
#define wfe() asm volatile("wfe" ::: "memory")
#define wfi() asm volatile("wfi" ::: "memory")

#define isb() asm volatile("isb" ::: "memory")
/* ARMv7 DSB/DMB take the same option names the rest of this port already uses
 * (sy/st/ld/ish/ishst/ishld/nsh/osh/...), so shared call sites such as
 * `dsb(ish)` still expand to valid ARMv7. */
#define dmb(opt) asm volatile("dmb " #opt ::: "memory")
#define dsb(opt) asm volatile("dsb " #opt ::: "memory")

/* ---- TLB maintenance ---- */
/* TLBIALL (c8,c7,0): invalidate the whole unified TLB.  AArch32 has no
 * EL-scoped TLBI ops and KP does not manage ASIDs. */
static inline void local_flush_tlb_all(void)
{
    dsb(sy);
    asm volatile("mcr p15, 0, %0, c8, c7, 0" ::"r"(0) : "memory");
    dsb(sy);
    isb();
}

static inline void flush_tlb_all(void)
{
    local_flush_tlb_all();
}

/* TLBIMVAA's operand is {ASID[7:0], MVA[31:12]}; there is nothing like
 * arm64's packed TLBI argument encoding, so this is only a naming shim. */
static inline uint64_t tlbi_vaddr(uint64_t addr, uint64_t asid)
{
    return (addr & ~0xfffull) | (asid & 0xffu);
}

/* arch/arm itself implements flush_tlb_kernel_range() as flush_tlb_all(), and
 * without ASID tracking a range cannot be flushed precisely, so do the same.
 * TLBIALL is likewise the only unambiguously correct invalidation for a
 * single address here: TLBIMVA is current-ASID only and TLBIMVAA needs ASIDs
 * KP does not use. */
static inline void flush_tlb_kernel_range(uint64_t start, uint64_t end)
{
    (void)start;
    (void)end;
    local_flush_tlb_all();
}

static inline void flush_tlb_kernel_page(uint64_t addr)
{
    (void)addr;
    local_flush_tlb_all();
}

extern uint64_t kimage_voffset;
extern uint64_t linear_voffset;
extern uint64_t kernel_va;
extern uint64_t kernel_pa;
extern int64_t kernel_size;
extern int64_t page_shift;
extern int64_t page_size;
extern int64_t va_bits;
extern int64_t page_level;
extern uint64_t pgd_pa;
extern uint64_t pgd_va;

/*
 * AArch32 has ONE flat linear map: the kernel image lives inside it, so there
 * is no separate image/vmalloc window as on arm64.  The port's map code sets
 * kimage_voffset = kernel_va - kernel_pa (== linear_voffset; see base/map.c),
 * which is why has_vmalloc_area() is false here and the *_kimg helpers
 * collapse onto the same offset.  va_bits is 32 and page_level is 2.
 */

static inline uint64_t phys_to_virt(uint64_t phys)
{
    return phys + linear_voffset;
}

static inline uint64_t virt_to_phys(uint64_t virt)
{
    return virt - linear_voffset;
}

static inline uint64_t phys_to_kimg(uint64_t phys)
{
    return phys + kimage_voffset;
}

static inline uint64_t kimg_to_phys(uint64_t addr)
{
    return addr - kimage_voffset;
}

static inline int has_vmalloc_area(void)
{
    /* Always false on AArch32 (single flat map, see the note above).  Kept as
     * an expression so it stays correct if a port ever separates the two. */
    return kimage_voffset != linear_voffset;
}

static inline uint64_t kp_kimg_to_phys(uint64_t addr)
{
    return addr - kimage_voffset;
}

static inline int is_kimg_range(uint64_t addr)
{
    return addr >= kernel_va && addr < (kernel_va + kernel_size);
}

/* ---- L1 (short-descriptor) access ---- */

#define KP_L1_ENTRIES 4096 /* TTBCR.N == 0 -> one table covers all 4 GB */

static inline uint32_t kp_read_ttbr0(void)
{
    uint32_t val;
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(val));
    return val;
}

static inline uint32_t kp_read_ttbcr(void)
{
    uint32_t val;
    asm volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(val));
    return val;
}

/* VA of the L1 table: TTBR0 holds its PA; +linear_voffset to reach it. */
static inline uint64_t kp_l1_base(void)
{
    return (uint64_t)((kp_read_ttbr0() & 0xffffc000u) + (uint32_t)linear_voffset);
}

/* L1 index: 1 MB sections, `va >> 20` -- NOT `va >> 21`. */
static inline uint32_t kp_l1_index(uint64_t va)
{
    return (uint32_t)(va >> 20) & (KP_L1_ENTRIES - 1);
}

/*
 * The single L1 slot for a VA.  This *is* the whole walk on AArch32, and it
 * is the slot that must be filled in when paging_init() runs before
 * map_lowmem().
 */
static inline uintptr_t *kp_l1_slot(uint64_t va)
{
    return &((uintptr_t *)(uintptr_t)kp_l1_base())[kp_l1_index(va)];
}

/*
 * Install a 1 MB section mapping for `va` and make it live.  `attrs` is the
 * low 20 bits of the descriptor: copy them from a live known-good section
 * (KP_SECTION_ATTR_RWX, whose XN is already clear) rather than re-deriving
 * TEX/C/B/AP/domain.  Self-installation is mandatory for memory allocated
 * before map_lowmem(): its slot reads 0.
 */
static inline void kp_l1_install_section(uint64_t va, uint64_t pa, uintptr_t attrs)
{
    uintptr_t *slot = kp_l1_slot(va);
    *slot = ((uintptr_t)pa & PTE_SECT_BASE_MASK) | (attrs & 0xfffffu);
    dsb(sy);
    local_flush_tlb_all();
}

/*
 * PA behind a kernel VA, following the same single-table model.  L1 entry
 * types: 0b10 = 1 MB section (leaf), 0b01 = coarse page table whose 256
 * entries are 4 KB small pages, 0b00 = fault.  Only those two leaf types are
 * handled (the target maps 4 KB pages and 1 MB sections).
 */
static inline uint64_t kp_va_to_phys(uint64_t va)
{
    uintptr_t l1 = *kp_l1_slot(va);
    if ((l1 & PTE_TYPE_MASK) == PTE_TYPE_SECT) return (uint64_t)(l1 & PTE_SECT_BASE_MASK) | (va & 0xfffffu);
    if ((l1 & PTE_TYPE_MASK) == PTE_TYPE_TABLE) {
        uintptr_t *l2 = (uintptr_t *)(uintptr_t)phys_to_virt(l1 & 0xfffffc00u);
        uintptr_t pte = l2[(va >> 12) & 0xffu];
        if ((pte & PTE_TYPE_MASK) != PTE_TYPE_PAGE) return 0;
        return (uint64_t)(pte & 0xfffff000u) | (va & 0xfffu);
    }
    return 0;
}

/* ---- accessors ----
 * `pgd` is the L1 base VA (pgd_va), so on AArch32 pgtable_entry() is simply
 * the L1 slot, i.e. kp_l1_slot().  The pgd-parameterised pair is still
 * declared here because base/start.c defines it (KP_EXPORT_SYMBOL); its ARM
 * implementation must return 32-bit entries, not 64-bit ones.  The _kernel
 * forms are self-contained below so that text patching does not depend on
 * start.c's (arm64-only) four-level walk. */
uintptr_t *pgtable_entry(uint64_t pgd, uint64_t va);
uint64_t pgtable_phys(uint64_t pgd, uint64_t va);

static inline uintptr_t *pgtable_entry_kernel(uint64_t va)
{
    return kp_l1_slot(va);
}

static inline uint64_t pgtable_phys_kernel(uint64_t va)
{
    return kp_va_to_phys(va);
}

#elif defined(CONFIG_X86_64)

/* x86_64 PTE bits (4-level paging, 4K pages).
 *
 * Several arm64 PTE names have no x86 equivalent with the same polarity, so they
 * are deliberately not defined here rather than aliased to a bit that means the
 * opposite:
 *   PTE_RDONLY  arm64 sets it to deny writes, x86 bit 1 grants them.  Use
 *               PTE_WRITE and clear it instead.
 *   PTE_NG      arm64 sets it to make an entry non-global, x86 bit 8 (PTE_GLOBAL)
 *               sets it to make one global.  Opposite sense.
 *   PTE_TYPE_*  x86 has no page/table type field in a leaf entry.
 */
#define PTE_VALID    (1ul << 0)   /* Present */
#define PTE_WRITE    (1ul << 1)   /* R/W: set means writable */
#define PTE_USER     (1ul << 2)   /* U/S */
#define PTE_AF       (1ul << 5)   /* Accessed */
#define PTE_DIRTY    (1ul << 6)   /* Dirty */
#define PTE_GLOBAL   (1ul << 8)   /* Global: not flushed by a CR3 reload */
#define PTE_PXN      (1ul << 63)  /* NX (No-Execute) */
#define PTE_SHARED   (0)
#define PTE_GP       (0)
#define PTE_TABLE_BIT (1ul << 0)
#define PTE_CONT     (0)

#define pte_valid_cont(pte) 0

#define CONT_PTES      1
#define CONT_PTE_MASK  (~0ul)

#define sev() asm volatile("" ::: "memory")
#define wfe() asm volatile("pause" ::: "memory")
#define wfi() asm volatile("hlt" ::: "memory")

#define isb()  asm volatile("" ::: "memory")
#define dmb(opt) asm volatile("mfence" ::: "memory")
#define dsb(opt) asm volatile("mfence" ::: "memory")

/* A CR3 reload does not invalidate global entries, and kernel text and data are
 * mapped global on x86, so toggling CR4.PGE is the only way to flush everything.
 * Mirrors the kernel's own __native_flush_tlb_global(). */
static inline void local_flush_tlb_all(void)
{
    uint64_t cr4;
    asm volatile("movq %%cr4, %0" : "=r"(cr4));
    if (cr4 & (1ul << 7)) { /* CR4.PGE */
        asm volatile("movq %0, %%cr4" ::"r"(cr4 & ~(1ul << 7)) : "memory");
        asm volatile("movq %0, %%cr4" ::"r"(cr4) : "memory");
    } else {
        uint64_t cr3;
        asm volatile("movq %%cr3, %0" : "=r"(cr3));
        asm volatile("movq %0, %%cr3" ::"r"(cr3) : "memory");
    }
}

static inline void flush_tlb_all(void)
{
    local_flush_tlb_all();
}

static inline uint64_t tlbi_vaddr(uint64_t addr, uint64_t asid)
{
    (void)asid;
    return addr >> 12;
}

extern uint64_t kimage_voffset;
extern uint64_t linear_voffset;
extern uint64_t kernel_va;
extern uint64_t kernel_pa;
extern int64_t kernel_size;
extern int64_t page_shift;
extern int64_t page_size;
extern int64_t va_bits;
extern int64_t page_level;
extern uint64_t pgd_pa;
extern uint64_t pgd_va;

static inline uint64_t phys_to_virt(uint64_t phys)
{
    return phys + linear_voffset;
}

static inline uint64_t virt_to_phys(uint64_t virt)
{
    return virt - linear_voffset;
}

static inline uint64_t phys_to_kimg(uint64_t phys)
{
    return phys + kimage_voffset;
}

static inline uint64_t kimg_to_phys(uint64_t addr)
{
    return addr - kimage_voffset;
}

static inline int has_vmalloc_area(void)
{
    return kimage_voffset != linear_voffset;
}

static inline uint64_t kp_kimg_to_phys(uint64_t addr)
{
    return addr - kimage_voffset;
}

/* invlpg does invalidate global entries, so a per-page walk is correct here.
 * Bail out to a full flush for large ranges rather than loop over them. */
#define X86_TLB_SINGLE_PAGE_LIMIT 33

static inline void flush_tlb_kernel_range(uint64_t start, uint64_t end)
{
    if (end <= start) return;
    uint64_t first = start >> 12;
    uint64_t last = (end + 0xfff) >> 12;
    if (last - first > X86_TLB_SINGLE_PAGE_LIMIT) {
        local_flush_tlb_all();
        return;
    }
    for (uint64_t i = first; i < last; i++) asm volatile("invlpg (%0)" ::"r"(i << 12) : "memory");
}

static inline void flush_tlb_kernel_page(uint64_t addr)
{
    asm volatile("invlpg (%0)" :: "r"(addr) : "memory");
}

static inline int is_kimg_range(uint64_t addr)
{
    return addr >= kernel_va && addr < (kernel_va + kernel_size);
}

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);
uint64_t pgtable_phys(uint64_t pgd, uint64_t va);

static inline uint64_t *pgtable_entry_kernel(uint64_t va)
{
    return pgtable_entry(pgd_va, va);
}

static inline uint64_t pgtable_phys_kernel(uint64_t va)
{
    return pgtable_phys(pgd_va, va);
}

#else /* ARM64 */

#define MT_DEVICE_nGnRnE
#define MT_DEVICE_nGnRE
#define MT_DEVICE_GRE
#define MT_NORMAL_NC
#define MT_NORMAL
#define MT_NORMAL_WT

#define PTE_VALID (1ul << 0)
#define PTE_TYPE_MASK (3ul << 0)
#define PTE_TYPE_PAGE (3ul << 0)
#define PTE_TABLE_BIT (1ul << 1)
#define PTE_ATTRINDX(t) (t << 2) /* AttrIndx[2:0] encoding (mapping attributes defined in the MAIR_EL* registers */
#define PTE_NS (1ul << 5) /* Non-Secure access control */
#define PTE_USER (1ul << 6) /* AP[1] */
#define PTE_RDONLY (1ul << 7) /* AP[2] */
#define PTE_SHARED (3ul << 8) /* SH[1:0], inner shareable */
#define PTE_AF (1ul << 10) /* Access Flag */
#define PTE_NG (1ul << 11) /* nG */
#define PTE_GP (1ul << 50) /* BTI guarded */
#define PTE_DBM (1ul << 51) /* Dirty Bit Management */
#define PTE_CONT (1ul << 52) /* Contiguous range */
#define PTE_PXN (1ul << 53) /* Privileged XN */
#define PTE_UXN (1ul << 54) /* User XN */

#define PTE_WRITE (PTE_DBM) /* same as DBM (51) */
#define PTE_SWP_EXCLUSIVE (1ul << 2) /* only for swp ptes */
#define PTE_DIRTY (1ul << 55) /* software dirty in some version */
#define PTE_SPECIAL (1ul << 56)
#define PTE_DEVMAP (1ul << 57)
#define PTE_PROT_NONE (1ul << 58) /* only when !PTE_VALID */

#define PMD_PRESENT_INVALID (1ul << 59) /* only when !PMD_SECT_VALID */

#define PTATTR_PXN (1ul << 59)
#define PTATTR_XN (1ul << 60)
#define PTATTR_USER (1ul << 61) /* AP[1] read not premited in el0*/
#define PTATTR_RDONLY (1ul << 62) /* AP[2], write note permited at any exception level*/
#define PTATTR_NS (1ul << 63) /* Indicates whether the table identifier is located in Secure PA space */

#define pte_valid_cont(pte) (((pte) & (PTE_VALID | PTE_TABLE_BIT | PTE_CONT)) == (PTE_VALID | PTE_TABLE_BIT | PTE_CONT))

#define CONT_PTE_SHIFT (4 + page_shift)
#define CONT_PTES (1 << (CONT_PTE_SHIFT - page_shift))
#define CONT_PTE_SIZE (CONT_PTES * page_size)
#define CONT_PTE_MASK (~(CONT_PTE_SIZE - 1))

#define mask_ul(h, l) (((~0ul) << (l)) & (~0ul >> (63 - (h))))

#define sev() asm volatile("sev" : : : "memory")
#define wfe() asm volatile("wfe" : : : "memory")
#define wfi() asm volatile("wfi" : : : "memory")

#define isb() asm volatile("isb" : : : "memory")
#define dmb(opt) asm volatile("dmb " #opt : : : "memory")
#define dsb(opt) asm volatile("dsb " #opt : : : "memory")

#define tlbi_0(op)       \
    asm("tlbi " #op "\n" \
        "dsb ish\n"      \
        "tlbi " #op "\n")

#define tlbi_1(op, arg)      \
    asm("tlbi " #op ", %0\n" \
        "dsb ish\n"          \
        "tlbi " #op ", %0\n" \
        :                    \
        : "r"(arg))

static inline void local_flush_tlb_all(void)
{
    dsb(nshst);
    tlbi_0(vmalle1);
    dsb(nsh);
    isb();
}

static inline void flush_tlb_all(void)
{
    dsb(ishst);
    tlbi_0(vmalle1is);
    dsb(ish);
    isb();
}

// __TLBI_VADDR
static inline uint64_t tlbi_vaddr(uint64_t addr, uint64_t asid)
{
    uint64_t x = addr >> 12;
    x &= mask_ul(43, 0);
    x |= asid << 48;
    return x;
}

extern uint64_t kimage_voffset;
extern uint64_t linear_voffset;
extern uint64_t kernel_va;
extern uint64_t kernel_pa;
extern int64_t kernel_size;
extern int64_t page_shift;
extern int64_t page_size;
extern int64_t va_bits;
extern int64_t page_level;
extern uint64_t pgd_pa;
extern uint64_t pgd_va;
// extern int64_t pa_bits;

static inline uint64_t phys_to_virt(uint64_t phys)
{
    return phys + linear_voffset;
}

static inline uint64_t virt_to_phys(uint64_t virt)
{
    return virt - linear_voffset;
}

static inline uint64_t phys_to_kimg(uint64_t phys)
{
    return phys + kimage_voffset;
}

static inline uint64_t kimg_to_phys(uint64_t addr)
{
    return addr - kimage_voffset;
}

static inline int has_vmalloc_area()
{
    return kimage_voffset != linear_voffset;
}

static inline uint64_t kp_kimg_to_phys(uint64_t addr)
{
    return addr - kimage_voffset;
}

static inline void flush_tlb_kernel_range(uint64_t start, uint64_t end)
{
    start = tlbi_vaddr(start, 0);
    end = tlbi_vaddr(end, 0);
    dsb(ishst);
    for (uint64_t addr = start; addr < end; addr += 1 << (page_shift - 12))
        tlbi_1(vaale1is, addr);
    dsb(ish);
    isb();
}

static inline void flush_tlb_kernel_page(uint64_t addr)
{
    addr = tlbi_vaddr(addr, 0);
    dsb(ishst);
    tlbi_1(vaale1is, addr);
    dsb(ish);
    isb();
}

static inline int is_kimg_range(uint64_t addr)
{
    return addr >= kernel_va && addr < (kernel_va + kernel_size);
}

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);

static inline uint64_t *pgtable_entry_kernel(uint64_t va)
{
    return pgtable_entry(pgd_va, va);
}

uint64_t pgtable_phys(uint64_t pgd, uint64_t va);

static inline uint64_t pgtable_phys_kernel(uint64_t va)
{
    return pgtable_phys(pgd_va, va);
}

#endif /* CONFIG_ARM / CONFIG_X86_64 */

#endif