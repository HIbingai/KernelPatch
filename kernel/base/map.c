/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "setup.h"
#define NUMA_NO_NODE (-1)

/*
 * The kernel's phys_addr_t — and therefore the width every memblock entry
 * point below takes its arguments in.  include/linux/types.h makes it u64 only
 * when CONFIG_PHYS_ADDR_T_64BIT is set, which on ARM needs CONFIG_ARM_LPAE;
 * this port is explicitly non-LPAE (CONFIG_ARM_LPAE unset in the target
 * .config), so the kernel compiles these functions with 32-bit phys_addr_t.
 *
 * Declaring them 64-bit here did not just truncate values: on AAPCS a 64-bit
 * argument occupies an even/odd register pair, so every later argument landed
 * one register further along than the callee looked for.  The kernel read the
 * HIGH half of `size` as `align` (always 0), took the `if (!align) dump_stack()`
 * path in memblock_alloc_range_nid(), then forced align = SMP_CACHE_BYTES and
 * consumed the real min/max/nid from the wrong registers.  M5-D observed
 * exactly that dump on the first boot of the linked full port; the same
 * off-by-one applied to memblock_reserve/memblock_mark_nomap/memblock_free.
 */
#if defined(CONFIG_ARM)
typedef uint32_t phys_addr_t;
#else
typedef uint64_t phys_addr_t;
#endif
typedef int (*memblock_reserve_f)(phys_addr_t base, phys_addr_t size);
typedef phys_addr_t (*memblock_phys_alloc_try_nid_f)(phys_addr_t size, phys_addr_t align, int nid);
typedef phys_addr_t (*memblock_alloc_try_nid_f)(phys_addr_t size, phys_addr_t align, phys_addr_t min_addr,
                                                phys_addr_t max_addr, int nid);
typedef void *(*memblock_virt_alloc_try_nid_f)(phys_addr_t size, phys_addr_t align, phys_addr_t min_addr,
                                               phys_addr_t max_addr, int nid);
typedef int (*memblock_free_f)(phys_addr_t base, phys_addr_t size);
typedef int (*memblock_mark_nomap_f)(phys_addr_t base, phys_addr_t size);
typedef int (*printk_f)(const char *fmt, ...);
#if defined(CONFIG_ARM)
/*
 * AArch32 paging_init() is `void __init paging_init(const struct machine_desc
 * *mdesc)` -- it has an ARGUMENT, unlike AArch64's paging_init(void).  The hook
 * (a raw `B` written over paging_init's first instruction) transfers control
 * BEFORE paging_init's prologue runs, so r0 still holds mdesc there.  We must
 * capture it and forward it, and in particular must NOT let r0 keep whatever
 * the last printk() returned.
 *
 * The M4 scaffold measured this exact failure on this kernel: the worker left
 * r0 = 25 (0x19, printk's return value), so paging_init ran with mdesc = 0x19
 * and faulted at devicemaps_init()'s `mdesc->map_io`, i.e. address 0x19 + 0x4c
 * = 0x65.  That abort re-enters the not-yet-installed vector path and hangs
 * with no output -- exactly the M5-D silent hang.
 */
typedef void (*paging_init_f)(const void *mdesc);
#else
typedef void (*paging_init_f)(void);
#endif

map_data_t map_data __section(.map.data) __aligned(MAP_ALIGN) = {
#ifdef MAP_DEBUG
    .str_fmt_px = "KP: %x-%llx\n",
#endif
};

uint64_t __section(.map.text) __noinline __aligned(MAP_ALIGN) get_myva()
{
#if defined(CONFIG_ARM)
    /*
     * AArch32: `adr` materialises a 32-bit PC-relative address.  Keep the
     * destination 32-bit -- with a uint64_t destination GCC allocates an
     * even/odd register pair and only the low half is written, so the returned
     * VA would carry an undefined high word.
     */
    uint32_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    return this_va & ~((uint64_t)MAP_ALIGN - 1);
#else
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    return this_va & ~((uint64_t)MAP_ALIGN - 1);
#endif
}

map_data_t *__noinline get_data()
{
    uint64_t va = get_myva() - sizeof(map_data_t);
    return (map_data_t *)(va & ~((uint64_t)MAP_ALIGN - 1));
}

static uint64_t get_kva()
{
    map_data_t *data = get_data();
    uint64_t kernel_va = (uint64_t)data - data->map_offset;
    return kernel_va;
}

static inline uint64_t phys_to_lm(map_data_t *data, uint64_t phys)
{
    return phys + data->linear_voffset;
}

static uint64_t map_phys_alloc(map_data_t *data, uint64_t size, uint64_t align)
{
    /*
     * Dispatch on the ARGUMENT COUNT the resolved symbol really has:
     *
     *   MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID (1)
     *       memblock_phys_alloc_try_nid(size, align, nid)              -- 3 args
     *   MAP_SYM_MEMBLOCK_ALLOC_TRY_NID (2)
     *       memblock_alloc_try_nid(size, align, min_addr, max_addr, nid)
     *                                                                  -- 5 args
     *
     * (2) is the 4.x fallback, and it is what the on-device patcher picked for
     * this target: 4.9.193 has no memblock_phys_alloc_try_nid, so kptools
     * resolved memblock_alloc_try_nid instead.  It MUST be called through a
     * five-argument prototype.  Calling it through the three-argument one left
     * max_addr (r3) and nid (the stacked fifth argument) undefined, so
     * memblock_find_in_range_node() either clamped the search window to nothing
     * or missed every region because of a bogus node id; the allocation then
     * returned 0 and _paging_init went on to map and zero VA
     * (0 + kimage_voffset) instead of a fresh KP region -- overwriting live
     * kernel memory and hanging the device with no console output.
     *
     * The values passed for (2) are exactly the kernel's own memblock_alloc():
     * min_addr = MEMBLOCK_ALLOC_ACCESSIBLE (0), max_addr = MEMBLOCK_ALLOC_ANYWHERE
     * (~0) and nid = NUMA_NO_NODE.
     */
    if (data->map_symbol.memblock_phys_alloc_type == MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID) {
        return ((memblock_phys_alloc_try_nid_f)data->map_symbol.memblock_phys_alloc_relo)(size, align, NUMA_NO_NODE);
    }
    if (data->map_symbol.memblock_phys_alloc_type == MAP_SYM_MEMBLOCK_ALLOC_TRY_NID) {
        return ((memblock_alloc_try_nid_f)data->map_symbol.memblock_phys_alloc_relo)(
            size, align, (phys_addr_t)0, (phys_addr_t)~(phys_addr_t)0, NUMA_NO_NODE);
    }

    return 0;
}

#if defined(CONFIG_ARM)
/*
 * AArch32 arch glue.  The CP15 sequences mirror the port's verified layer:
 * include/pgtable.h (local_flush_tlb_all -> DSB / TLBIALL / DSB / ISB) and
 * include/cache.h (flush_icache_all -> DSB / ICIALLU / DSB / ISB).  Those
 * headers cannot simply be included here because they define functions with
 * these very names, and map.c is also compiled for the AArch64 map region.
 *   TLBIALL = mcr p15,0,Rt,c8,c7,0     ICIALLU = mcr p15,0,Rt,c7,c5,0
 * On ARMv7 the only DMB/DSB options are SY/ST/ISH/ISHST/NSH/NSHST/OSH/OSHST --
 * `ishst`/`ish` as used below are valid, and `sy` is the strongest.
 */
static void flush_tlb_all()
{
    asm volatile("dsb sy" : : : "memory");
    asm volatile("mcr p15, 0, %0, c8, c7, 0" : : "r"(0) : "memory"); // TLBIALL
    asm volatile("dsb sy" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static void flush_icache_all(void)
{
    asm volatile("dsb sy" : : : "memory");
    asm volatile("mcr p15, 0, %0, c7, c5, 0" : : "r"(0) : "memory"); // ICIALLU
    asm volatile("dsb sy" : : : "memory");
    asm volatile("isb" : : : "memory");
}
#else
static void flush_tlb_all()
{
    asm volatile("dsb ishst" : : : "memory");
    asm volatile("tlbi vmalle1is\n"
                 "dsb ish\n"
                 "tlbi vmalle1is\n");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static void flush_icache_all(void)
{
    asm volatile("dsb ish" : : : "memory");
    asm volatile("ic ialluis");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}
#endif

// The map region is copied to a different kernel address at boot, so it must be
// self-contained: no `bl` may leave the region. GCC 14 lowers the 0xa0-byte
// struct copy `*data = *get_data()` to a memcpy() call; that bl targets the
// kpimg's own memcpy (fixed kpimg offset) and misrelocates once the map code is
// copied into the kernel, jumping into unrelated kernel text (e.g. tcp_done).
// Copy explicitly with a volatile byte loop so no memcpy call is emitted.
static __noinline void copy_map_data(map_data_t *dst)
{
    const map_data_t *src = get_data();
    volatile unsigned char *d = (volatile unsigned char *)dst;
    const volatile unsigned char *s = (const volatile unsigned char *)src;
    for (unsigned int i = 0; i < sizeof(map_data_t); i++) {
        d[i] = s[i];
    }
}

static __noinline void mem_proc(map_data_t *data)
{
    copy_map_data(data);
    uint64_t kernel_va = get_kva();

    // relocation
    data->kimage_voffset = kernel_va - data->kernel_pa;
    data->paging_init_relo += kernel_va;

#ifdef MAP_DEBUG
    data->printk_relo += kernel_va;
#endif

    if (data->map_symbol.memblock_reserve_relo) data->map_symbol.memblock_reserve_relo += kernel_va;
    if (data->map_symbol.memblock_free_relo) data->map_symbol.memblock_free_relo += kernel_va;
    if (data->map_symbol.memblock_phys_alloc_relo) data->map_symbol.memblock_phys_alloc_relo += kernel_va;
    if (data->map_symbol.memblock_virt_alloc_relo) data->map_symbol.memblock_virt_alloc_relo += kernel_va;
    if (data->map_symbol.memblock_mark_nomap_relo) data->map_symbol.memblock_mark_nomap_relo += kernel_va;

    // pgtable
#if defined(CONFIG_ARM)
    /*
     * AArch32 has no TCR_EL1; the equivalent register is TTBCR (c2,c0,2).
     * This target runs with TTBCR.N == 0 (measured: the real 4.9.193 image
     * contains no `mcr p15,0,Rt,c2,c0,2` at all), i.e. TTBR0 translates the
     * whole 4 GB through ONE 4096-entry L1 table.  The AArch64 "TTBR1 VA size /
     * TG1 granule" geometry therefore collapses to constants:
     *   va1_bits   = 32 -- one flat table covers the entire address space
     *   page_shift = 12 -- 4 KB small pages; short descriptors have no 16K/64K
     *                     granule knob (TG1 does not exist here)
     * A non-zero N splits TTBR0/TTBR1 into regions whose size is not a power of
     * two, which would make the level/granule arithmetic in
     * get_or_create_pte() meaningless -- fail loudly instead.
     */
    uint32_t ttbcr;
    asm volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr));
    if (ttbcr & 0x7u) {
        asm volatile(".inst 0xe7f000f0"); // UDF #0: TTBCR.N != 0 is unsupported
    }
    data->va1_bits = 32;
    data->page_shift = 12;
#else
    uint64_t tcr_el1;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    uint64_t t1sz = tcr_el1 << 42 >> 58; // bits(tcr_el1, 21, 16)
    uint64_t va1_bits = 64 - t1sz;
    data->va1_bits = va1_bits;
    uint64_t tg1 = tcr_el1 << 32 >> 62; // bits(tcr_el1, 31, 30)
    uint64_t page_shift = 12;
    if (tg1 == 1) {
        page_shift = 14;
    } else if (tg1 == 3) {
        page_shift = 16;
    }
    data->page_shift = page_shift;
#endif

    // linear
#if defined(CONFIG_ARM)
    /*
     * AArch32 keeps the kernel image inside the SAME flat mapping as the rest
     * of RAM (single TTBR0 table, TTBCR.N == 0), so the linear offset is by
     * definition the image offset -- no probing needed.  The memblock
     * phys/virt probe below is not only unnecessary, it is unusable: it
     * requires memblock_virt_alloc_try_nid to be present in the preset and
     * traps otherwise.  include/pgtable.h documents the same identity.
     */
    data->linear_voffset = data->kimage_voffset;
#else
    if (data->map_symbol.memblock_virt_alloc_relo) {
        /* route through the same dispatcher so the 5-arg 4.x fallback gets all
         * five arguments here too */
        uint64_t detect_phys = map_phys_alloc(data, 0, 0x10);
        uint64_t detect_virt = (uint64_t)((memblock_virt_alloc_try_nid_f)data->map_symbol.memblock_virt_alloc_relo)(
            0, 0x10, detect_phys, detect_phys, NUMA_NO_NODE);
        data->linear_voffset = detect_virt - detect_phys;
    } else {
        __builtin_trap();
    }
#endif
}

// todo: 52-bits pa
static uint64_t __noinline get_or_create_pte(map_data_t *data, uint64_t va, uint64_t pa, uint64_t attr_indx)
{
#if defined(CONFIG_ARM)
    /*
     * AArch32 short-descriptor walk.  TTBCR.N == 0 on this target (measured),
     * so TTBR0 points at ONE 4096-entry L1 table covering the whole 4 GB and
     * the L1 index is (va >> 20) -- this kernel maps its image with 1 MB
     * sections, not 2 MB blocks (the port's measured live RWX section is
     * 0x41911c0e, attrs 0x11c0e).
     *   L1 base  = (TTBR0 & 0xFFFFC000) + linear_voffset       (see pgtable.h)
     *   section  : [1:0] = 0b10, PA in [31:20], attrs in [19:0], XN = bit4
     *   L2 table : [1:0] = 0b01, PA in [31:10]
     * The callers in _paging_init() hit exactly two cases: the kernel text VA
     * (already a section -> return that leaf) and freshly memblock-allocated
     * RAM (the L1 slot reads 0 -> install a section).  A pre-existing coarse
     * L2 table is deliberately NOT handled: this port maps GP RAM with
     * sections and deriving a small-page attribute word would be guesswork (a
     * page descriptor has a different bit layout -- XN is bit0, AP[1:0] is
     * [5:4]) -- so refuse; the caller then faults loudly at the VA it tried to
     * map instead of silently corrupting an existing kernel mapping.
     */
    uint32_t ttbr0;
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ttbr0));
    uint32_t l1 = (uint32_t)phys_to_lm(data, (uint64_t)(ttbr0 & 0xFFFFC000u));
    uint32_t idx = ((uint32_t)va >> 20) & 0xFFFu;
    uint32_t *entry = (uint32_t *)(uintptr_t)(l1 + idx * 4u);
    uint32_t desc = *entry;
    uint32_t attrs = (uint32_t)attr_indx & 0x000FFFFFu;

    if ((desc & 0x3u) == 0x2u) return (uint64_t)(uintptr_t)entry; // 1 MB section leaf
    if ((desc & 0x3u) == 0x1u) return 0;                          // coarse L2 table: refuse

    /*
     * Invalid: install a 1 MB section for this VA.  attr_indx carries the
     * low-20-bit attribute field of a live kernel section (TEX/C/B/AP/domain,
     * XN clear in bit4) copied by the caller from the kernel text entry -- the
     * same measurement-based approach the port's AArch32 mapper uses.
     */
    *entry = ((uint32_t)pa & 0xFFF00000u) | attrs;
    return (uint64_t)(uintptr_t)entry;
#else
    uint64_t page_shift = data->page_shift;
    uint64_t va_bits = data->va1_bits;
    uint64_t page_level = (va_bits - 4) / (page_shift - 3);
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;

    uint64_t ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    uint64_t baddr = ttbr1_el1 & 0xFFFFFFFFFFFE;
    uint64_t page_size = 1 << page_shift;
    uint64_t page_size_mask = ~(page_size - 1);
    uint64_t attr_prot = 0x40000000000703 | attr_indx;

    uint64_t pxd_pa = baddr & page_size_mask;
    uint64_t pxd_va = phys_to_lm(data, pxd_pa);
    uint64_t pxd_entry_va = 0;

    for (uint64_t lv = 4 - page_level; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        uint64_t alloc_flag = 0;
        uint64_t block_flag = 0;

        pxd_entry_va = pxd_va + pxd_index * 8;

        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);

        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift)) - 1) << page_shift);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_flag = 1;
        } else { // invalid, alloc
            if (lv != 3) {
                pxd_pa = map_phys_alloc(data, page_size, page_size);
                alloc_flag = 1;
            } else {
                pxd_pa = pa;
            }
            pxd_desc = (pxd_pa) | attr_prot;
            *((uint64_t *)pxd_entry_va) = pxd_desc;
        }
        pxd_va = phys_to_lm(data, pxd_pa);
        if (alloc_flag) {
            for (uint64_t i = pxd_va; i < pxd_va + page_size; i += 8) {
                *(uint64_t *)i = 0;
            }
        }
        if (block_flag) {
            break;
        }
    }
    return pxd_entry_va;
#endif
}

// todo: bti
// 6.15+ keeps kernel text read-only and creates the linear map inside
// paging_init(), so while the hook runs there is no usable linear map and
// the memblock probe in mem_proc() yields an incoherent phys_to_virt pair.
// swapper_pg_dir lives in the kernel image, so the top-level table is
// reachable and writable through the image mapping: borrow its unused
// entries to alias arbitrary physical pages through the top table itself.
// The chain re-enters the top table at every intermediate level and ends
// with a page descriptor: for 39-bit VA (3 levels) slots s -> j1 -> j2 map
// top -> next -> leaf, for 48-bit VA (4 levels) one more slot joins the
// chain. This needs no linear map and works on both old and new kernels.

#define SCRATCH_MAX_SLOTS 5

typedef struct
{
    uint64_t pgd_va;
    uint64_t pgd_pa;
    uint64_t window;
    uint64_t slots[SCRATCH_MAX_SLOTS]; // [0] = top entry, last = leaf entry
    int nslots;                        // top entry + intermediate entries + leaf
    uint64_t top_shift;
    uint64_t pxd_bits;
    uint64_t page_shift;
    uint64_t va1_bits;
} scratch_t;

#define SCRATCH_DESC_TABLE (0x3ull)
#define SCRATCH_DESC_PAGE (0x703ull) // V|AF|SH inner|AttrIndx 0|EL1 RW (no contiguous)

static int scratch_prep(map_data_t *data, scratch_t *sc)
{
#if defined(CONFIG_ARM)
    /*
     * AArch32 has no TTBR1, so there is no unused top-level half to borrow.
     * With TTBCR.N == 0 a single 4096-entry L1 table covers the whole 4 GB,
     * every entry already belongs to the one address space, and a short
     * descriptor walk is at most 2 levels -- fewer than the >=3 chain needed
     * here.  Fail, so _paging_init() takes the legacy restore path: write the
     * saved instruction back at paging_init's VA and call it, which is exactly
     * what the port's AArch32 mapper (kernel/arm/map.c) does on this target.
     */
    (void)data;
    (void)sc;
    return -1;
#else
    uint64_t pxd_bits = data->page_shift - 3;
    uint64_t page_level = (data->va1_bits - 4) / pxd_bits;
    // chain length == number of walk levels: 39-bit VA (3 levels) slots
    // s -> j1 -> j2 map top -> next -> leaf; 42/48-bit (4 levels) add one.
    // The last level of a walk only accepts page descriptors, so the chain
    // must not be deeper than the walk itself.
    int nslots = (int)page_level;
    if (page_level < 3 || nslots > SCRATCH_MAX_SLOTS) return -1;
    uint64_t ttbr1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    uint64_t page_size = 1 << data->page_shift;
    uint64_t pgd_pa = ttbr1 & ~(page_size - 1);
    // the top-level table must live inside the kernel image (.bss) for the
    // image mapping below to reach it
    if (pgd_pa < data->kernel_pa || pgd_pa >= data->kernel_pa + 0x8000000) return -1;
    uint64_t pgd_va = pgd_pa + data->kimage_voffset;
    uint64_t top_shift = 12 + pxd_bits * (page_level - 1);
    // when the walk starts at level 1 (va1_bits <= 39 for 4K pages) every
    // entry of the top table is a TTBR1 kernel entry; only 4-level walks
    // (start level 0) have a user-half that TTBR1 never translates
    uint64_t half = data->va1_bits <= 39 ? 0 : (1 << (data->va1_bits - 1 - top_shift));
    uint64_t n = 1 << (data->va1_bits - top_shift);
    int nf = 0;
    for (uint64_t i = half; i < n && nf < nslots; i++) {
        if (((*(uint64_t *)(pgd_va + i * 8)) & 0x3) == 0) {
            sc->slots[nf++] = i;
        }
    }
    if (nf < nslots) return -1;
    sc->nslots = nslots;
    sc->pgd_va = pgd_va;
    sc->pgd_pa = pgd_pa;
    sc->top_shift = top_shift;
    sc->pxd_bits = pxd_bits;
    sc->page_shift = data->page_shift;
    sc->va1_bits = data->va1_bits;
    sc->window = ((sc->slots[0] << top_shift) | ~((1ull << data->va1_bits) - 1)) & 0xFFFFFFFFFFFFFFFFull;
#endif
    return 0;
}

static void scratch_activate(map_data_t *data, scratch_t *sc)
{
#if defined(CONFIG_ARM)
    /*
     * Unreachable on AArch32: scratch_prep() always returns -1 there, so
     * have_scratch is 0 in _paging_init() and this is never called.  The
     * AArch64 body would read TTBR1_EL1, which does not exist here -- keep the
     * documented no-op rather than an unrunnable conversion.
     */
    (void)data;
    (void)sc;
#else
    uint64_t ttbr1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    uint64_t pgd_pa = ttbr1 & ~((1ull << sc->page_shift) - 1);
    sc->pgd_va = pgd_pa + data->kimage_voffset;
    // every intermediate slot re-enters the top table itself
    for (int k = 0; k < sc->nslots - 1; k++) {
        *(uint64_t *)(sc->pgd_va + sc->slots[k] * 8) = pgd_pa | SCRATCH_DESC_TABLE;
    }
    flush_tlb_all();
#endif
}

// returns the VA through which the first page of `pa` can be accessed
static uint64_t scratch_map_page(map_data_t *data, scratch_t *sc, uint64_t pa)
{
    int last = sc->nslots - 1;
    *(uint64_t *)(sc->pgd_va + sc->slots[last] * 8) = (pa & ~((1ull << sc->page_shift) - 1)) | SCRATCH_DESC_PAGE;
    flush_tlb_all();
    // the leaf slot sits k levels below the top entry
    uint64_t va = sc->window;
    for (int k = 1; k < sc->nslots; k++) {
        va += sc->slots[k] << (sc->top_shift - k * sc->pxd_bits);
    }
    return va;
}

static void scratch_unmap_page(map_data_t *data, scratch_t *sc)
{
    int last = sc->nslots - 1;
    *(uint64_t *)(sc->pgd_va + sc->slots[last] * 8) = 0;
    flush_tlb_all();
}

static void scratch_teardown(map_data_t *data, scratch_t *sc)
{
    for (int k = 0; k < sc->nslots; k++) {
        *(uint64_t *)(sc->pgd_va + sc->slots[k] * 8) = 0;
    }
    flush_tlb_all();
}

#define SCAN_CAND_MAX 16

static void scan_add_cand(uint64_t *cvals, uint64_t *ccnts, int *cn, uint64_t v)
{
    for (int i = 0; i < *cn; i++) {
        if (cvals[i] == v) {
            ccnts[i]++;
            return;
        }
    }
    if (*cn < SCAN_CAND_MAX) {
        cvals[*cn] = v;
        ccnts[*cn] = 1;
        (*cn)++;
    }
}

// scan one table page: leaf entries vote (va - oa); tables recurse
static void scan_level(map_data_t *data, scratch_t *sc, uint64_t table_pa, uint64_t base_va, uint64_t shift,
                       int depth, uint64_t *cvals, uint64_t *ccnts, int *cn)
{
    if (depth < 0 || shift < sc->page_shift) return;
    if (table_pa == sc->pgd_pa) return; // never treat the top table as a lower level
    uint64_t view = scratch_map_page(data, sc, table_pa);
    uint64_t n = 1 << (sc->page_shift - 3);
    uint64_t pxd_bits = sc->page_shift - 3;
    uint64_t child_pa[8];
    uint64_t child_va[8];
    int tn = 0;
    for (uint64_t k = 0; k < n; k++) {
        uint64_t d = *(uint64_t *)(view + k * 8);
        uint64_t bits = d & 0x3;
        if (bits == 0) continue;
        uint64_t va = base_va + (k << shift);
        if (bits == 0x1) { // leaf
            uint64_t oa = d & (((1ull << (48 - shift)) - 1) << shift);
            // skip the kernel image's own mapping: its offset differs from
            // the linear offset on kernels where the scan is relevant
            if (va - oa != data->kimage_voffset) scan_add_cand(cvals, ccnts, cn, va - oa);
        } else if (tn < 8) { // table
            child_pa[tn] = d & (((1ull << (48 - sc->page_shift)) - 1) << sc->page_shift);
            child_va[tn] = va;
            tn++;
        }
    }
    scratch_unmap_page(data, sc);
    for (int i = 0; i < tn; i++) {
        scan_level(data, sc, child_pa[i], child_va[i], shift - pxd_bits, depth - 1, cvals, ccnts, cn);
    }
}

// recover linear_voffset from the real page tables; returns 0 if the scan
// is inconclusive (caller keeps the memblock-probed value then). votes
// equal to kimage_voffset are skipped: they belong to the image's own
// mapping, whose offset differs from the linear offset on older kernels
static uint64_t scan_linear_voffset(map_data_t *data, scratch_t *sc)
{
    uint64_t cvals[SCAN_CAND_MAX];
    uint64_t ccnts[SCAN_CAND_MAX];
    int cn = 0;
    uint64_t pxd_bits = sc->page_shift - 3;
    uint64_t top_shift = sc->top_shift;
    uint64_t n_top = 1 << (data->va1_bits - top_shift);
    uint64_t high_mask = ~((1ull << data->va1_bits) - 1);
    uint64_t pgd = sc->pgd_va;
    // 39-bit style walks start at level 1: the whole top table is kernel
    // space and the linear map typically lives in its first entries, so the
    // scan must cover all of it; 4-level walks keep the user-half skipped
    uint64_t half = data->va1_bits <= 39 ? 0 : (1 << (data->va1_bits - 1 - top_shift));
    for (uint64_t i = half; i < n_top; i++) {
        // never descend into our own scratch alias entries
        int mine = 0;
        for (int k = 0; k < sc->nslots; k++) mine |= (i == sc->slots[k]);
        if (mine) continue;
        uint64_t d = *(uint64_t *)(pgd + i * 8);
        uint64_t bits = d & 0x3;
        if (bits == 0) continue;
        uint64_t base_va = ((i << top_shift) | high_mask) & 0xFFFFFFFFFFFFFFFFull;
        if (bits == 0x1) { // top-level leaf (1GB block)
            uint64_t oa = d & (((1ull << (48 - top_shift)) - 1) << top_shift);
            if (base_va - oa != data->kimage_voffset) scan_add_cand(cvals, ccnts, &cn, base_va - oa);
        } else {
            uint64_t t_pa = d & (((1ull << (48 - sc->page_shift)) - 1) << sc->page_shift);
            scan_level(data, sc, t_pa, base_va, top_shift - pxd_bits, 2, cvals, ccnts, &cn);
        }
    }
    uint64_t best = 0, best_cnt = 0;
    for (int i = 0; i < cn; i++) {
        if (ccnts[i] > best_cnt) {
            best_cnt = ccnts[i];
            best = cvals[i];
        }
    }
    return best_cnt >= 2 ? best : 0;
}

// kernels >= 6.15 (early paging rework) have no usable linear map inside the
// paging_init hook: only the kernel image and fixmap are mapped, and the
// linear map is built later by setup_arch. provide KP's own linear window
// instead: identity-map the first GBs of RAM with 1GB block entries in a
// run of consecutive free top-level slots and return the window's VA base
// to be used as linear_voffset
static uint64_t install_kp_linear(map_data_t *data, scratch_t *sc)
{
    uint64_t pxd_bits = data->page_shift - 3;
    uint64_t page_level = (data->va1_bits - 4) / pxd_bits;
    if (page_level < 2) return 0; // no block-capable top level
    // blocks are only legal from level 1 down; for 4K pages the top level is
    // level 1 exactly when va1_bits <= 39 (walk starts below level 0)
    if (data->va1_bits > 39) return 0;
    uint64_t top_shift = 12 + pxd_bits * (page_level - 1);
    uint64_t pgd = sc->pgd_va;
    // with a level-1 start (va1_bits <= 39) every top entry is kernel space;
    // skip the real linear map's low entries by scanning from index 2
    uint64_t half = data->va1_bits <= 39 ? 2 : (1 << (data->va1_bits - 1 - top_shift));
    uint64_t n_top = 1 << (data->va1_bits - top_shift);
    uint64_t high_mask = ~((1ull << data->va1_bits) - 1);

    uint64_t run = 0;
    // the identity window must start at the RAM base, not at PA 0
    uint64_t ram_base = data->kernel_pa & ~((1ull << 30) - 1);
    for (uint64_t i = half; i < n_top; i++) {
        if ((*(uint64_t *)(pgd + i * 8) & 0x3) == 0) {
            // extend the consecutive free run, capped at 4GB of coverage
            while (i + run < n_top && run < 4 && (*(uint64_t *)(pgd + (i + run) * 8) & 0x3) == 0) run++;
            if (run < 2) { // too small to be useful, keep looking
                i += run;
                run = 0;
                continue;
            }
            uint64_t base = ((i << top_shift) | high_mask) & 0xFFFFFFFFFFFFFFFFull;
            // V | 1GB block | AF | SH inner | AttrIndx 0 | EL1 RW
            for (uint64_t k = 0; k < run; k++) {
                *(uint64_t *)(pgd + (i + k) * 8) = (((ram_base >> 30) + k) << 30) | 0x701ull;
            }
            flush_tlb_all();
            // linear_voffset so that pa + lv lands inside the window run
            return base - ram_base;
        }
    }
    return 0;
}

#if defined(CONFIG_ARM)
/* Entered by the B rewritten into paging_init's first instruction, so r0 is
 * still `const struct machine_desc *mdesc` -- see the paging_init_f comment. */
void __noinline _paging_init(void *mdesc)
#else
void __noinline _paging_init(void)
#endif
{
	map_data_t buf;
	map_data_t *data = &buf;
    mem_proc(data);

#ifdef MAP_DEBUG
    printk_f printk = (printk_f)(data->printk_relo);
#define map_debug(idx, val) printk(data->str_fmt_px, idx, val)
    for (int i = 0; i < sizeof(map_data_t); i += 8) {
        map_debug(i, *(uint64_t *)((uint64_t)data + i));
    }
#else
#define map_debug(idx, val)
#endif

    uint64_t page_size = 1 << data->page_shift;
    uint64_t old_start_pa = data->start_offset + data->kernel_pa;
    uint64_t reserve_size = data->start_img_size + data->extra_size;
    uint64_t align_extra_size = (data->extra_size + page_size - 1) & ~(page_size - 1);
    uint64_t all_size = data->start_size + align_extra_size + data->alloc_size;
#if defined(CONFIG_ARM)
    /*
     * AArch32: the new region must be SECTION_SIZE (1 MB) aligned in BOTH its
     * start and its size.
     *
     * memblock_mark_nomap() SPLITS memblock.memory at the region boundaries,
     * and map_lowmem() walks those regions with for_each_mem_range(), which
     * (include/linux/memblock.h) passes type_b = NULL and only excludes
     * MEMBLOCK_HOTPLUG -- so a NOMAP region is still visited and its edges
     * become new region boundaries.  If such a boundary is not 1 MB aligned,
     * create_mapping() -> alloc_init_section() cannot build a section mapping
     * and falls back to the small-page path, which calls early_alloc() for an
     * L2 table and immediately memsets the freshly allocated VA -- a VA that
     * map_lowmem() has not mapped yet.  That write data-aborts inside
     * paging_init(), before bootmem_init(), with no console output.
     *
     * Measured on this target: start_pa = 0x4b8bf000 (only 4 KB aligned, from
     * the unaligned end of the first memory bank at 0x4d000000 minus
     * all_size = 0x741000) created the unaligned boundary 0x4b8bf000 and the
     * abort was DFSR 0x805 (write, section translation fault) at
     * DFAR 0xcb8be000 = __va(0x4b8be000) -- exactly the 4 KB immediately below
     * the region, i.e. the L2 table memblock had just handed to early_alloc().
     * The unpatched kernel never hits this because every memory-region edge is
     * section aligned.  Allocate with SECTION_SIZE alignment and round the size
     * up to a multiple of it.
     */
    const uint64_t map_align = 0x100000u; /* SECTION_SIZE */
    all_size = (all_size + map_align - 1) & ~(map_align - 1);
#else
    const uint64_t map_align = page_size;
#endif

    // reserve old start
    ((memblock_reserve_f)data->map_symbol.memblock_reserve_relo)(old_start_pa, reserve_size);
#if defined(CONFIG_ARM)
    /*
     * AArch32: .setup.map lives in the kernel image's own section-alignment
     * padding just below __init_begin, not inside a kernel-text hole (see
     * tools/patch.c).  Unlike the arm64 anchor, nothing is borrowed from live
     * kernel text, so there is nothing to restore and restore_map() is a no-op
     * on this port.  This call keeps any allocator inside the real
     * paging_init() below off the code currently executing in that window.
     *
     * REDUNDANT BY DESIGN, NOT LOAD-BEARING -- do not "simplify" it away
     * assuming it was load-bearing.  arm_memblock_init() already reserved the
     * whole image with
     * memblock_reserve(__pa(KERNEL_START), KERNEL_END - KERNEL_START) before
     * paging_init(), so this is defensive only: it also covers a build where
     * KERNEL_START/KERNEL_END shrink that reservation, and it survives any
     * future reordering of arm_memblock_init().
     *
     * memblock_reserve() fills memblock.reserved only; it does NOT split
     * memblock.memory, so it cannot create the unaligned memory-region
     * boundary that made map_lowmem()/create_mapping() data-abort with DFSR
     * 0x805 (that failure needs memblock_mark_nomap(), which the next
     * statement still calls with SECTION_SIZE-aligned start and size).
     */
    ((memblock_reserve_f)data->map_symbol.memblock_reserve_relo)(data->kernel_pa + (uint32_t)data->map_offset,
                                                                 1u << data->page_shift);
#endif
    // alloc
    uint64_t start_pa = map_phys_alloc(data, all_size, map_align);

#if defined(CONFIG_ARM)
    /*
     * --- KP_MAP_STAGE: AArch32 boot bisect knob -------------------------
     * memblock_virt_alloc_type is never read on AArch32 (linear_voffset is the
     * image offset by construction, see the AArch32 branch below), so it is
     * free to carry a stage selector that map_prepare() copies into map_data.
     * The setup preset ships 1, which means "run everything".  A test image can
     * patch preset+0x98 (= setup_map_symbol_offset + 0x30) to 3/4/5/6 and stop
     * _paging_init() at successive points, so one blob bisects the boot across
     * a few images instead of requiring a rebuild per step:
     *
     *   6 = DETECTOR: bail out only if the memblock allocation returned 0, so a
     *       clean boot proves start_pa == 0 was the fault (a successful
     *       allocation keeps going into exactly the code that hangs)
     *   3 = stop after the real paging_init() has run
     *   4 = stop after the new region's page tables are built
     *   5 = stop after the kpimg has been copied into the new region
     *   1 (or anything else) = production: continue into start()
     */
    const uint32_t kp_stage = (uint32_t)data->map_symbol.memblock_virt_alloc_type;
    if (kp_stage == 6 && start_pa == 0) return;
#else
    /* Non-AArch32 builds keep the arm64 path behaviour: stage 1 only. */
    const uint32_t kp_stage = 1;
#endif

    // mark all size nomap
    if (data->map_symbol.memblock_mark_nomap_relo)
        ((memblock_mark_nomap_f)(data->map_symbol.memblock_mark_nomap_relo))(start_pa, all_size);

    // paging_init
    uint64_t paging_init_va = data->paging_init_relo;
    scratch_t sc;
    // The scratch/scan/identity-window paths are needed on 6.x kernels only:
    // 6.15+ builds the linear map inside paging_init() (so there is no usable
    // linear map while the hook runs) and maps kernel text read-only.  Every
    // kernel <= 5.x (4.x, 5.4, 5.10, 5.15) keeps the legacy direct paths that
    // 0.13.5 verified on device; 5.4 follows the non-GKI (legacy) rule too,
    // and 4.9/4.19 additionally hang on the scratch path regardless of the
    // restore timing (bisected on 4.9.337).  Gate on the kernel version, NOT
    // on va1_bits: 4.19/5.4 both run 39-bit VAs.  If the version is unknown
    // (0), new_era stays 0 and the legacy path is taken, so an image patched
    // by an older kptools still boots.  The stored version is the raw
    // setup_preset kernel_version bytes, which on a little-endian machine
    // read back as [_][patch][minor][major]: major = kv >> 24.
    uint32_t kv = data->kernel_version;
    uint32_t kmajor = (kv >> 24) & 0xFF;
    int new_era = kmajor > 5;
    int have_scratch = new_era && scratch_prep(data, &sc) == 0;
    if (have_scratch) {
        scratch_activate(data, &sc);
        // kernel >= 6.15 maps kernel text read-only, so restore the hooked
        // instruction through a temporary alias instead of touching its PTE
        uint64_t page_size = 1 << data->page_shift;
        uint64_t insn_page = (paging_init_va - data->kimage_voffset) & ~(page_size - 1);
        uint64_t insn_view = scratch_map_page(data, &sc, insn_page);
        *(uint32_t *)(insn_view + (paging_init_va & (page_size - 1))) = data->paging_init_backup;
        scratch_unmap_page(data, &sc);
        scratch_teardown(data, &sc);
    } else {
        *(uint32_t *)(paging_init_va) = data->paging_init_backup;
    }
    flush_icache_all();
#if defined(CONFIG_ARM)
    /* A32 paging_init() takes mdesc; prove we captured the real one (it must be
     * a kernel .init.data pointer, not printk's return value). */
#endif
#if defined(CONFIG_ARM)
    ((paging_init_f)(paging_init_va))(mdesc);
    if (kp_stage == 3) return;
#else
    ((paging_init_f)(paging_init_va))();
#endif
    // can't write data below

    if (have_scratch) {
        // re-prep on the post-paging_init tables (TTBR1 may have changed)
        have_scratch = scratch_prep(data, &sc) == 0;
    }
    if (have_scratch) {
        // the linear map only exists from here on (paging_init created it);
        // re-derive linear_voffset from the real page tables if possible
        scratch_activate(data, &sc);
        uint64_t lv = scan_linear_voffset(data, &sc);
        scratch_teardown(data, &sc);
        if (!lv) {
            // no kernel linear map reachable from here: provide our own
            lv = install_kp_linear(data, &sc);
        }
        if (lv) data->linear_voffset = lv;
    }
    // can't write data below

    // AttrIndx[2:0] encoding
    uint64_t ktext_pte = get_or_create_pte(data, data->paging_init_relo, 0, 0);
#if defined(CONFIG_ARM)
    /*
     * AArch32: the entry is a 32-bit short descriptor, NOT an 8-byte AArch64
     * descriptor -- reading it as uint64_t would fold in the neighbouring L1
     * entry.  There is no AttrIndx field: bits[19:0] are the whole attribute
     * word (TEX/C/B/AP/domain/XN), which is exactly what get_or_create_pte()
     * then copies onto each new section.  Measured kernel text section
     * 0x41911c0e -> attrs 0x11c0e.
     */
    uint64_t attrs = *(uint32_t *)ktext_pte;
    uint64_t attr_indx = attrs & 0xFFFFFu;

    /*
     * clear wxn.  ARMv7 SCTLR.WXN is bit 19 -- the same bit the AArch64 code
     * clears -- but there is a single SCTLR (c1,c0,0) instead of per-EL
     * SCTLR_EL1.  ISB is architecturally required after a SCTLR update.
     */
    uint32_t sctlr;
    asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    sctlr &= ~(1u << 19);
    asm volatile("mcr p15, 0, %0, c1, c0, 0" : : "r"(sctlr) : "memory");
    asm volatile("isb" : : : "memory");
#else
    uint64_t attrs = *(uint64_t *)ktext_pte;
    uint64_t attr_indx = attrs & 0b11100;

    // clear wxn
    // todo: restore wxn later
    uint64_t sctlr_el1 = 0;
    asm volatile("mrs %[reg], sctlr_el1" : [reg] "+r"(sctlr_el1));
    sctlr_el1 &= 0xFFFFFFFFFFF7FFFF;
    asm volatile("msr sctlr_el1, %[reg]" : : [reg] "r"(sctlr_el1));
#endif

    // move start memory
    uint64_t old_start_va = phys_to_lm(data, old_start_pa);

    // uint64_t vm_gurad_enough = page_size << 3;
    uint64_t start_va = start_pa + data->kimage_voffset;

    for (uint64_t off = 0; off < all_size; off += page_size) {
        uint64_t entry = get_or_create_pte(data, start_va + off, start_pa + off, attr_indx);
#if defined(CONFIG_ARM)
        /*
         * 32-bit section descriptor: clear XN (bit4) and clear AP[2] (bit15).
         *
         * AArch32 has NO PXN: with short descriptors XN (bit4) blocks execution
         * in BOTH privileged and user mode (not LPAE, so there is no separate
         * privileged-XN bit).  The AArch64 line below is therefore NOT
         * "set XN": its mask clears PXN (bit53), i.e. it *enables* EL1
         * execution of the new region -- which is mandatory, because the very
         * next thing _paging_init() does is call start() at start_va, and
         * prot_myself() only re-protects the region after start() is running.
         * An earlier revision of this port set bit4 here and reproduced the
         * upstream text upside down: every boot died with a Prefetch Abort at
         * PC == start_va == 0xcb800000 (no mapped-X code), before start() ever
         * ran.  Clear XN to allow EL1 fetch, and keep AP[2]=0 so the region is
         * writable while the move below and prot_myself run.
         */
        *(uint32_t *)entry = (*(uint32_t *)entry & ~0x10u) & ~0x8000u;
#else
        *(uint64_t *)entry = (*(uint64_t *)entry | 0x8000000000000) & 0xFFDFFFFFFFFFFF7F;
#endif
    }
    flush_tlb_all();
#if defined(CONFIG_ARM)
    if (kp_stage == 4) return;
#endif

#if defined(CONFIG_ARM)
    /*
     * AArch32: byte-wise move.  The AArch64 loops below move 8 bytes per step,
     * which would read and write past any size that is not a multiple of 8
     * (start_img_size need not be), and on ILP32 it would pair unrelated
     * words.  A volatile byte loop is also what copy_map_data() uses to keep
     * GCC from emitting a memcpy() call into the self-contained map region.
     * (uintptr_t) keeps the 64-bit VA from triggering -Wint-to-pointer-cast.
     */
    {
        volatile unsigned char *d = (volatile unsigned char *)(uintptr_t)start_va;
        const volatile unsigned char *s = (const volatile unsigned char *)(uintptr_t)old_start_va;
        for (uint64_t i = 0; i < all_size; i++) d[i] = 0;
        for (uint64_t i = 0; i < data->start_img_size; i++) d[i] = s[i];
        for (uint64_t i = 0; i < data->extra_size; i++) {
            d[data->start_size + i] = s[data->start_img_size + i];
        }
    }
#else
    for (uint64_t i = start_va; i < start_va + all_size; i += 8) {
        *(uint64_t *)i = 0;
    }
    for (uint64_t i = 0; i < data->start_img_size; i += 8) {
        *(uint64_t *)(start_va + i) = *(uint64_t *)(old_start_va + i);
    }
    for (uint64_t i = 0; i < data->extra_size; i += 8) {
        *(uint64_t *)(start_va + data->start_size + i) = *(uint64_t *)(old_start_va + data->start_img_size + i);
    }
#endif

    flush_icache_all();

    // free old start
    ((memblock_free_f)data->map_symbol.memblock_free_relo)(old_start_pa, reserve_size);

#if defined(CONFIG_ARM)
    if (kp_stage == 5) return;
#endif

    // start
    ((start_f)start_va)(data->kimage_voffset, data->linear_voffset, (uint64_t)kp_stage);
}
