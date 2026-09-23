/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <common.h>
#include <pgtable.h>
#include <ktypes.h>
#include <kallsyms.h>
#include <compiler.h>
#include <cache.h>
#include <symbol.h>
#include <predata.h>
#include <barrier.h>
#include <stdarg.h>

#include "../banner"
#include "start.h"
#include "hook.h"
#include "tlsf.h"
#include "hmem.h"
#include "setup.h"
#include "symbol_lookup_scan.h"

#define bits(n, high, low) (((n) << (63u - (high))) >> (63u - (high) + (low)))
#define align_floor(x, align) ((uint64_t)(x) & ~((uint64_t)(align) - 1))
#define align_ceil(x, align) (((uint64_t)(x) + (uint64_t)(align) - 1) & ~((uint64_t)(align) - 1))
extern int cfi_bypass;
start_preset_t start_preset __attribute__((section(".start.data")));

setup_header_t *setup_header = 0;
KP_EXPORT_SYMBOL(setup_header);

int (*kallsyms_on_each_symbol)(int (*fn)(void *data, const char *name, struct module *module, unsigned long addr),
                               void *data) = 0;
KP_EXPORT_SYMBOL(kallsyms_on_each_symbol);

typedef int (*kallsyms_on_each_symbol_nomod_t)(int (*fn)(void *, const char *, unsigned long), void *data);
typedef int (*kallsyms_on_each_match_symbol_t)(int (*fn)(void *, unsigned long), const char *name, void *data);
static kallsyms_on_each_match_symbol_t kernel_kallsyms_on_each_match_symbol = 0;

unsigned long (*kallsyms_lookup_name)(const char *name) = 0;
KP_EXPORT_SYMBOL(kallsyms_lookup_name);

void (*printk)(const char *fmt, ...) = 0;
KP_EXPORT_SYMBOL(printk);

int (*vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);

struct suffix_lookup
{
    const char *base;
    unsigned long addr;
};

static struct vm_struct
{
    struct vm_struct *next;
    void *addr;
    unsigned long size;
    unsigned long flags;
    struct page **pages;
#ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC
    unsigned int page_order;
#endif
    unsigned int nr_pages;
    phys_addr_t phys_addr;
    const void *caller;
} kp_vm = { 0 };

uint32_t kver = 0;
KP_EXPORT_SYMBOL(kver);

uint32_t kpver = 0;
KP_EXPORT_SYMBOL(kpver);

endian_t endian = little;
KP_EXPORT_SYMBOL(endian);

struct kallsyms_match_symbol_context
{
    int (*fn)(void *, unsigned long);
    const char *name;
    void *data;
};

#if 0
static unsigned long resolve_kallsyms_lookup_name_by_backward_symbol_scan(unsigned long anchor_offset)
{
    char buf[256];
    unsigned long addr;
    unsigned long offset;
    unsigned long size;
    unsigned long anchor_addr;
    kernel_sprintf_t kernel_sprintf;

    if (!anchor_offset || !start_preset.sprintf_offset) return 0;

    anchor_addr = kernel_va + anchor_offset;
    if (anchor_addr < kernel_va + 4) return 0;

    kernel_sprintf = (kernel_sprintf_t)(kernel_va + start_preset.sprintf_offset);
    addr = anchor_addr - 4;

    for (int i = 0; i < 4096 && addr > kernel_va; i++) {
        kernel_sprintf(buf, "%pSb", (void *)addr);
        if (!kp_symbol_scan_parse_info(buf, &offset, &size) || !offset || offset > addr - kernel_va) break;
        if (!kp_symbol_scan_strcmp(buf, "kallsyms_lookup_name")) {
            return addr - offset - kernel_va;
        }
        addr -= offset + 4;
    }
    return 0;
}
#endif

static unsigned long resolve_kallsyms_lookup_name_by_symbol_lookup_anchor()
{
    return kp_resolve_symbol_by_lookup_anchor(kernel_va, kernel_size, start_preset.sprintf_offset,
                                              start_preset.symbol_lookup_anchor_offset, "kallsyms_lookup_name");
}

static void log_kallsyms_lookup_name_unresolved()
{
    if (printk) {
        printk("KP failed to resolve kallsyms_lookup_name via symbol scan or preset\n");
    }
}

static int kallsyms_on_each_match_symbol_cb(void *data, const char *name, struct module *unused_mod,
                                            unsigned long addr)
{
    struct kallsyms_match_symbol_context *ctx = data;

    (void)unused_mod;
    if (kp_symbol_scan_strcmp(name, ctx->name)) return 0;
    return ctx->fn(ctx->data, addr);
}

static int kallsyms_on_each_match_symbol_cb_nomod(void *data, const char *name, unsigned long addr)
{
    struct kallsyms_match_symbol_context *ctx = data;

    if (kp_symbol_scan_strcmp(name, ctx->name)) return 0;
    return ctx->fn(ctx->data, addr);
}

int kallsyms_on_each_match_symbol(int (*fn)(void *, unsigned long), const char *name, void *data)
{
    struct kallsyms_match_symbol_context ctx = { .fn = fn, .name = name, .data = data };

    if (unlikely(!fn || !name)) return 0;
    if (likely(kernel_kallsyms_on_each_match_symbol)) {
        return kernel_kallsyms_on_each_match_symbol(fn, name, data);
    }
    if (unlikely(!kallsyms_on_each_symbol)) return 0;
    if (kver <= VERSION(6, 1, 0)) {
        return kallsyms_on_each_symbol(kallsyms_on_each_match_symbol_cb, &ctx);
    }
    kallsyms_on_each_symbol_nomod_t kallsyms_on_each_symbol_nomod =
        (kallsyms_on_each_symbol_nomod_t)kallsyms_on_each_symbol;
    return kallsyms_on_each_symbol_nomod(kallsyms_on_each_match_symbol_cb_nomod, &ctx);
}
KP_EXPORT_SYMBOL(kallsyms_on_each_match_symbol);

static bool suffix_contains_cfi(const char *suffix)
{
    size_t i;

    for (i = 0; suffix[i]; i++) {
        if (suffix[i] == 'c' && suffix[i + 1] == 'f' && suffix[i + 2] == 'i' &&
            (i == 0 || suffix[i - 1] == '.' || suffix[i - 1] == '$') &&
            (!suffix[i + 3] || suffix[i + 3] == '.' || suffix[i + 3] == '$'))
            return true;
    }
    return false;
}

static bool symbol_has_compiler_suffix(const char *name, const char *base)
{
    size_t i;

    for (i = 0; base[i]; i++) {
        if (name[i] != base[i]) return false;
    }
    if (!(name[i] == '.' || name[i] == '$') || !name[i + 1]) return false;
    if (suffix_contains_cfi(name + i + 1)) return false; /* skip .cfi_jt stubs */
    return true;
}

static int lookup_suffix_cb(void *data, const char *name, struct module *module, unsigned long addr)
{
    struct suffix_lookup *lookup = data;

    (void)module;
    if (!lookup || lookup->addr || !addr) return 0;
    if (!symbol_has_compiler_suffix(name, lookup->base)) return 0;
    lookup->addr = addr;
    return 1;
}

static int lookup_suffix_cb_nomod(void *data, const char *name, unsigned long addr)
{
    struct suffix_lookup *lookup = data;

    if (!lookup || lookup->addr || !addr) return 0;
    if (!symbol_has_compiler_suffix(name, lookup->base)) return 0;
    lookup->addr = addr;
    return 1;
}

unsigned long kallsyms_lookup_name_by_suffix(const char *name){


    unsigned long addr = kallsyms_lookup_name(name);
    if (addr) return addr;
    if (!kallsyms_on_each_symbol) return 0;
    if (!cfi_bypass) return 0;
    struct suffix_lookup lookup;

    lookup.base = name;
    lookup.addr = 0;

    if (kver <= VERSION(6, 1, 0)) {
        kallsyms_on_each_symbol(lookup_suffix_cb, &lookup);
    } else {
        typedef int (*kallsyms_on_each_symbol_nomod_t)(int (*fn)(void *, const char *, unsigned long), void *data);
        kallsyms_on_each_symbol_nomod_t on_each_symbol =
            (kallsyms_on_each_symbol_nomod_t)kallsyms_on_each_symbol;
        on_each_symbol(lookup_suffix_cb_nomod, &lookup);
    }

    return lookup.addr;

}
KP_EXPORT_SYMBOL(kallsyms_lookup_name_by_suffix);

uint64_t _kp_extra_start = 0;
uint64_t _kp_extra_end = 0;
uint64_t _kp_hook_start = 0;
uint64_t _kp_hook_end = 0;
uint64_t _kp_rox_start = 0;
uint64_t _kp_rox_end = 0;
uint64_t _kp_rw_start = 0;
uint64_t _kp_rw_end = 0;
uint64_t _kp_region_start = 0;
uint64_t _kp_region_end = 0;

#if defined(CONFIG_ARM)
/* include/symbol.h declares both of these as `unsigned long`.  On ILP32 that is
 * 32-bit and a *different type* from uint64_t (`unsigned long long`), so the
 * definitions must match the declaration exactly.  On LP64 `unsigned long` is
 * 64-bit, so the arm64/x86_64 definitions below are unchanged. */
unsigned long link_base_addr = (unsigned long)_link_base;
unsigned long runtime_base_addr = 0;
#else
uint64_t link_base_addr = (uint64_t)_link_base;
uint64_t runtime_base_addr = 0;
#endif

uint64_t kimage_voffset = 0;
uint64_t linear_voffset = 0;
uint64_t kernel_va = 0;
uint64_t kernel_pa = 0;
int64_t kernel_size = 0;
int64_t page_shift = 0;
int64_t page_size = 0;
int64_t va_bits = 0;
int64_t page_level;
uint64_t pgd_pa;
uint64_t pgd_va;
// int64_t pa_bits = 0;

uint64_t kernel_stext_va = 0;

tlsf_t kp_rw_mem = 0;
tlsf_t kp_rox_mem = 0;

#define BOOT_LOG_SIZE 0x2000
static char boot_log[BOOT_LOG_SIZE] = { 0 };
static int boot_log_offset = 0;
static bool boot_log_full = false;

static inline bool hw_dirty()
{
#if defined(CONFIG_ARM)
    /* ARMv7 short descriptors have no hardware dirty-bit management (that is an
     * AArch64 TCR_EL1.HD feature), so it can never be active here. */
    return false;
#else
    uint64_t tcr_el1;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    return tcr_el1 & 0x10000000000;
#endif
}

const char *get_boot_log()
{
    return boot_log;
}

void log_boot(const char *fmt, ...)
{
    va_list va;
    int avail = (int)sizeof(boot_log) - boot_log_offset;

    if (avail > 1) {
        va_start(va, fmt);
        int ret = vsnprintf(boot_log + boot_log_offset, avail, fmt, va);
        va_end(va);
        if (ret < 0) return;
        printk("KP %s", boot_log + boot_log_offset);
        // vsnprintf returns the length it would have written, so clamp to what actually fit
        boot_log_offset += ret < avail ? ret : avail - 1;
        return;
    }

    // buffer exhausted, keep feeding the kernel log but stop appending
    if (!boot_log_full) {
        boot_log_full = true;
        printk("KP boot log buffer full, later messages only go to the kernel log\n");
    }
    char line[192];
    va_start(va, fmt);
    vsnprintf(line, sizeof(line), fmt, va);
    va_end(va);
    printk("KP %s", line);
}

/*
 * Page-table entry width differs per architecture: AArch32 short descriptors
 * are one 32-bit word (uintptr_t, see include/pgtable.h), while arm64/x86_64
 * entries are 64-bit.  prot_myself()/restore_map() dereference and write these
 * entries back, so the pointee must be the real entry width, not a fixed 64.
 */
#if defined(CONFIG_ARM)
typedef uintptr_t kp_pte_t;
#else
typedef uint64_t kp_pte_t;
#endif

#if defined(CONFIG_ARM)
/*
 * AArch32, non-LPAE: a single 32-bit translation regime and TTBCR.N == 0, i.e.
 * one 4096-entry L1 table of 1 MB/coarse descriptors covering the whole 4 GB,
 * so the entire walk for a VA is its L1 slot (include/pgtable.h: kp_l1_slot()).
 * `pgd` is the L1 base VA; pgd == 0 means "use the live TTBR0 table", which is
 * also what pgtable_entry_kernel() returns.
 */
uintptr_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    if (!pgd) return kp_l1_slot(va);
    return &((uintptr_t *)(uintptr_t)pgd)[kp_l1_index(va)];
}
#else
uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys(pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;

    // ================
    // Branch to some function (even empty), It can work,
    // I don't know why, if anyone knows, please let me know. thank you very much.
    // ================
    __flush_dcache_area((void *)pxd_va, page_size);

    for (int64_t lv = 4 - page_level; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);
        if ((pxd_desc & 0b11) == 0b11) { // table
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift)) - 1) << page_shift);
        } else if ((pxd_desc & 0b11) == 0b01) { // block
            // 4k page: lv1, lv2. 16k and 64k page: only lv2.
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else { // invalid
            return 0;
        }
        //
        pxd_va = phys_to_virt(pxd_pa);
        if (block_lv) {
            break;
        }
    }
#if 0
    uint64_t left_bit = page_shift + (block_lv ? (3 - block_lv) * pxd_bits : 0);
    uint64_t tpa = pxd_pa + (va & ((1u << left_bit) - 1));
    uint64_t tlva = phys_to_virt(tpa);
    uint64_t tkimg = phys_to_kimg(tpa);
    if (tlva != va && tkimg != va) {
        return 0;
    }
#endif
    return (uint64_t *)pxd_entry_va;
}
#endif /* CONFIG_ARM */
KP_EXPORT_SYMBOL(pgtable_entry);

#if defined(CONFIG_ARM)
/*
 * PA behind a kernel VA, using the same single-table short-descriptor model as
 * include/pgtable.h:kp_va_to_phys(), but starting from the caller's L1 base.
 * L1 types: 0b10 = 1 MB section (leaf), 0b01 = coarse page table whose 256
 * entries are 4 KB small pages; anything else is a fault.
 */
uint64_t pgtable_phys(uint64_t pgd, uint64_t va)
{
    uintptr_t l1 = *pgtable_entry(pgd, va);
    if ((l1 & PTE_TYPE_MASK) == PTE_TYPE_SECT)
        return (uint64_t)(l1 & PTE_SECT_BASE_MASK) | (va & 0xfffffu);
    if ((l1 & PTE_TYPE_MASK) == PTE_TYPE_TABLE) {
        uintptr_t *l2 = (uintptr_t *)(uintptr_t)phys_to_virt(l1 & 0xfffffc00u);
        uintptr_t pte = l2[(va >> 12) & 0xffu];
        if ((pte & PTE_TYPE_MASK) != PTE_TYPE_PAGE) return 0;
        return (uint64_t)(pte & 0xfffff000u) | (va & 0xfffu);
    }
    return 0;
}
#else
uint64_t pgtable_phys(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_pa = 0;
    uint64_t pxd_va = pgd;
    __flush_dcache_area((void *)pxd_va, page_size);
    for (int64_t lv = 4 - page_level; lv < 4; ++lv) {
        uint64_t pxd_shift = pxd_bits * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        uint64_t pxd_desc = ((uint64_t *)pxd_va)[pxd_index];
        uint8_t valid_table = pxd_desc & 0b11;
        if (valid_table == 0b11) {
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift)) - 1) << page_shift);
        } else if (valid_table == 0b01) {
            uint64_t bits = (3 - lv) * pxd_bits;
            uint64_t block_bits = bits + page_shift;
            pxd_pa = (pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits)) +
                     (va & (((1ul << bits) - 1) << page_shift));
            break;
        } else {
            return 0;
        }
        pxd_va = phys_to_virt(pxd_pa);
    }
    return pxd_pa ? pxd_pa + (va & (page_size - 1)) : 0;
}
#endif /* CONFIG_ARM */
KP_EXPORT_SYMBOL(pgtable_phys);

static void prot_myself(uint64_t boot_stage)
{
    (void)boot_stage;
    kp_pte_t *kpte = pgtable_entry_kernel(kernel_stext_va);
    log_boot("Kernel stext prot: %llx\n", (uint64_t)*kpte);

    _kp_region_start = (uint64_t)_kp_text_start;
    _kp_region_end = (uint64_t)_kp_end + align_ceil(start_preset.extra_size, page_size) + HOOK_ALLOC_SIZE +
                     MEMORY_ROX_SIZE + MEMORY_RW_SIZE;
    log_boot("Region: %llx, %llx\n", _kp_region_start, _kp_region_end);

    kp_pte_t *kppte = pgtable_entry_kernel(_kp_region_start);
    log_boot("KernelPatch start prot: %llx\n", (uint64_t)*kppte);

    // text, rodata
    uint64_t text_start = (uint64_t)_kp_text_start;
    uint64_t text_end = (uint64_t)_kp_text_end;
    uint64_t align_text_end = align_ceil(text_end, page_size);
    log_boot("Text: %llx, %llx\n", text_start, text_end);

    for (uint64_t i = text_start; i < align_text_end; i += page_size) {
        kp_pte_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_SHARED) & ~PTE_PXN & ~PTE_GP;
        if (has_vmalloc_area()) {
            *pte = (*pte | PTE_RDONLY) & ~PTE_DBM;
        }
    }
    flush_tlb_kernel_range(text_start, align_text_end);

    // data, bss
    uint64_t data_start = (uint64_t)_kp_data_start;
    uint64_t data_end = (uint64_t)_kp_data_end;
    uint64_t align_data_end = align_ceil(data_end, page_size);
    log_boot("Data: %llx, %llx\n", data_start, data_end);

    for (uint64_t i = data_start; i < align_data_end; i += page_size) {
        kp_pte_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_RDONLY;
        if (has_vmalloc_area()) {
            *pte |= PTE_PXN;
        }
    }
    flush_tlb_kernel_range(data_start, align_data_end);

    // extra data
    _kp_extra_start = (uint64_t)_kp_end;
    _kp_extra_end = _kp_extra_start + start_preset.extra_size;
    uint64_t align_extra_end = align_ceil(_kp_extra_end, page_size);
    log_boot("Extra: %llx, %llx\n", _kp_extra_start, _kp_extra_end);

    for (uint64_t i = _kp_extra_start; i < align_extra_end; i += page_size) {
        kp_pte_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_RDONLY;
        if (has_vmalloc_area()) {
            *pte |= PTE_PXN;
        }
    }
    flush_tlb_kernel_range(_kp_extra_start, align_extra_end);

    // rwx for hook
    _kp_hook_start = (uint64_t)align_extra_end;
    _kp_hook_end = _kp_hook_start + HOOK_ALLOC_SIZE;
    log_boot("Hook: %llx, %llx\n", _kp_hook_start, _kp_hook_end);

    for (uint64_t i = _kp_hook_start; i < _kp_hook_end; i += page_size) {
        kp_pte_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_PXN & ~PTE_RDONLY & ~PTE_GP;
    }
    flush_tlb_kernel_range(_kp_hook_start, _kp_hook_end);
    hook_mem_add(_kp_hook_start, HOOK_ALLOC_SIZE);

    // rw memory
    _kp_rw_start = _kp_hook_end;
    _kp_rw_end = _kp_rw_start + MEMORY_RW_SIZE;
    log_boot("RW: %llx, %llx\n", _kp_rw_start, _kp_rw_end);

    for (uint64_t i = _kp_rw_start; i < _kp_rw_end; i += page_size) {
        kp_pte_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_DBM | PTE_SHARED) & ~PTE_RDONLY;
        if (has_vmalloc_area()) {
            *pte |= PTE_PXN;
        }
    }
    flush_tlb_kernel_range(_kp_rw_start, _kp_rw_end);
    kp_rw_mem = tlsf_create_with_pool((void *)_kp_rw_start, MEMORY_RW_SIZE);

    // rox memory
    kp_rox_mem = tlsf_malloc(kp_rw_mem, tlsf_size());
    tlsf_create(kp_rox_mem);

    _kp_rox_start = _kp_rw_end;
    _kp_rox_end = _kp_rox_start + MEMORY_ROX_SIZE;
    log_boot("ROX: %llx, %llx\n", _kp_rox_start, _kp_rox_end);

    tlsf_add_pool(kp_rox_mem, (void *)_kp_rox_start, MEMORY_ROX_SIZE);

    for (uint64_t i = _kp_rox_start; i < _kp_rox_end; i += page_size) {
        kp_pte_t *pte = pgtable_entry_kernel(i);
        *pte = (*pte | PTE_SHARED) & ~PTE_PXN & ~PTE_GP;
        // todo: tlsf malloc block_split will write to alloced memory
        // if (has_vmalloc_area()) {
        // *pte |= PTE_RDONLY;
        // *pte &= ~PTE_DBM;
        // }
    }
    flush_tlb_kernel_range(_kp_rox_start, _kp_rox_end);

    // add to vmalloc area
#if defined(CONFIG_ARM)
    /*
     * AArch32: SKIP ENTIRELY.  This call is what hung the first on-device boot,
     * and it is meaningless on this target anyway: AArch32 has ONE flat linear
     * map (see include/pgtable.h), so has_vmalloc_area() is false and the KP
     * region does not live in a vmalloc window at all.
     *
     * Two independent reasons it cannot work at this point on 4.9 ARM32:
     *  1. prot_myself() runs INSIDE paging_init(), but the vmalloc layer that
     *     vm_area_add_early() manipulates is brought up by vmalloc_init(),
     *     which mm_init() calls only AFTER setup_arch()/paging_init() return.
     *     The 4.9 body allocates from vmap_area_cachep, still NULL here, and
     *     vmap_area_root is empty -> BUG_ON / garbage dereference, with no
     *     console and no watchdog yet -> silent permanent hang (measured:
     *     stage 11 = pass, stage 12 = hang).
     *  2. struct vm_struct is a 32-bit layout on this target (4-byte pointers)
     *     while kp_vm is the 64-bit arm64 layout, so even a live vmap layer
     *     would read addr/size/flags/flags from wrong offsets.
     * The 5.15.167 QEMU oracle never caught this: it is arm64, where both the
     * lifecycle prerequisite and the struct layout are different.
     */
    if (boot_stage == 14) return;
#else
    void (*vm_area_add_early)(struct vm_struct *vm) =
        (typeof(vm_area_add_early))kallsyms_lookup_name("vm_area_add_early");

    if (vm_area_add_early) {
        kp_vm.addr = (void *)_kp_region_start;
        kp_vm.phys_addr = kp_kimg_to_phys(_kp_region_start);
        kp_vm.size = _kp_region_end - _kp_region_start;
        kp_vm.flags = 0x00000044;
        kp_vm.caller = (void *)_kp_region_start;
        vm_area_add_early(&kp_vm);
        log_boot("add vmalloc area: %llx, %llx\n", (unsigned long long)kp_vm.addr, (unsigned long long)kp_vm.size);
    }
#endif
}

// Restore the map anchor area (a sacrificed kernel function) to its
// original bytes. Idempotent. Always runs inside start(), before
// sched_init: the anchor functions (tcp_init_sock & friends) must be
// restored before any of them can be called again, and the tail return
// below in start() never executes the anchor bytes after this.
//
// AArch32 does not use a sacrificed kernel function at all: the map region
// lives in the kernel image's own section-alignment padding, which contains no
// live kernel content, so there is nothing to restore.  Worse, restoring it
// would be actively fatal -- on AArch32 the tail call `((start_f)start_va)(...)`
// at the end of _paging_init re-enters the *map region itself*, which is
// therefore still executing when start() runs.  The backup saved before the
// copy is all zeros, so restoring it would overwrite the running code and
// prefetch-abort.  Observed on the 5.15.167 oracle: the byte-identical image
// instruction at 0xc0f94924 was zeroed by the restore and the CPU took a
// prefetch abort there (log: `Restore: ffffffffc0f940e0, ffffffffc0f950e0`
// followed by a fault at 0xc0f94924).
static int map_restored = 0;
void restore_map()
{
    if (map_restored) return;
    map_restored = 1;

#if defined(CONFIG_ARM)
    // Nothing to restore: the map region was never borrowed from live kernel
    // text.  Logged so the skip is visible rather than silent.
    log_boot("Restore: skipped (arm32 keeps .setup.map in linker padding)\n");
    return;
#else
    uint64_t start = kernel_va + start_preset.map_offset;
    uint64_t end = start + start_preset.map_backup_len;
    log_boot("Restore: %llx, %llx\n", start, end);

    for (uint64_t i = start; i < align_ceil(end, page_size); i += page_size) {
        kp_pte_t *pte = pgtable_entry_kernel(i);
        uint64_t orig = *pte;
        *pte = (orig | PTE_DBM) & ~PTE_RDONLY;
        flush_tlb_kernel_page(i);
        for (uint64_t j = i; j >= start && j < end && j < i + page_size; j += 8) {
            *(uint64_t *)j = *(uint64_t *)(start_preset.map_backup + (j - start));
        }
        *pte = orig;
        flush_tlb_kernel_page(i);
    }
    flush_icache_all();
#endif
}

#if defined(CONFIG_ARM)
/*
 * AArch32 counterpart of the arm64 system-register dump below.  AArch32 has no
 * exception levels and no AArch64 ID_*_EL1 registers, so the equivalent
 * information comes from CP15.  CRn/CRm/op2 are spelled literally (opcode1 is 0
 * for every one of these) so each read is self-documenting.
 */
#define log_cp15(name, crn, crm, op2)                                               \
    do {                                                                            \
        uint32_t name##_val = 0;                                                    \
        asm volatile("mrc p15, 0, %0, " #crn ", " #crm ", " #op2 : "=r"(name##_val)); \
        log_boot("" #name ": %x\n", name##_val);                                    \
    } while (0)

static void log_regs()
{
    log_cp15(MIDR, c0, c0, 0);     /* Main ID Register */
    log_cp15(CTR, c0, c0, 1);      /* Cache Type Register */
    log_cp15(TLBTR, c0, c0, 3);    /* TLB Type Register */
    log_cp15(MPIDR, c0, c0, 5);    /* Multiprocessor Affinity Register */
    log_cp15(REVIDR, c0, c0, 6);   /* Revision ID Register */
    log_cp15(ID_PFR0, c0, c1, 0);  /* Processor Feature Register 0 */
    log_cp15(ID_MMFR3, c0, c1, 7); /* Memory Model Feature Register 3 */
    log_cp15(ID_ISAR4, c0, c2, 4); /* Instruction Set Attribute Register 4 */
    log_cp15(SCTLR, c1, c0, 0);    /* System Control Register */
    log_cp15(TTBR0, c2, c0, 0);    /* Translation Table Base Register 0 */
    log_cp15(TTBCR, c2, c0, 2);    /* Translation Table Base Control Register */
}
#else /* AArch64 */
#define log_reg(regname)                                                   \
    do {                                                                   \
        uint64_t regname##_val = 0;                                        \
        asm volatile("mrs %[val], " #regname : [val] "+r"(regname##_val)); \
        log_boot("" #regname ": %llx\n", regname##_val);                   \
    } while (0)

static void log_regs()
{
    // log_reg(APDAKey_EL1); //      | R/W [1] | Pointer Authentication Key A for Data (Hi/Lo pair)
    // log_reg(APDBKey_EL1); //      | R/W [1] | Pointer Authentication Key B for Data (Hi/Lo pair)
    // log_reg(APGAKey_EL1); //      | R/W [1] | Pointer Authentication Generic Key (Hi/Lo pair)
    // log_reg(APIAKey_EL1); //      | R/W [1] | Pointer Authentication Key A for Instructions (Hi/Lo pair)
    // log_reg(APIBKey_EL1); //      | R/W [1] | Pointer Authentication Key B for Instructions (Hi/Lo pair)
    // log_reg(CTR_EL0); //          | R   [5] | Cache Type Register
    // log_reg(HCR_EL2); //          | R   [2] | Hypervisor Configuration Register
    log_reg(ID_AA64AFR0_EL1); //  | R       | AArch64 Auxiliary Feature Register 0
    log_reg(ID_AA64AFR1_EL1); //  | R       | AArch64 Auxiliary Feature Register 1
    log_reg(ID_AA64DFR0_EL1); //  | R       | AArch64 Debug Feature Register 0
    log_reg(ID_AA64DFR1_EL1); //  | R       | AArch64 Debug Feature Register 1
    // log_reg(ID_AA64ISAR0_EL1); // | R       | AArch64 Instruction Set Attribute Register 0
    // log_reg(ID_AA64ISAR1_EL1); // | R       | AArch64 Instruction Set Attribute Register 1
    // log_reg(ID_AA64ISAR2_EL1); // | R       | AArch64 Instruction Set Attribute Register 2
    log_reg(ID_AA64MMFR0_EL1); // | R       | AArch64 Memory Model Feature Register 0
    log_reg(ID_AA64MMFR1_EL1); // | R       | AArch64 Memory Model Feature Register 1
    log_reg(ID_AA64MMFR2_EL1); // | R       | AArch64 Memory Model Feature Register 2
    // log_reg(ID_AA64MMFR3_EL1); // | R       | AArch64 Memory Model Feature Register 3
    // log_reg(ID_AA64MMFR4_EL1); // | R       | AArch64 Memory Model Feature Register 4
    log_reg(ID_AA64PFR0_EL1); //  | R       | AArch64 Processor Feature Register 0
    log_reg(ID_AA64PFR1_EL1); //  | R       | AArch64 Processor Feature Register 1
    // log_reg(ID_AA64PFR2_EL1); //  | R       | AArch64 Processor Feature Register 2
    // log_reg(ID_AA64SMFR0_EL1); // | R       | SME Feature ID register 0
    // log_reg(ID_AA64ZFR0_EL1); //  | R       | SVE Feature ID register 0
    log_reg(MAIR_EL1); //         | R       | Memory Attribute Indirection Register (EL1)
    // log_reg(MAIR2_EL1); //        | R       | Extended Memory Attribute Indirection Register (EL1)
    log_reg(MIDR_EL1); //         | R       | Main ID Register
    log_reg(MPIDR_EL1); //        | R       | Multiprocessor Affinity Register
    // log_reg(PIR_EL1); //          | R       | Permission Indirection Register 1 (EL1)
    // log_reg(PIRE0_EL1); //        | R       | Permission Indirection Register 0 (EL1)
    log_reg(REVIDR_EL1); //       | R       | Revision ID Register
    // log_reg(RNDR); //             | R       | Random Number
    // log_reg(RNDRRS); //           | R       | Reseeded Random Number
    // log_reg(SCR_EL3); //          |     [3] | Secure Configuration Register (EL3)
    log_reg(SCTLR_EL1); //        | R/W     | System Control Register (EL1)
    // log_reg(SCTLR2_EL1); //       | R/W     | System Control Register 2 (EL1)
    // log_reg(SCXTNUM_EL0); //      | R/W     | EL0 Read/Write Software Context Number
    // log_reg(SCXTNUM_EL1); //      | R/W     | EL1 Read/Write Software Context Number
    log_reg(TCR_EL1); //          | R       | Translation Control Register (EL1)
    // log_reg(TCR2_EL1); //         | R       | Extended Translation Control Register (EL1)
    // log_reg(TPIDR_EL0); //        | R/W [5] | EL0 Read/Write Software Thread ID Register
    // log_reg(TPIDR_EL1); //        | R/W [5] | EL1 Software Thread ID Register
    // log_reg(TPIDRRO_EL0); //      | R/W [5] | EL0 Read-Only Software Thread ID Register
    // log_reg(TRCDEVARCH); //       | R       | Trace Device Architecture Register
    log_reg(TTBR0_EL1); //        | R       | Translation Table Base Register 0 (EL1)
    log_reg(TTBR1_EL1); //        | R       | Translation Table Base Register 1 (EL1)
    // log_reg(PMMIR_EL1); //        | R       | Performance Monitors Machine Identification Register
    // log_reg(PMSIDR_EL1); //       | R   [4] | Sampling Profiling ID Register
}
#endif /* CONFIG_ARM */

static int start_init(uint64_t kimage_voff, uint64_t linear_voff)
{
    unsigned long kallsym_offset = 0;
    const char *kallsyms_resolver = "preset";

    kimage_voffset = kimage_voff;
    linear_voffset = linear_voff;

    kernel_pa = start_preset.kernel_pa;
    kernel_va = kimage_voff + kernel_pa;
    kernel_size = start_preset.kernel_size;
    runtime_base_addr = (unsigned long)_link_base;

    if (start_preset.patch_config.printk) {
        printk = (typeof(printk))(kernel_va + start_preset.patch_config.printk);
    }

#if 0
    kallsym_offset = resolve_kallsyms_lookup_name_by_backward_symbol_scan(start_preset.symbol_lookup_anchor_offset);
    if (kallsym_offset) {
        kallsyms_resolver = "backward_symbol_scan";
    }
#endif
    /*
     * PRESET FIRST.  kptools derived kallsyms_lookup_name_offset for exactly
     * this kernel and it is verified against this image: 0x1dcd98 ->
     * 0xc01e4d98, which is the kernel's own kallsyms_lookup_name (the same
     * value is also carried in patch_config[0]).
     *
     * Only fall back to the symbol scan when the preset has no value.  The
     * scan calls KERNEL CODE through a second preset-derived pointer
     * (start_preset.sprintf_offset), and on this target that field is off by
     * TEXT_OFFSET (0x8000): 0x4bf0a8 -> 0xc04bf0a8, which is NOT sprintf
     * (0xc04c70a8).  Measured: the scan does not crash (stage 11 passes) -- it
     * parses garbage, returns 0 and the preset value is used anyway -- so this
     * reorder only removes up to 4096 bogus kernel calls and boot-time risk.
     */
    kallsym_offset = start_preset.kallsyms_lookup_name_offset;
    if (!kallsym_offset) {
        kallsym_offset = resolve_kallsyms_lookup_name_by_symbol_lookup_anchor();
        if (kallsym_offset) {
            kallsyms_resolver = "symbol_lookup_anchor";
        }
    }
    if (!kallsym_offset) {
        log_kallsyms_lookup_name_unresolved();
        return -1;
    }

    start_preset.kallsyms_lookup_name_offset = kallsym_offset;
    kallsyms_lookup_name = (typeof(kallsyms_lookup_name))(kernel_va + kallsym_offset);
    if (!kallsyms_lookup_name) {
        log_kallsyms_lookup_name_unresolved();
        return -1;
    }
    kernel_stext_va = kallsyms_lookup_name("_stext");
    printk = (typeof(printk))kallsyms_lookup_name("printk");
    if (!printk) printk = (typeof(printk))kallsyms_lookup_name("_printk");
    if (!printk) {
        return -1;
    }

    vsnprintf = (typeof(vsnprintf))kallsyms_lookup_name("vsnprintf");
    if (!vsnprintf) {
        printk("KP failed to resolve vsnprintf\n");
        return -1;
    }

    log_boot(KERNEL_PATCH_BANNER);

    endian = *(unsigned char *)&(uint16_t){ 1 } ? little : big;
    setup_header = &start_preset.header;
    kver = VERSION(start_preset.kernel_version.major, start_preset.kernel_version.minor,
                   start_preset.kernel_version.patch);
    kpver = VERSION(setup_header->kp_version.major, setup_header->kp_version.minor, setup_header->kp_version.patch);

    log_boot("Kernel pa: %llx\n", kernel_pa);
    log_boot("Kernel va: %llx\n", kernel_va);

    log_boot("Kernel Version: %x\n", kver);
    log_boot("KernelPatch Version: %x\n", kpver);
    log_boot("KernelPatch Config: %llx\n", setup_header->config_flags);
    log_boot("KernelPatch Compile Time: %s\n", setup_header->compile_time);
    log_boot("kallsyms_lookup_name offset: %llx (%s)\n", (uint64_t)start_preset.kallsyms_lookup_name_offset,
             kallsyms_resolver);

    log_boot("KernelPatch link base: %llx, runtime base: %llx\n", (uint64_t)link_base_addr,
             (uint64_t)runtime_base_addr);

    kallsyms_on_each_symbol = (typeof(kallsyms_on_each_symbol))kallsyms_lookup_name("kallsyms_on_each_symbol");
    kernel_kallsyms_on_each_match_symbol =
        (typeof(kernel_kallsyms_on_each_match_symbol))kallsyms_lookup_name("kallsyms_on_each_match_symbol");

#if defined(CONFIG_ARM)
    /* AArch32, non-LPAE: no TCR_EL1/TTBR1_EL1 and no exception levels.  There is
     * one 32-bit translation regime with 4 KB pages (L1 + L2) and, because the
     * target's TTBCR.N == 0, TTBR0's single 4096-entry table covers the whole
     * 4 GB -- see include/pgtable.h.  pgd_va is that L1 table's VA. */
    va_bits = 32;
    page_shift = 12;
    page_size = 1 << page_shift;
    page_level = 2;
    pgd_pa = kp_read_ttbr0() & 0xffffc000u;
    pgd_va = phys_to_virt(pgd_pa);
    log_boot("TTBR0: %llx, TTBCR: %llx\n", (uint64_t)kp_read_ttbr0(), (uint64_t)kp_read_ttbcr());
    return 0;
#else
    uint64_t tcr_el1;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    uint64_t t1sz = bits(tcr_el1, 21, 16);
    va_bits = 64 - t1sz;
    uint64_t tg1 = bits(tcr_el1, 31, 30);

    page_shift = 12;
    if (tg1 == 1) {
        page_shift = 14;
    } else if (tg1 == 3) {
        page_shift = 16;
    }
    page_size = 1 << page_shift;

    page_level = (va_bits - 4) / (page_shift - 3);

    uint64_t ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    uint64_t baddr = ttbr1_el1 & 0xFFFFFFFFFFFE;
    uint64_t page_size_mask = ~(page_size - 1);
    pgd_pa = baddr & page_size_mask;
    pgd_va = phys_to_virt(pgd_pa);
    return 0;
#endif
}

void symbol_init();
int patch();

int __attribute__((section(".start.text"))) __noinline start(uint64_t kimage_voff, uint64_t linear_voff,
                                                             uint64_t boot_stage)
{
    int rc = 0;
    (void)boot_stage;
    // raw stash for post-mortem debugging: no vsnprintf available yet here
    ((uint64_t *)boot_log)[0] = 0x4b50565354415254ull; // "KPVSTART" marker
    ((uint64_t *)boot_log)[1] = kimage_voff;
    ((uint64_t *)boot_log)[2] = linear_voff;
#if defined(CONFIG_ARM)
    /*
     * --- KP_MAP_STAGE ladder, part 2: inside start() ---------------------
     * The _paging_init ladder proved the whole relocation is clean on this
     * target (stages 3/4/5 all boot), so the remaining fault is in KP's own
     * init here.  These checkpoints split that init into ordered steps:
     *   10 = return before any KP init at all (tests the jump into the
     *        relocated region and the return through _paging_init's tail)
     *   11 = return after start_init() (kallsyms + printk + vmalloc area)
     *   12 = return after prot_myself() (page-table self-protection)
     *   13 = return after symbol_init(), before patch()
     */
    if (boot_stage == 10) return 0;
#endif
    rc = start_init(kimage_voff, linear_voff);
    if (rc) return rc;
#if defined(CONFIG_ARM)
    if (boot_stage == 11) return 0;
#endif
    prot_myself(boot_stage);
#if defined(CONFIG_ARM)
    if (boot_stage == 12) return 0;
#endif
    // Restore the map anchor.
    //
    // ARM64: select_map_area() NOPs a code hole in live kernel text and the
    // bytes there ARE relocated into, so they must be restored -- and the tail
    // return below is what makes that safe (`return ...` never re-executes the
    // hooked bytes).
    //
    // AArch32 (Design B): kptools places .setup.map in the linker padding page
    // immediately below __init_begin (no kallsyms symbol there, bytes verified
    // all-zero in the input image, page necessarily in the MT_MEMORY_RWX half).
    // kptools NOPs nothing on arm32, so nothing was borrowed from live code and
    // there is nothing to restore.  restore_map() still runs for the arm64
    // path's sake but early-returns on CONFIG_ARM, which is why ARM32 needs no
    // stack-frame handoff and no "tail never executes it" argument at all --
    // the reason root cause 7 cannot recur here.
    restore_map();
    log_regs();
    predata_init();
    symbol_init();
#if defined(CONFIG_ARM)
    if (boot_stage == 13) return 0;
#endif
    rc = patch();
#if defined(CONFIG_ARM)
    // AArch32: return normally.
    //
    // The LINKED _paging_init is base/map.c:650 (kernel/arm/map.c's `bx r12`
    // stub is the superseded M4a scaffold and is NOT linked).  base/map.c
    // restores paging_init's original first instruction, calls the real
    // paging_init itself, builds and copies the map region, and finally calls
    // start() with a plain `bl` (base/map.c:906).  So start() is an ordinary
    // callee: returning here lands back in _paging_init's tail, whose own
    // epilogue returns straight to paging_init's original caller.  No frame
    // rebuild is needed or safe to guess -- the A32 paging_init prologue
    // layout has not been measured -- and no bytes need restoring because the
    // map region was never borrowed from live text (see restore_map above).
    return rc;
#else
    // Return to the kernel's paging_init caller directly, restoring
    // _paging_init's callee-saved registers from its frame: [our x29] = its
    // x29 (P); its saved x19-x28 at P+16..P+88; the caller's frame pointer
    // at [P]; the kernel's return address at P+8; the caller's sp at
    // P+0x280 (frame 0x290 with x29 = sp + 0x10 — the same layout on the
    // scratch and legacy _paging_init paths, since it is the same compiled
    // function entered via blr in both cases).  x29 must be restored from
    // [P], exactly like _paging_init's own epilogue (ldp x29, x30,
    // [sp, #16]) — returning with x29 = P instead of the caller's FP hangs
    // the 4.9 device kernel in setup_arch's post-paging_init code.  This
    // bypasses _paging_init's epilogue, which lives in the RESTORED map
    // anchor: with the map section (~0xf10, scratch machinery included)
    // larger than the carved hole, the epilogue position can land
    // mid-function inside e.g. do_tcp_getsockopt, and executing those
    // restored native bytes kills 5.10 GKI before the console is up
    // (verified in QEMU).  The historical 4.9 tail-return boot loop was
    // confounded with the scratch path running on 4.x.
    __asm__ volatile(
        "ldr x10, [x29]\n"
        "ldp x19, x20, [x10, #16]\n"
        "ldp x21, x22, [x10, #32]\n"
        "ldp x23, x24, [x10, #48]\n"
        "ldp x25, x26, [x10, #64]\n"
        "ldp x27, x28, [x10, #80]\n"
        "ldr x29, [x10]\n"
        "ldr x30, [x10, #8]\n"
        "add sp, x10, #0x280\n"
        "ret\n"
        : : : "x10", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
              "x27", "x28", "x29", "x30", "memory");
    __builtin_unreachable();
#endif
}
