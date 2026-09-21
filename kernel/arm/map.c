/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelPatch AArch32 (ARMv7-A) port — minimal map (M4 step 1).
 * Port skeleton of kernel/base/map.c (aarch64). NON-LPAE short-descriptor target.
 *
 * ===== MILESTONE SCOPE (M4a) =====
 * Prove the paging_init hook end-to-end WITHOUT page-table relocation:
 *   map_prepare() [setup-time, MMU off, physical]:
 *     - fill map_data (kernel_pa, map_offset, paging_init/printk offsets)
 *     - back up paging_init's first instruction
 *     - overwrite it with an A32 `B` to the (relocated) _paging_init
 *     - copy the whole .map region into the kernel text hole at map_offset
 *       (that hole is inside the kernel's mapped/reserved text, unlike the
 *        kpimg appended past _end which may be unmapped when paging_init runs)
 *   _paging_init() [runs relocated, MMU on, virtual]:
 *     - printk one line (proves hook timing + printk reachability)
 *     - restore paging_init's original instruction, I-cache flush, call it
 *     - return -> kernel continues booting normally
 *
 * M4 (full, todo): replace _paging_init body with the short-descriptor page
 * table build + memblock alloc + kpimg(start) relocation (port of A64 map.c).
 *
 * Position independence: this code is injected/relocated, so it never relies on
 * absolute symbol addresses. map_prepare gets `delta` (runtime-minus-link bias)
 * from setup1.S; _paging_init self-locates via the A64 get_myva()/get_data()
 * trick (PC-relative `adr`).
 */

#include "../base/setup.h"

typedef void (*paging_init_f)(void);
typedef int (*printk_f)(const char *fmt, ...);

/* ---- M4b: kernel memory allocation ------------------------------------
 * kptools resolves the memblock symbols into setup_preset.map_symbol (it
 * exits if none resolve), so we only have to pick the right signature:
 *   MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID -> memblock_phys_alloc_try_nid
 *                                           (size, align, nid) -> phys
 *   MAP_SYM_MEMBLOCK_ALLOC_TRY_NID      -> memblock_alloc_try_nid
 *                                           (size, align, min, max, nid) -> va
 * The 5-arg form is what Linux 4.x (i.e. the watch's 4.9.193) provides, so
 * pass all five explicitly instead of relying on stale argument registers. */
#define NUMA_NO_NODE (-1)
typedef uint32_t (*mem_alloc3_f)(uint32_t size, uint32_t align, int nid);
typedef uint32_t (*mem_alloc5_f)(uint32_t size, uint32_t align, uint32_t min_addr, uint32_t max_addr, int nid);

typedef void (*map_test_f)(uint32_t printk_addr, const char *fmt);

#define M4B_ALLOC_SIZE 0x1000u
#define M4B_ALLOC_ALIGN 0x10u

extern setup_preset_t setup_preset; // defined in base/setup.c

map_data_t map_data __section(.map.data) __aligned(MAP_ALIGN) = {
#ifdef MAP_DEBUG
    .str_fmt_px = "KP-ARM: %x %x\n",
    .str_fmt_alloc = "KP-ARM m: %x %x %x %x\n",
    .str_fmt_call = "KP-ARM call ok\n",
    .str_fmt_pre = "KP-ARM pre: %x %x\n",
    .str_fmt_desc = "KP-ARM r: %x %x %x %x %x %x\n",
    .str_fmt_xn = "KP-ARM xn: %x %x %x %x\n",
    /* printk(fmt) with the callee in r0 and fmt in r1:
     *   push {r4, lr} / mov r4, r0 / mov r0, r1 / blx r4 / pop {r4, pc}  */
    .test_code = {0x10, 0x40, 0x2d, (char)0xe9, 0x00, 0x40, (char)0xa0, (char)0xe1,
                  0x01, 0x00, (char)0xa0, (char)0xe1, 0x34, (char)0xff, 0x2f, (char)0xe1,
                  0x10, (char)0x80, (char)0xbd, (char)0xe8},
#endif
};

/* ---- ARMv7 cache maintenance helpers (CP15). always_inline so .map.text
 * contains only get_myva/get_data/_paging_init (get_data's self-location
 * assumes get_myva sits immediately after map_data). ---- */
#define AINLINE static inline __attribute__((always_inline))
AINLINE void dsb_sy(void) { asm volatile("dsb sy" ::: "memory"); }
AINLINE void isb_(void) { asm volatile("isb" ::: "memory"); }
// clean+invalidate one D-cache line to PoC (DCCIMVAC), by MVA
AINLINE void dccimvac(uint32_t va) { asm volatile("mcr p15, 0, %0, c7, c14, 1" ::"r"(va) : "memory"); }
// clean D to PoU (DCCMVAU) + invalidate I to PoU (ICIMVAU), by MVA
AINLINE void sync_icache_va(uint32_t va)
{
    asm volatile("mcr p15, 0, %0, c7, c11, 1" ::"r"(va) : "memory"); // DCCMVAU
    dsb_sy();
    asm volatile("mcr p15, 0, %0, c7, c5, 1" ::"r"(va) : "memory"); // ICIMVAU
    dsb_sy();
    isb_();
}

/* =========================================================================
 * map_prepare: SETUP-TIME (MMU off, physical). Position-independent: every
 * kpimg symbol address is (link address + delta). Must not call out to any
 * absolute-addressed function; keep it self-contained.
 * ========================================================================= */
void __section(.setup.text) __noinline map_prepare(uint32_t kernel_pa, uint32_t delta)
{
    map_data_t *md = (map_data_t *)((uint32_t)&map_data + delta);
    setup_preset_t *sp = (setup_preset_t *)((uint32_t)&setup_preset + delta);

    uint32_t map_offset = (uint32_t)sp->map_offset;
    uint32_t paging_init_off = (uint32_t)sp->paging_init_offset;
    uint32_t printk_off = (uint32_t)sp->printk_offset;

    md->kernel_pa = kernel_pa;
    md->kernel_version = sp->kernel_version.major << 24 | sp->kernel_version.minor << 16 |
                         sp->kernel_version.patch << 8;
    md->map_offset = map_offset;
    md->paging_init_relo = paging_init_off; // + kernel_va added in _paging_init
#ifdef MAP_DEBUG
    md->printk_relo = printk_off;
#endif

    // Carry the memblock symbol offsets over from the preset. They are
    // kernel-base-relative like paging_init_relo/printk_relo, so _paging_init
    // adds kernel_va before calling them. Copied byte-wise so no memcpy() call
    // is emitted (this runs before the kernel is relocated).
    {
        const volatile uint8_t *s = (const volatile uint8_t *)&sp->map_symbol;
        volatile uint8_t *d = (volatile uint8_t *)&md->map_symbol;
        for (uint32_t i = 0; i < sizeof(map_symbol_t); i++) d[i] = s[i];
    }

    // back up paging_init's first instruction (physical: kernel_pa + offset)
    uint32_t *pi_pa = (uint32_t *)(kernel_pa + paging_init_off);
    md->paging_init_backup = *pi_pa;

    // where _paging_init lands after .map is copied to the kernel hole:
    //   replace_off = (_paging_init - _map_start) + map_offset   [link-const diff]
    uint32_t rel_in_map = (uint32_t)((uint32_t)&_paging_init - (uint32_t)&_map_start);
    uint32_t replace_off = rel_in_map + map_offset;

    // A32 B at pi_pa -> (kernel_pa + replace_off). Both relative to kernel_pa,
    // so the branch displacement is delta/PA-independent.
    int32_t disp = (int32_t)replace_off - (int32_t)paging_init_off - 8;
    uint32_t imm24 = ((uint32_t)(disp >> 2)) & 0x00FFFFFFu;
    *pi_pa = 0xEA000000u | imm24;

    // relocate the whole .map region into the kernel hole (physical copy)
    uint8_t *dst = (uint8_t *)(kernel_pa + map_offset);
    const uint8_t *src = (const uint8_t *)((uint32_t)&_map_start + delta);
    uint32_t len = (uint32_t)((uint32_t)&_map_end - (uint32_t)&_map_start);
    for (uint32_t i = 0; i < len; i++) dst[i] = src[i];

    // make the rewritten paging_init insn and the relocated code coherent
    dccimvac((uint32_t)pi_pa);
    dsb_sy();
    for (uint32_t i = 0; i < len; i += 32) dccimvac((uint32_t)dst + i);
    dsb_sy();
    // invalidate entire I-cache to PoU + branch predictor
    asm volatile("mcr p15, 0, %0, c7, c5, 0" ::"r"(0) : "memory"); // ICIALLU
    asm volatile("mcr p15, 0, %0, c7, c5, 6" ::"r"(0) : "memory"); // BPIALL
    dsb_sy();
    isb_();
}

/* =========================================================================
 * _paging_init: runs RELOCATED at (kernel_va + map_offset + off), MMU on.
 * ========================================================================= */
static uint32_t __section(.map.text) __noinline __aligned(MAP_ALIGN) get_myva(void)
{
    uint32_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    return this_va & ~((uint32_t)MAP_ALIGN - 1);
}

static map_data_t *__section(.map.text) __noinline get_data(void)
{
    uint32_t va = get_myva() - sizeof(map_data_t);
    return (map_data_t *)(va & ~((uint32_t)MAP_ALIGN - 1));
}

/* ---- ARMv7 short-descriptor (non-LPAE) page-table walk -------------------
 * Linux maps the kernel image RWX but ordinary pages RW, i.e. with XN set, so
 * memory obtained from memblock is NOT executable through its linear alias.
 * These helpers return the raw PDE / PTE so the real XN+AP bit layout is read
 * off a live kernel rather than assumed.
 *   TTBR1 bits[31:14] hold the table base (bits[13:0] are control/flag bits).
 *   PDE bits[1:0]: 0b01 = page table, 0b10 = section.                        */
AINLINE uint32_t ttbr1_base(void)
{
    uint32_t t;
    asm volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(t));
    return t & 0xFFFFE000u;
}

AINLINE uint32_t read_ttbr0(void)
{
    uint32_t t;
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(t));
    return t;
}
AINLINE uint32_t read_ttbr1(void)
{
    uint32_t t;
    asm volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(t));
    return t;
}
AINLINE uint32_t read_ttbcr(void)
{
    uint32_t t;
    asm volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(t));
    return t;
}

AINLINE void flush_tlb_all_arm(void)
{
    dsb_sy();
    asm volatile("mcr p15, 0, %0, c8, c7, 0" ::"r"(0) : "memory"); // TLBIALL
    dsb_sy();
    isb_();
}

/* First-level slot for a kernel VA. The target kernel runs with TTBCR.N == 0
 * (measured at runtime: TTBCR = 0, TTBR0 == TTBR1), so there is a single
 * 4096-entry table of 1MB sections indexed by va >> 20 -- *not* the 2-entry
 * TTBR0/TTBR1 split with va >> 21 that LPAE-style assumptions suggest. */
AINLINE volatile uint32_t *l1_slot(map_data_t *data, uint32_t va)
{
    uint32_t base = (read_ttbr0() & 0xFFFFC000u) + (uint32_t)data->linear_voffset;
    return &((volatile uint32_t *)base)[(va >> 20) & 0xFFFu];
}

static uint32_t __section(.map.text) __noinline __attribute__((used))
mmu_pde(map_data_t *data, uint32_t va)
{
    uint32_t pgd = ttbr1_base() + (uint32_t)data->linear_voffset;
    return ((volatile uint32_t *)pgd)[(va >> 21) & 0x7FFu];
}

static uint32_t __section(.map.text) __noinline __attribute__((used))
mmu_pte(map_data_t *data, uint32_t va)
{
    uint32_t pde = mmu_pde(data, va);
    if ((pde & 3u) != 1u) return 0xFFFFFFFFu; // section mapping: no PTE level
    uint32_t table = (pde & 0xFFFFFC00u) + (uint32_t)data->linear_voffset;
    return ((volatile uint32_t *)table)[(va >> 12) & 0x1FFu];
}

/* ==== M4a hook body ====
 * Everything here is position independent: no absolute literals, no direct
 * calls to absolute addresses, no string literals. The printk function address
 * and the format string pointer both come from map_data (filled in at setup
 * time by map_prepare), so they are valid at the relocated runtime VA.
 *
 * Must be entered with sp 8-byte aligned (it is a normal AAPCS callee).
 * Returns the runtime VA of paging_init for the stub to tail-call. */
uint32_t __section(.map.text) __noinline __attribute__((used))
kp_paging_init_work(void)
{
    map_data_t *data = get_data();
    uint32_t kernel_va = (uint32_t)data - data->map_offset;
    uint32_t pi_va = (uint32_t)data->paging_init_relo + kernel_va;

#ifdef MAP_DEBUG
    // printk_relo is a link-time offset -> add the runtime kernel VA.
    // str_fmt_px is a 24-byte buffer *inside map_data*, which map_prepare()
    // copies into the kernel text hole, so it is already a valid runtime
    // pointer to the format string. (Using a bare string literal here would
    // emit its link-time address and fault once relocated.)
    printk_f printk = (printk_f)((uint32_t)data->printk_relo + kernel_va);
    printk(data->str_fmt_px, kernel_va, (uint32_t)data->kernel_pa);

    // ---- M4b: allocate kernel memory and execute code out of it ----
    // On AArch32 the linear map is one flat offset (__va(x) = x + off), so a
    // single constant converts phys<->virt. Unlike AArch64 we do not need to
    // build a mapping from scratch -- but we DO still have to clear XN, because
    // Linux maps ordinary memory non-executable (see below).
    data->linear_voffset = kernel_va - (uint32_t)data->kernel_pa;

    uint32_t alloc_pa = 0, alloc_va = 0;
    uint32_t alloc_relo = (uint32_t)data->map_symbol.memblock_phys_alloc_relo;
    uint32_t alloc_type = (uint32_t)data->map_symbol.memblock_phys_alloc_type;
    if (alloc_relo) {
        uint32_t fn = alloc_relo + kernel_va;
        if (alloc_type == MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID) {
            // 5.x: memblock_phys_alloc_try_nid(size, align, nid) -> phys addr
            alloc_pa = ((mem_alloc3_f)fn)(M4B_ALLOC_SIZE, M4B_ALLOC_ALIGN, NUMA_NO_NODE);
            alloc_va = alloc_pa + (uint32_t)data->linear_voffset;
        } else {
            // 4.x (the watch's 4.9.193): memblock_alloc_try_nid(size, align,
            // min_addr, max_addr, nid) -> __va(). All five args are passed
            // explicitly; upstream's 3-arg call would leave max_addr/nid as
            // stale register garbage on a 4.x kernel.
            alloc_va = ((mem_alloc5_f)fn)(M4B_ALLOC_SIZE, M4B_ALLOC_ALIGN, 0, 0xFFFFFFFFu, NUMA_NO_NODE);
            alloc_pa = alloc_va - (uint32_t)data->linear_voffset;
        }
    }
    printk(data->str_fmt_alloc, alloc_relo, alloc_type, alloc_pa, alloc_va);

    if (alloc_va) {
        // paging_init() has NOT yet run map_lowmem(), so at hook time only the
        // kernel image is mapped and the linear alias of a memblock allocation
        // is absent from the L1 table (measured: slot == 0). So we install the
        // mapping ourselves -- the AArch32 analogue of the AArch64 port's
        // get_or_create_pte, except here it is a single 1MB section descriptor.
        //
        // The attribute word is copied from a live known-good RWX section (the
        // one holding paging_init) with XN cleared, rather than hard-coding
        // TEX/C/B/AP/domain bits. Because linear_voffset maps VA 0xcb000000 to
        // PA 0x4b000000, this section is identical to what map_lowmem() will
        // later install -- except executable -- so it is harmless and
        // idempotent.
        uint32_t attr = (*l1_slot(data, pi_va)) & 0x000FFFFFu;
        uint32_t sect = (alloc_pa & 0xFFF00000u) | (attr & ~0x10u); // XN = 0
        volatile uint32_t *slot = l1_slot(data, alloc_va);
        uint32_t before = *slot;
        printk(data->str_fmt_xn, before, sect, alloc_va, attr);

        *slot = sect;
        dsb_sy();
        flush_tlb_all_arm();
        printk(data->str_fmt_xn, *slot, alloc_pa, (uint32_t)slot, kernel_va);

        // Copy the blob in, make it visible to the instruction fetcher, run it.
        volatile uint8_t *dst = (volatile uint8_t *)alloc_va;
        for (uint32_t i = 0; i < sizeof(data->test_code); i++) dst[i] = data->test_code[i];
        dsb_sy();
        for (uint32_t i = 0; i < sizeof(data->test_code); i += 32) dccimvac((uint32_t)dst + i);
        dsb_sy();
        sync_icache_va(alloc_va);
        ((map_test_f)alloc_va)((uint32_t)data->printk_relo + kernel_va, data->str_fmt_call);
    }
#endif

    // restore paging_init's original first instruction, then make it visible
    *(uint32_t *)pi_va = data->paging_init_backup;
    sync_icache_va(pi_va);

    return pi_va;
}

/* ==== M4a entry stub ====
 * Entered by the B we rewrote into paging_init's FIRST instruction, so
 * paging_init's prologue has not run yet and its argument registers are still
 * live: r0 = const struct machine_desc *mdesc.
 *
 * The worker calls printk(), which returns 25 in r0. Handing that back as the
 * argument made paging_init save mdesc=0x19 and later fault at
 * mdesc->map_io == 0x19 + 0x4c == 0x65. So save/restore the argument and
 * callee-saved registers, and park the tail-call target in ip (r12), which is
 * caller-saved and therefore free for us to clobber.
 *
 * 10 registers = 40 bytes, keeping sp 8-byte aligned across the call. */
void __section(.map.text) __noinline _paging_init(void)
{
    asm volatile(
        "push {r0, r1, r2, r3, r4, r5, r6, r7, r8, lr}\n\t"
        "bl   kp_paging_init_work\n\t"
        "mov  r12, r0\n\t"
        "pop  {r0, r1, r2, r3, r4, r5, r6, r7, r8, lr}\n\t"
        "bx   r12\n\t");
    __builtin_unreachable();
}
