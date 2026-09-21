#ifndef _KP_CACHE_H_
#define _KP_CACHE_H_

#include <stdint.h>

#ifdef CONFIG_ARM

/* ===================== AArch32 (ARMv7-A) ===================== */

/*
 * AArch32 has no exception levels: there is exactly one translation regime,
 * and cache maintenance is issued through CP15.
 */

static inline void local_flush_icache_all(void)
{
    asm volatile("mcr p15, 0, %0, c7, c5, 0" ::"r"(0) : "memory"); /* ICIALLU */
    asm volatile("dsb" ::: "memory");
    asm volatile("isb" ::: "memory");
}

static inline void flush_icache_all(void)
{
    asm volatile("dsb" ::: "memory");
    asm volatile("mcr p15, 0, %0, c7, c5, 0" ::"r"(0) : "memory"); /* ICIALLU */
    asm volatile("dsb" ::: "memory");
    asm volatile("isb" ::: "memory");
}

enum dma_data_direction
{
    DMA_BIDIRECTIONAL = 0,
    DMA_TO_DEVICE = 1,
    DMA_FROM_DEVICE = 2,
    DMA_NONE = 3,
};

static inline void arm_cache_line_size(uint32_t *line, uint32_t *ways)
{
    uint32_t ctr;
    asm volatile("mrc p15, 0, %0, c0, c0, 1" : "=r"(ctr));
    *line = 4u << ((ctr >> 16) & 0xfu);
    *ways = ((ctr >> 3) & 0x1ffu) + 1u;
}

static inline void dccmvac(uint32_t va)
{
    asm volatile("mcr p15, 0, %0, c7, c10, 1" ::"r"(va) : "memory");
}
static inline void dccmvau(uint32_t va)
{
    asm volatile("mcr p15, 0, %0, c7, c11, 1" ::"r"(va) : "memory");
}
static inline void dccimvac(uint32_t va)
{
    asm volatile("mcr p15, 0, %0, c7, c14, 1" ::"r"(va) : "memory");
}
static inline void dcimvac(uint32_t va)
{
    asm volatile("mcr p15, 0, %0, c7, c6, 1" ::"r"(va) : "memory");
}
static inline void icimvau(uint32_t va)
{
    asm volatile("mcr p15, 0, %0, c7, c5, 1" ::"r"(va) : "memory");
}
static inline void dccsw(uint32_t val)
{
    asm volatile("mcr p15, 0, %0, c7, c10, 2" ::"r"(val) : "memory");
}
static inline void dccisw(uint32_t val)
{
    asm volatile("mcr p15, 0, %0, c7, c14, 2" ::"r"(val) : "memory");
}
static inline void dcisw(uint32_t val)
{
    asm volatile("mcr p15, 0, %0, c7, c6, 2" ::"r"(val) : "memory");
}
static inline void iciallu(void)
{
    asm volatile("mcr p15, 0, %0, c7, c5, 0" ::"r"(0) : "memory");
}
static inline void bpiall(void)
{
    asm volatile("mcr p15, 0, %0, c7, c5, 6" ::"r"(0) : "memory");
}

/* Names the shared C code uses (arm64 spelled these differently). */
static inline void dccivac(uint32_t va)
{
    dccimvac(va);
}
static inline void dccvac(uint32_t va)
{
    dccmvac(va);
}
static inline void dcivac(uint32_t va)
{
    dcimvac(va);
}

static inline void arm_dsb(void)
{
    asm volatile("dsb" ::: "memory");
}
static inline void arm_isb(void)
{
    asm volatile("isb" ::: "memory");
}

static inline void __flush_dcache_area(void *addr, size_t len)
{
    uint32_t line, ways, start, end;
    arm_cache_line_size(&line, &ways);
    start = (uint32_t)addr & ~(line - 1u);
    end = ((uint32_t)addr + (uint32_t)len + line - 1u) & ~(line - 1u);
    for (; start < end; start += line) dccimvac(start);
    arm_dsb();
}

static inline void flush_icache_range(unsigned long start, unsigned long end)
{
    uint32_t line, ways, a;
    arm_cache_line_size(&line, &ways);
    for (a = (uint32_t)start & ~(line - 1u); a < (uint32_t)end; a += line) dccmvau(a);
    arm_dsb();
    iciallu();
    arm_dsb();
    arm_isb();
}

static inline void flush_cache_all(void)
{
    flush_icache_all();
}

static inline void __flush_dcache_all(void)
{
    uint32_t line, ways, set, way;
    arm_cache_line_size(&line, &ways);
    for (way = 0; way < ways; way++)
        for (set = 0; set < 256; set++) dccisw((way << 30) | (set << 5));
    arm_dsb();
}

static inline void __flush_cache_user_range(unsigned long start, unsigned long end)
{
    flush_icache_range(start, end);
}
static inline void __inval_cache_range(unsigned long start, unsigned long end)
{
    uint32_t line, ways, a;
    arm_cache_line_size(&line, &ways);
    for (a = (uint32_t)start & ~(line - 1u); a < (uint32_t)end; a += line) dcimvac(a);
    arm_dsb();
}
static inline void __dma_inv_range(unsigned long start, unsigned long end)
{
    __inval_cache_range(start, end);
}
static inline void __dma_clean_range(unsigned long start, unsigned long end)
{
    uint32_t line, ways, a;
    arm_cache_line_size(&line, &ways);
    for (a = (uint32_t)start & ~(line - 1u); a < (uint32_t)end; a += line) dccmvac(a);
    arm_dsb();
}
static inline void __dma_flush_range(unsigned long start, unsigned long end)
{
    __flush_dcache_area((void *)start, end - start);
}
static inline void __dma_map_area(unsigned long start, unsigned long size,
                                  enum dma_data_direction dir)
{
    if (dir == DMA_FROM_DEVICE)
        __dma_inv_range(start, start + size);
    else
        __dma_clean_range(start, start + size);
}
static inline void __dma_unmap_area(unsigned long start, unsigned long size,
                                    enum dma_data_direction dir)
{
    if (dir != DMA_TO_DEVICE) __dma_inv_range(start, start + size);
}

/*
 * AArch32 has no exception levels: collapse the EL-switching arm64 helpers
 * onto the single translation regime (TTBR0 = c2,c0,0, TTBCR = c2,c0,2).
 */
static inline uint32_t current_el(void)
{
    return 1;
}
static inline void write_ttbr0(uint64_t val, uint32_t el)
{
    (void)el;
    asm volatile("mcr p15, 0, %0, c2, c0, 0" ::"r"((uint32_t)val) : "memory");
}
static inline uint64_t read_tcr(uint32_t el)
{
    uint32_t val;
    (void)el;
    asm volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(val));
    return (uint64_t)val;
}
static inline void write_tcr(uint64_t val, uint32_t el)
{
    (void)el;
    asm volatile("mcr p15, 0, %0, c2, c0, 2" ::"r"((uint32_t)val) : "memory");
}

#elif defined(CONFIG_X86_64)

static inline void local_flush_icache_all(void)
{
    /* x86 has coherent I/D; only a serializing instruction is needed after code mods */
}

static inline void flush_icache_all(void)
{
    asm volatile("wbinvd" ::: "memory");
}

static inline void __flush_dcache_area(void *addr, size_t len)
{
    /* x86 does not require explicit D-cache maintenance for coherency */
    (void)addr; (void)len;
}

void flush_icache_range(unsigned long start, unsigned long end);

#else /* ARM64 */

static inline void local_flush_icache_all(void)
{
    asm volatile("ic iallu");
    asm volatile("dsb nsh" : : : "memory");
    asm volatile("isb" : : : "memory");
}

static inline void flush_icache_all(void)
{
    asm volatile("dsb ish" : : : "memory");
    asm volatile("ic ialluis");
    asm volatile("dsb ish" : : : "memory");
    asm volatile("isb" : : : "memory");
}

/*
 * These definitions mirror those in pci.h, so they can be used
 * interchangeably with their PCI_ counterparts.
 */
enum dma_data_direction
{
    DMA_BIDIRECTIONAL = 0,
    DMA_TO_DEVICE = 1,
    DMA_FROM_DEVICE = 2,
    DMA_NONE = 3,
};

/*
 * Utility macro to choose an instruction according to the exception
 * level (EL) passed, which number is concatenated between insa and insb parts
 */
#define SWITCH_EL(insa, insb, el)    \
    if (el == 1)                     \
        asm volatile(insa "1" insb); \
    else if (el == 2)                \
        asm volatile(insa "2" insb); \
    else                             \
        asm volatile(insa "3" insb)
/* get current exception level (EL1-EL3) */
static inline uint32_t current_el(void)
{
    uint32_t el;
    asm volatile("mrs %0, CurrentEL" : "=r"(el));
    return el >> 2;
}

/* write translation table base register 0 (TTBR0_ELx) */
static inline void write_ttbr0(uint64_t val, uint32_t el)
{
    SWITCH_EL("msr ttbr0_el", ", %0" : : "r"(val) : "memory", el);
}
/* read translation control register (TCR_ELx) */
static inline uint64_t read_tcr(uint32_t el)
{
    uint64_t val = 0;
    SWITCH_EL("mrs %0, tcr_el", : "=r"(val), el);
    return val;
}
/* write translation control register (TCR_ELx) */
static inline void write_tcr(uint64_t val, uint32_t el)
{
    SWITCH_EL("msr tcr_el", ", %0" : : "r"(val) : "memory", el);
}

/* data cache clean and invalidate by VA to PoC */
static inline void dccivac(uint64_t va)
{
    asm volatile("dc civac, %0" : : "r"(va) : "memory");
}
/* data cache clean and invalidate by set/way */
static inline void dccisw(uint64_t val)
{
    asm volatile("dc cisw, %0" : : "r"(val) : "memory");
}
/* data cache clean by VA to PoC */
static inline void dccvac(uint64_t va)
{
    asm volatile("dc cvac, %0" : : "r"(va) : "memory");
}
/* data cache clean by set/way */
static inline void dccsw(uint64_t val)
{
    asm volatile("dc csw, %0" : : "r"(val) : "memory");
}
/* data cache invalidate by VA to PoC */
static inline void dcivac(uint64_t va)
{
    asm volatile("dc ivac, %0" : : "r"(va) : "memory");
}
/* data cache invalidate by set/way */
static inline void dcisw(uint64_t val)
{
    asm volatile("dc isw, %0" : : "r"(val) : "memory");
}
/* instruction cache invalidate all */
static inline void iciallu(void)
{
    asm volatile("ic iallu" : : : "memory");
}

void flush_cache_all(void);
void flush_icache_range(unsigned long start, unsigned long end);
void __flush_dcache_all();
void __flush_dcache_area(void *addr, size_t len);
void __flush_cache_user_range(unsigned long start, unsigned long end);
void __inval_cache_range(unsigned long start, unsigned long end);
void __dma_inv_range(unsigned long start, unsigned long end);
void __dma_clean_range(unsigned long start, unsigned long end);
void __dma_flush_range(unsigned long start, unsigned long end);
void __dma_map_area(unsigned long start, unsigned long size, enum dma_data_direction dir);
void __dma_unmap_area(unsigned long start, unsigned long size, enum dma_data_direction dir);

#endif /* CONFIG_ARM / CONFIG_X86_64 / ARM64 */

#endif /* _KP_CACHE_H_ */