/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AArch32 (ARMv7-A) cacheflush.h.
 *
 * The KernelPatch port keeps all cache maintenance in <cache.h>, which already
 * carries a complete CONFIG_ARM branch (CP15 ICIALLU / DCCMVAC / DCCMVAU /
 * DCCMVAC / ICIMVAU, set/way ops, flush_icache_range() and __flush_dcache_area()).
 *
 * Linux-style callers (patch/module/insn.c: #include <asm/cacheflush.h>,
 * flush_icache_range()) expect this header name, so it is a pure forwarder --
 * no definition is duplicated here.
 */
#ifndef __ASM_CACHEFLUSH_H
#define __ASM_CACHEFLUSH_H

#include <cache.h>

#endif /* __ASM_CACHEFLUSH_H */