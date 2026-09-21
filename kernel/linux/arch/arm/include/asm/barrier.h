/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AArch32 (ARMv7-A) forwarder.
 *
 * The real definitions live in the port's own <barrier.h>, which already has a
 * CONFIG_ARM branch (DSB/DMB/ISB). This file only satisfies the
 * <asm/barrier.h> include that the imported Linux headers expect, mirroring
 * linux/tools/arch/arm64/include/asm/barrier.h.
 */
#ifndef __ASM_ARM_BARRIER_H
#define __ASM_ARM_BARRIER_H

#include <barrier.h>

#endif /* __ASM_ARM_BARRIER_H */
