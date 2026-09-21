/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AArch32 (ARMv7-A) ELF definitions.
 *
 * Mirrors arch/arm64/include/asm/elf.h where the two overlap.  Consumer is
 * patch/module/relo.c, which switches on relocation numbers while applying
 * ET_REL module images.
 *
 * The ARM32 (R_ARM_*) numbers are the ones this port relocates against.  The
 * R_AARCH64_* numbers are kept because relo.c still carries its AArch64
 * relocation switch (and the R_ARM_NONE / R_AARCH64_NONE shared "null" case)
 * and must keep compiling unchanged for the AArch64 build lineage.
 */
#ifndef __ASM_ELF_H
#define __ASM_ELF_H

#include <asm/ptrace.h>
#include <uapi/asm-generic/errno.h>

/*
 * ARM32 static relocation types (ARM ELF ABI).
 */
#define R_ARM_NONE 0
#define R_ARM_PC24 1
#define R_ARM_ABS32 2
#define R_ARM_REL32 3
#define R_ARM_THM_CALL 10
#define R_ARM_GLOB_DAT 21
#define R_ARM_JUMP_SLOT 22
#define R_ARM_RELATIVE 23
#define R_ARM_CALL 28
#define R_ARM_JUMP24 29
#define R_ARM_THM_JUMP24 30
#define R_ARM_MOVW_ABS_NC 43
#define R_ARM_MOVT_ABS 44
#define R_ARM_MOVW_PREL_NC 45
#define R_ARM_MOVT_PREL 46

/*
 * AArch64 static relocation types (kept for the shared relo.c switch).
 */

/* Miscellaneous. */
#define R_AARCH64_NONE 256

/* Data. */
#define R_AARCH64_ABS64 257
#define R_AARCH64_ABS32 258
#define R_AARCH64_ABS16 259
#define R_AARCH64_PREL64 260
#define R_AARCH64_PREL32 261
#define R_AARCH64_PREL16 262

/* Instructions. */
#define R_AARCH64_MOVW_UABS_G0 263
#define R_AARCH64_MOVW_UABS_G0_NC 264
#define R_AARCH64_MOVW_UABS_G1 265
#define R_AARCH64_MOVW_UABS_G1_NC 266
#define R_AARCH64_MOVW_UABS_G2 267
#define R_AARCH64_MOVW_UABS_G2_NC 268
#define R_AARCH64_MOVW_UABS_G3 269

#define R_AARCH64_MOVW_SABS_G0 270
#define R_AARCH64_MOVW_SABS_G1 271
#define R_AARCH64_MOVW_SABS_G2 272

#define R_AARCH64_LD_PREL_LO19 273
#define R_AARCH64_ADR_PREL_LO21 274
#define R_AARCH64_ADR_PREL_PG_HI21 275
#define R_AARCH64_ADR_PREL_PG_HI21_NC 276
#define R_AARCH64_ADD_ABS_LO12_NC 277
#define R_AARCH64_LDST8_ABS_LO12_NC 278

#define R_AARCH64_TSTBR14 279
#define R_AARCH64_CONDBR19 280
#define R_AARCH64_JUMP26 282
#define R_AARCH64_CALL26 283
#define R_AARCH64_LDST16_ABS_LO12_NC 284
#define R_AARCH64_LDST32_ABS_LO12_NC 285
#define R_AARCH64_LDST64_ABS_LO12_NC 286
#define R_AARCH64_LDST128_ABS_LO12_NC 299

#define R_AARCH64_MOVW_PREL_G0 287
#define R_AARCH64_MOVW_PREL_G0_NC 288
#define R_AARCH64_MOVW_PREL_G1 289
#define R_AARCH64_MOVW_PREL_G1_NC 290
#define R_AARCH64_MOVW_PREL_G2 291
#define R_AARCH64_MOVW_PREL_G2_NC 292
#define R_AARCH64_MOVW_PREL_G3 293

#define R_AARCH64_RELATIVE 1027

/*
 * These are used to set parameters in the core dumps.
 */
#ifndef EM_ARM
#define EM_ARM 40
#endif

#define ELF_CLASS ELFCLASS32
#define ELF_DATA ELFDATA2LSB
#define ELF_ARCH EM_ARM

/*
 * This yields a string that ld.so will use to load implementation specific
 * libraries for optimization.  This is more specific in intent than poking at
 * uname or /proc/cpuinfo.
 */
#define ELF_PLATFORM_SIZE 8
#define ELF_PLATFORM ("arm")

/*
 * This is used to ensure we don't load something for the wrong architecture.
 */
#define elf_check_arch(x) ((x)->e_machine == EM_ARM)

#endif /* __ASM_ELF_H */