/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_LOG_H_
#define _KP_LOG_H_

#include <stdint.h>

#define PREFIX_MAX 48
#define LOG_LINE_MAX (1024 - PREFIX_MAX)

/* Format checking, part 1 of 2: the printk POINTER.  On ILP32 (AArch32) any
 * 32-bit value formatted with %llx makes vsnprintf read a 64-bit register
 * pair, which silently drops the value AND desynchronises every later
 * argument -- so it must be a compile error, not a silent boot-log lie.
 * The logkv/logkd/... macros below expand through this pointer; GCC reports
 * each misuse with a `note: in expansion of macro` naming the real call site,
 * which is what port/fix_ilp32_format.py consumes.  It also reports inside
 * this header, so DO NOT run an automated argument-cast fixer over this file
 * (an earlier version did and corrupted the #define lines). */
extern void (*printk)(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#define logkv(fmt, ...) printk("[+] KP V " fmt, ##__VA_ARGS__)
// #define logkv(fmt, ...)

// #define logkfv(fmt, ...) printk("[+] KP V %s: " fmt, __func__, ##__VA_ARGS__)
#define logkfv(fmt, ...)

#define logkd(fmt, ...) printk("[+] KP D " fmt, ##__VA_ARGS__)
#define logkfd(fmt, ...) printk("[+] KP D %s: " fmt, __func__, ##__VA_ARGS__)

#define logki(fmt, ...) printk("[+] KP I " fmt, ##__VA_ARGS__)
#define logkfi(fmt, ...) printk("[+] KP I %s: " fmt, __func__, ##__VA_ARGS__)

#define logkw(fmt, ...) printk("[-] KP W " fmt, ##__VA_ARGS__)
#define logkfw(fmt, ...) printk("[-] KP W %s: " fmt, __func__, ##__VA_ARGS__)

#define logke(fmt, ...) printk("[-] KP E " fmt, ##__VA_ARGS__)
#define logkfe(fmt, ...) printk("[-] KP E %s: " fmt, __func__, ##__VA_ARGS__)

/* Format checking, part 2 of 2: the real function.  Gives precise caller
 * locations for the log_boot() family (all the arm32 bring-up findings below
 * came from these diagnostics). */
void log_boot(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
const char *get_boot_log();

#endif