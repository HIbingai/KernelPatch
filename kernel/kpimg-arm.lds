/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelPatch AArch32 (ARMv7-A) port — linker script.
 * Port of kernel/kpimg.lds (aarch64). Non-LPAE short-descriptor target.
 *
 * Layout MUST match what tools/patch.c expects when it injects the blob:
 *   - preset_t (setup_header + setup_preset) at blob offset 0  (setup_offset)
 *   - setup_entry at blob offset 0x1000                        (text_offset = setup_offset + SZ_4K)
 * so the 4K preset page comes first, then .setup.text.
 *
 * M3a scope: preset + setup stub only (statically-verifiable injection). The
 * .setup.map / .kp.text / .kp.data sections (map.c, start.c, hook.c) get added
 * at M3b/M4 as those modules are ported, mirroring the aarch64 kpimg.lds.
 */

OUTPUT_ARCH(arm)
OUTPUT_FORMAT("elf32-littlearm")
ENTRY(setup_entry)

_link_base = 64k - 3 * 4k;

SECTIONS
{
    /DISCARD/ : { *(.discard) *(.discard.*) }
    /DISCARD/ : {
        *(.interp .dynamic)
        *(.dynsym .dynstr .hash .gnu.hash)
        *(.ARM.exidx*) *(.ARM.extab*)
        *(.comment) *(.note*)
    }

    . = _link_base;
    _link_base = .;

    /* preset page: header(64) + setup_preset + stack, padded to 4K.
     * patch.c writes the preset here (blob offset 0). */
    .setup.data : {
        _setup_start = .;
        base/setup.o(.setup.header)
        . = _setup_start + 64;
        base/setup.o(.setup.preset)
        base/setup.o(.setup.data)
        . = _setup_start + 4K;
    }

    /* setup_entry lands at blob offset 0x1000 == text_offset */
    .setup.text : {
        arm/setup1.o(.entry.text)
        arm/setup1.o(.text)
        base/setup.o(.text)
        arm/map.o(.setup.text)      /* map_prepare: runs at setup time, physical */
        *(.text)
        *(.rodata*)
        . = ALIGN(16);
        _setup_end = .;
    }

    /* .map region: copied at boot into the kernel text hole (map_offset).
     * map_data first, then get_myva/get_data/_paging_init (get_data locates
     * map_data by sitting right after it). Keep < 0x1000 (MAP_MAX_SIZE). */
    . = ALIGN(16);
    .setup.map : {
        _map_start = .;
        arm/map.o(.map.data)
        arm/map.o(.map.text)
        . = ALIGN(16);
        _map_end = .;
    }
    ASSERT(SIZEOF(.setup.map) < 0x1000, "Size too large of .setup.map!")

    . = ALIGN(16);
    .kp.data : {
        _kp_data_start = .;
        *(.data)
        *(.bss)
        *(COMMON)
        . = ALIGN(16);
        _kp_data_end = .;
    }

    . = ALIGN(16);
    _kp_end = .;
    _link_end = .;

    /* A freestanding injected blob must carry no dynamic linkage. */
    .got : { *(.got) }
    ASSERT(SIZEOF(.got) == 0, "Unexpected GOT entries detected!")
    .got.plt : { *(.got.plt) }
    ASSERT(SIZEOF(.got.plt) == 0, "Unexpected GOT/PLT entries detected!")
    .plt : { *(.plt) *(.plt.*) *(.iplt) *(.igot .igot.plt) }
    ASSERT(SIZEOF(.plt) == 0, "Unexpected PLT entries detected!")
    .rel.dyn : { *(.rel .rel*) }
    ASSERT(SIZEOF(.rel.dyn) == 0, "Unexpected dynamic relocations detected!")
}
