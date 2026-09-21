/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelPatch AArch32 (ARMv7-A) port — FULL-port linker script.
 *
 * A32 counterpart of the AArch64 kernel/kpimg.lds, used to link the complete
 * inventory object set (`make -f Makefile.arm full` -> *.arm.o) plus the A32
 * entry/setjmp assembly into one position-independent injected blob.
 *
 * The M4 scaffold keeps using its own kernel/kpimg-arm.lds + arm/*.o; this
 * script is additive and must not change that path.
 *
 * Injection contract (tools/patch.c):
 *   - `setup_offset` = align_kimg_len: the blob is appended to the kernel image
 *     there, so blob offset 0 must be the preset page (setup_header at +0,
 *     setup_preset at +64).
 *   - `text_offset` = setup_offset + SZ_4K: tools/patch.c branches the ARM
 *     kernel entry (stext) to that flat offset, so `setup_entry` (the `.entry.text`
 *     of the setup object) must land at blob offset 0x1000.
 *   - the `.setup.map` region is copied verbatim at boot into the NOP hole that
 *     `select_map_area()` picked (`setup->map_offset`) and must be smaller than
 *     MAP_MAX_SIZE (0x1000).  `map_data` must stay immediately in front of
 *     `get_myva()` (.map.text): get_data() locates the data by subtracting
 *     sizeof(map_data_t) from the rounded-down address of that function.
 *   - a freestanding injected blob carries no dynamic linkage: zero GOT, PLT
 *     and dynamic relocations (the ASSERTs below are load-bearing).
 *
 * Region semantics copied from AArch64 kernel/kpimg.lds:
 *   _setup_start/_setup_end  preset page + setup entry code
 *   _map_start/_map_end      the relocatable map region (< 0x1000)
 *   _kp_start/_kp_text_start/_kp_text_end
 *                            KP image code+rodata (start, hooks, everything else)
 *   _kp_data_start/_kp_data_end
 *                            KP image data/bss
 *   _kp_symbol_start/_kp_symbol_end
 *                            KP_EXPORT_SYMBOL() records, at the very end of .kp.data
 *   _kp_end                  end of the KP image
 *
 * A32 vs AArch64 differences:
 *   - OUTPUT_ARCH(arm) / OUTPUT_FORMAT("elf32-littlearm") and ENTRY(setup_entry).
 *   - input objects are `*.arm.o` (full inventory) instead of `*.o`.
 *   - `.ARM.exidx*`/`.ARM.extab*` are discarded (ARM EABI unwind tables; the
 *     upstream AArch64 script has no equivalent).
 *   - dynamic relocations on ARM/ELF32 are SHT_REL and land in `.rel.dyn`;
 *     `.rela.dyn` is asserted as well so a stray RELA would also be caught.
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
     * Blob offset 0 == setup_offset. */
    .setup.data : {
        _setup_start = .;
        base/setup.arm.o(.setup.header)
        . = _setup_start + 64;
        base/setup.arm.o(.setup.preset)
        base/setup.arm.o(.setup.data)
        . = _setup_start + 4K;
    }

    /* setup_entry lands at blob offset 0x1000 == text_offset.
     * Only the setup-stage objects go here; everything else is in .kp.text
     * below (an upstream catch-all here would push .setup.map past 4K). */
    .setup.text : {
        base/setup_arm.arm.o(.entry.text)
        base/setup_arm.arm.o(.text)
        base/setup.arm.o(.text)
        _setup_end = .;
    }

    /* .map region: copied at boot into the kernel text hole (map_offset).
     * map_data first, then get_myva/get_data/_paging_init.  Keep < 0x1000
     * (MAP_MAX_SIZE). */
    . = ALIGN(16);
    .setup.map : {
        _map_start = .;
        base/map.arm.o(.map.data)
        base/map.arm.o(.map.text)
        base/map.arm.o(.text)
        . = ALIGN(16);
        _map_end = .;
    }
    ASSERT(SIZEOF(.setup.map) < 0x1000, "Size too large of .setup.map!")

    . = ALIGN(64K);
    _kp_start = .;
    .kp.text : {
        _kp_text_start = .;

        base/start.arm.o(.start.text)
        base/start.arm.o(.text)

        base/hook.arm.o(.transit0.text);
        _transit0_end = .;
        base/hook.arm.o(.transit4.text);
        _transit4_end = .;
        base/hook.arm.o(.transit8.text);
        _transit8_end = .;
        base/hook.arm.o(.transit12.text);
        _transit12_end = .;

        base/fphook.arm.o(.fp.transit0.text);
        _fp_transit0_end = .;
        base/fphook.arm.o(.fp.transit4.text);
        _fp_transit4_end = .;
        base/fphook.arm.o(.fp.transit8.text);
        _fp_transit8_end = .;
        base/fphook.arm.o(.fp.transit12.text);
        _fp_transit12_end = .;

        base/*(.text)
        base/*(.rodata*)

        *(.text)
        *(.rodata*)

        . = ALIGN(16);
        _kp_text_end = .;
    }

    . = ALIGN(64k);
    .kp.data : {
        _kp_data_start = .;
        base/start.arm.o(.start.data)
        base/*(.data)
        base/*(.bss)
        *(.data)
        *(.bss)
        *(COMMON)
        . = ALIGN(16);
        _kp_symbol_start = .;
        *(.kp.symbol)
        _kp_symbol_end = .;
        _kp_data_end = .;
    }

    .got.plt : { *(.got.plt) }
    ASSERT(SIZEOF(.got.plt) == 0, "Unexpected GOT/PLT entries detected!")

    . = ALIGN(64k);
    _kp_end = .;

    _link_end = .;

    .got : {
        *(.got)
    }
    ASSERT(SIZEOF(.got) == 0, "Unexpected GOT detected!")

    .plt : {
        *(.plt) *(.plt.*) *(.iplt) *(.igot .igot.plt)
    }
    ASSERT(SIZEOF(.plt) == 0, "Unexpected run-time procedure linkages detected!")

    .data.rel.ro : {
        *(.data.rel.ro)
    }
    ASSERT(SIZEOF(.data.rel.ro) == 0, "Unexpected RELRO detected!")

    .rel.dyn : {
        *(.rel .rel*)
    }
    ASSERT(SIZEOF(.rel.dyn) == 0, "Unexpected RELDYN detected!")

    .rela.dyn : {
        *(.rela .rela*)
    }
    ASSERT(SIZEOF(.rela.dyn) == 0, "Unexpected RELADYN detected!")
}
