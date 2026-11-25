/*
 * Linker script for Lane N3 MAC UL hot-path optimizer (`witcher-modem-mac-opt`).
 *
 * Uses two dead-function caves audited with full-image cavecheck + rdcheck against
 * stock tk.bin and verified 0-overlap against N6H, C1, N7, U14, IMG4, M1, and R4/N4:
 *
 *   N3_CODE: grf_cancellation_rpll_mutual_interference_sd_init
 *            0x8418_67e4 .. 0x8418_6b38 (852 B, executable Thumb-2 code)
 *   N3_BLK:  ATM_decodePCO (128-byte aligned sub-range)
 *            0x8449_a2a0 .. 0x8449_a320 (128 B, boot-off control block)
 *
 * Code and mutable control block live on completely separate regions/cache lines.
 */

/* Resume addresses are defined as Thumb function symbols via .thumb_set in modem.rs
 * so GNU ld emits pure Thumb-2 b.w with zero ARM veneers. */

MEMORY
{
    N3_CODE (rx) : ORIGIN = 0x841867e4, LENGTH = 852
    N3_BLK  (rw) : ORIGIN = 0x8449a2a0, LENGTH = 128
}

ENTRY(n3_search_bo_idx_shim)

SECTIONS
{
    .n3code : ALIGN(2)
    {
        KEEP(*(.text.n3_search_bo_idx_shim))
        KEEP(*(.text.n3_check_long_bsr_shim))
        KEEP(*(.text.n3_mac_bsr_pre_work_shim))
        *(.text .text.*)
    } > N3_CODE

    .n3blk : ALIGN(4)
    {
        KEEP(*(.n3blk))
    } > N3_BLK

    .rodata : { *(.rodata .rodata.*) } > N3_CODE
    .data   : { *(.data .data.*) } > N3_BLK
    .bss    : { *(.bss .bss.*) *(COMMON) } > N3_BLK

    /DISCARD/ :
    {
        *(.ARM.exidx* .ARM.extab* .ARM.attributes)
        *(.comment .note* .eh_frame* .debug*)
    }
}

ASSERT((n3_search_bo_idx_shim & ~1) == 0x841867e4, "n3_search_bo_idx_shim must start at 0x841867e4")
ASSERT(ADDR(.n3blk) == 0x8449a2a0, ".n3blk must start at 0x8449a2a0")
ASSERT(SIZEOF(.n3blk) == 128, ".n3blk must be exactly 128 bytes")
ASSERT(SIZEOF(.rodata) == 0, "unexpected .rodata in N3 code cave")
ASSERT(SIZEOF(.data) == 0, "unexpected .data outside .n3blk")
ASSERT(SIZEOF(.bss) == 0, "unexpected .bss (modem patch has no CRT zero-init)")
