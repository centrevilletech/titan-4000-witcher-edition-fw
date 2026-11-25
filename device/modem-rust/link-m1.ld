/*
 * Linker script for Lane M1 (Rust uplink PIE AQM on Titan 4000 tk.bin).
 *
 * Uses two dead-function caves from Lane M2's catalog, independently verified
 * with cavecheck.py + rdcheck.py against stock tk.bin and checked disjoint
 * from all 71 N6H + C1 sites, N7, U14, and IMG4 PRACH-tail RAM:
 *
 *   M1_CODE: cmd_phy       0x841de8dc..0x841df200 (2,340 B, read-only Thumb-2)
 *   M1_BLK:  UMM_DecodeATR 0x841b5900..0x841b5a00 (  256 B, 4 x 64 B cache lines)
 *
 * Separating read-only executable code from mutable RAM prevents I-cache /
 * D-cache line aliasing on CPU1 (Cortex-A7).
 */

MEMORY
{
    M1_CODE (rx) : ORIGIN = 0x841de8dc, LENGTH = 2340
    M1_BLK  (rw) : ORIGIN = 0x841b5900, LENGTH = 256
}

ENTRY(m1_aqm_shim)

SECTIONS
{
    .m1code : ALIGN(2)
    {
        KEEP(*(.text.m1_aqm_shim))
        *(.text.m1_pie_decide)
        *(.text .text.*)
    } > M1_CODE

    .m1blk : ALIGN(4)
    {
        KEEP(*(.m1blk))
    } > M1_BLK

    /* Reject any stray writable globals, BSS, or constant pools at link time. */
    .rodata : { *(.rodata .rodata.*) } > M1_CODE
    .data   : { *(.data .data.*) } > M1_BLK
    .bss    : { *(.bss .bss.*) *(COMMON) } > M1_BLK

    /DISCARD/ :
    {
        *(.ARM.exidx* .ARM.extab* .ARM.attributes)
        *(.comment .note* .eh_frame* .debug*)
    }
}

ASSERT(SIZEOF(.rodata) == 0, "unexpected .rodata in M1 code cave (breaks Thumb-2 Capstone decode)")
ASSERT(SIZEOF(.data) == 0, "unexpected .data outside .m1blk")
ASSERT(SIZEOF(.bss) == 0, "unexpected .bss (modem patch has no CRT zero-init)")
ASSERT(SIZEOF(.m1blk) == 256, "M1_BLK must be exactly 256 bytes (4 x 64 B cache lines)")
