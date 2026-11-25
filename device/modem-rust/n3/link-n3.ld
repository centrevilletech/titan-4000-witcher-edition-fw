/*
 * Linker script for the combined MAC/PDCP UL hot-path optimizer (`witcher-modem-mac-opt`).
 *
 * Uses three proven-dead caves audited with full-image cavecheck + rdcheck against
 * stock tk.bin and verified 0-overlap against v1.0.16, IMG4, R4/N4, N1/N5, R1, N6H,
 * C1, N7, U14, UL-B, and M1:
 *
 *   OPT_CODE1: grf_cancellation_rpll_mutual_interference_sd_init
 *              0x8418_67e4 .. 0x8418_6b38 (852 B, executable Thumb-2 MAC hooks)
 *   OPT_CODE2: restore_valid_check
 *              0x8417_ffd8 .. 0x8418_024c (628 B, executable Thumb-2 PDCP hooks)
 *   OPT_BLK:   UMM_DisplayUSIMPINInfo + 2 (4-byte aligned sub-range)
 *              0x841b_b5c0 .. 0x841b_b640 (128 B, boot-off MacPdcpOptBlock)
 *
 * Code caves and mutable control block live on completely separate regions/cache lines.
 */

MEMORY
{
    OPT_CODE1 (rx) : ORIGIN = 0x841867e4, LENGTH = 852
    OPT_CODE2 (rx) : ORIGIN = 0x8417ffd8, LENGTH = 628
    OPT_BLK   (rw) : ORIGIN = 0x841bb5c0, LENGTH = 128
}

ENTRY(opt_search_bo_idx_shim)

SECTIONS
{
    .optcode1 : ALIGN(2)
    {
        KEEP(*(.optcode1.entry.search_bo_idx))
        KEEP(*(.optcode1.entry.check_long_bsr))
        KEEP(*(.optcode1.entry.mac_bsr_pre_work))
        *(.optcode1 .optcode1.*)
        *(.text .text.*)
    } > OPT_CODE1

    .optcode2 : ALIGN(2)
    {
        KEEP(*(.optcode2.entry.pdcp_div))
        KEEP(*(.optcode2.entry.do_tc_cap))
        *(.optcode2 .optcode2.*)
    } > OPT_CODE2

    .optblk : ALIGN(4)
    {
        KEEP(*(.optblk))
    } > OPT_BLK

    .rodata : { *(.rodata .rodata.*) } > OPT_CODE1
    .data   : { *(.data .data.*) } > OPT_BLK
    .bss    : { *(.bss .bss.*) *(COMMON) } > OPT_BLK

    /DISCARD/ :
    {
        *(.ARM.exidx* .ARM.extab* .ARM.attributes)
        *(.comment .note* .eh_frame* .debug*)
    }
}

ASSERT((opt_search_bo_idx_shim & ~1) == 0x841867e4, "opt_search_bo_idx_shim must start at 0x841867e4")
ASSERT((opt_pdcp_div_shim & ~1) == 0x8417ffd8, "opt_pdcp_div_shim must start at 0x8417ffd8")
ASSERT(ADDR(.optblk) == 0x841bb5c0, ".optblk must start at 0x841bb5c0")
ASSERT(SIZEOF(.optblk) == 128, ".optblk must be exactly 128 bytes")
ASSERT(SIZEOF(.rodata) == 0, "unexpected .rodata in optimizer code caves")
ASSERT(SIZEOF(.data) == 0, "unexpected .data outside .optblk")
ASSERT(SIZEOF(.bss) == 0, "unexpected .bss (modem patch has no CRT zero-init)")
