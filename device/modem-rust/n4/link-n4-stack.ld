/*
 * Linker script for stack-integrated Rust N4 v2 (`--cfg feature="stack-hooks"`),
 * replacing assembly N4 inside the full IMG4 + N5 + N6H + M1 firmware stack.
 *
 * Preserves all six fixed-VA ABI labels inside 0x847ed000..0x847ed540 that
 * IMG3 HRB, IMG4 n4v3_spare, N5, and M1 branch to directly:
 *   0x847ed0ee  n4_abi_calc_lcg_bo  (IMG3 HRB tail target)
 *   0x847ed414  n4_abi_check_aqm    (N5 -> M1 m1_aqm_shim -> Rust N4 AQM v2)
 *   0x847ed458  n4_abi_n4v3_word    (IMG4 T1 direct bl n4v3_spare check)
 *   0x847ed51c  n4_abi_exit_d       (M1 Exit D drop target)
 *   0x847ed52e  n4_abi_exit_b       (IMG4 / N5 / M1 Exit B enqueue target)
 *   0x847ed53c  n4_abi_exit_a       (N5 Exit A stock Ring 0 target)
 *
 * Overflow Rust functions live in proven-dead RFFE_PAM_SKY77643_31_NEC
 * (0x84194654..0x84194a5c, 1,032 B, 0 real refs, disjoint from N6H/C1/N7/U14/IMG4/M1).
 */

/* m1_aqm_shim_va (0x841de8dc) and img4_n4v3_spare_va (0x8448a6de) are defined
 * as Thumb function symbols via .thumb_set in modem.rs so GNU ld emits pure Thumb BL. */

MEMORY
{
    N4_PRACH (rx) : ORIGIN = 0x847ed000, LENGTH = 1344
    N4_CAVE2 (rx) : ORIGIN = 0x84194654, LENGTH = 1032
}

ENTRY(hook_mac_tb)

SECTIONS
{
    /* Fill gaps between fixed-VA ABI labels with Thumb NOP (bytes 00 bf -> big-endian fill 0x00bf). */
    .n4prach 0x847ed000 : SUBALIGN(2)
    {
        KEEP(*(.text.n4_pdcp_limit_rust))
        KEEP(*(.text.n4_short_bsr_rust))
        KEEP(*(.text.*ensure_init*))
        ASSERT(. <= 0x0ee, "N4 pre-0x847ed0ee region overflowed");
        . = 0x0ee;
        KEEP(*(.text.n4_abi_0ee))
        ASSERT(. == 0x0f2, "n4_abi_0ee must be 4 bytes");

        KEEP(*(.text.n4_shims))
        KEEP(*(.text.n4_calc_lcg_bo_rust))
        KEEP(*(.text.n4_ingress_rust))
        ASSERT(. <= 0x414, "N4 0x847ed0f2..0x847ed414 region overflowed");
        . = 0x414;
        KEEP(*(.text.n4_abi_414))
        ASSERT(. <= 0x458, "n4_abi_414 overflowed into 0x847ed458");
        . = 0x458;
        KEEP(*(.text.n4_abi_458))
        ASSERT(. == 0x45c, "n4_abi_458 must be 4 bytes");

        KEEP(*(.text.n4_mac_tb_rust))
        ASSERT(. <= 0x51c, "N4 0x847ed45c..0x847ed51c region overflowed");
        . = 0x51c;
        KEEP(*(.text.n4_abi_51c))
        ASSERT(. == 0x52e, "n4_abi_51c must end at 0x847ed52e");
        KEEP(*(.text.n4_abi_52e))
        ASSERT(. == 0x53c, "n4_abi_52e must end at 0x847ed53c");
        KEEP(*(.text.n4_abi_53c))
        ASSERT(. <= 0x540, "n4_abi_53c overflowed 0x847ed540");
        . = 0x540;
    } > N4_PRACH =0x00bf

    .n4cave2 0x84194654 : ALIGN(2)
    {
        *(.text.n4_aqm_rust)
        *(.text.n4_sparse_rust)
        *(.text .text.*)
    } > N4_CAVE2

    .rodata : { *(.rodata .rodata.*) } > N4_CAVE2
    .data   : { *(.data .data.*) } > N4_CAVE2
    .bss    : { *(.bss .bss.*) *(COMMON) } > N4_CAVE2

    /DISCARD/ :
    {
        *(.ARM.exidx* .ARM.extab* .ARM.attributes)
        *(.comment .note* .eh_frame* .debug*)
    }
}

ASSERT(SIZEOF(.n4prach) == 1344, ".n4prach must be exactly 1344 bytes (0x847ed000..0x847ed540)")
ASSERT(SIZEOF(.rodata) == 0, "unexpected .rodata in N4 code cave")
ASSERT(SIZEOF(.data) == 0, "unexpected .data in N4 code cave")
ASSERT(SIZEOF(.bss) == 0, "unexpected .bss (modem patch has no CRT zero-init)")
