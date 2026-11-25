/*
 * Linker script for standalone Rust N4 v2 (`witcher-modem-n4`, no downstream stack hooks).
 *
 * Regions (both read-only executable Thumb-2, zero literal pools, zero mutable data):
 *   N4_PRACH: 0x847ed000..0x847ed540 (1,344 B, N4's original PRACH format-4 tail slot)
 *   N4_CAVE2: 0x84194654..0x84194a5c (1,032 B, dead RFFE_PAM_SKY77643_31_NEC, verified
 *             with cavecheck + rdcheck: 0 real refs, 1032/1032 B Thumb-2 decode,
 *             disjoint from N6H, C1, N7, U14, IMG4, and M1).
 *
 * State remains at the exact N4 addresses in PRACH-tail RAM (zero in stock tk.bin):
 *   N4State       0x847ed600..0x847ed67f
 *   ST_SPARSE_TBL 0x847ed680..0x847ed77f
 *   N4ExtCounters 0x847ed780..0x847ed79b
 */

MEMORY
{
    N4_PRACH (rx) : ORIGIN = 0x847ed000, LENGTH = 1344
    N4_CAVE2 (rx) : ORIGIN = 0x84194654, LENGTH = 1032
}

ENTRY(hook_mac_tb)

SECTIONS
{
    .n4prach : ALIGN(2)
    {
        KEEP(*(.text.n4_shims))
        *(.text.n4_mac_tb_rust)
        *(.text.n4_calc_lcg_bo_rust)
        *(.text.n4_short_bsr_rust)
        *(.text.n4_pdcp_limit_rust)
        *(.text.*ensure_init*)
    } > N4_PRACH

    .n4cave2 : ALIGN(2)
    {
        *(.text.n4_gipc_rx_rust)
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

ASSERT(SIZEOF(.rodata) == 0, "unexpected .rodata in N4 code cave (breaks Thumb-2 Capstone decode)")
ASSERT(SIZEOF(.data) == 0, "unexpected .data in N4 code cave")
ASSERT(SIZEOF(.bss) == 0, "unexpected .bss (modem patch has no CRT zero-init)")
