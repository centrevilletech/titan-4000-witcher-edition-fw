/*
 * Linker script for the uplink AQM in tk.bin: two dead-function caves from lane M2's
 * catalog, checked dead with cavecheck.py + rdcheck.py against stock tk.bin, and
 * disjoint from N6H, C1, N7, U14, IMG4's PRACH tail and R4's Rust N4 cave
 * (RFFE_PAM_SKY77643_31_NEC, 0x84194654..0x84194a5c):
 *
 *   M1_CODE: cmd_phy       0x841de8dc..0x841df200 (2,340 B, code)
 *   M1_BLK:  UMM_DecodeATR 0x841b5900..0x841b5a00 (  256 B, control block)
 *
 * Code and the mutable block never share a cache line.
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
        *(.text .text.*)
    } > M1_CODE

    .m1blk : ALIGN(4)
    {
        KEEP(*(.m1blk))
    } > M1_BLK

    /* Any of these would be data in the code cave or need a C runtime. */
    .rodata : { *(.rodata .rodata.*) } > M1_CODE
    .data   : { *(.data .data.*) } > M1_BLK
    .bss    : { *(.bss .bss.*) *(COMMON) } > M1_BLK

    /DISCARD/ :
    {
        *(.ARM.exidx* .ARM.extab* .ARM.attributes)
        *(.comment .note* .eh_frame* .debug*)
    }
}

/* N4's hook (asm N6H and R4's Rust N4) calls this address. */
ASSERT(m1_aqm_shim == 0x841de8dc, "m1_aqm_shim must stay at 0x841de8dc")
ASSERT(ADDR(.m1blk) == 0x841b5900, ".m1blk must start at 0x841b5900")
ASSERT(SIZEOF(.m1blk) == 256, ".m1blk must be exactly 256 bytes")
ASSERT(SIZEOF(.rodata) == 0, "unexpected .rodata in the code cave")
ASSERT(SIZEOF(.data) == 0, "unexpected .data outside .m1blk")
ASSERT(SIZEOF(.bss) == 0, "unexpected .bss (the patch has no zero-init)")
