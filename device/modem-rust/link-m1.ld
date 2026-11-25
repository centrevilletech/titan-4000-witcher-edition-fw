/*
 * Linker script for the uplink AQM in tk.bin: three dead-function caves (lane M2's and
 * IMG4's catalogs), checked dead with cavecheck.py + rdcheck.py against stock tk.bin,
 * and disjoint from N6H, C1, N7, U14, IMG4's PRACH tail, R4's Rust N4 cave
 * (RFFE_PAM_SKY77643_31_NEC, 0x84194654..0x84194a5c) and lanes N2's and N3's caves:
 *
 *   M1_CODE:   cmd_phy            0x841de8dc..0x841df200 (2,340 B, code: shim first)
 *   COLD_CODE: CloseUeTestLoopCnf 0x8446e4c8..0x8446e718 (  592 B, code: PIE's control law)
 *   M1_BLK:    UMM_DecodeATR      0x841b5900..0x841b5a00 (  256 B, control block)
 *
 * The per-packet path (shim, glue, both controllers' decisions, CoDel, the flow hash,
 * ECN) and selector 3's update stay in cmd_phy, first the shim. The PIE control law
 * (selector 1's update and the PI step both selectors' updates share), which runs once
 * per t_update_ms, and CoDel's drop spacing, which runs once per CoDel drop, go to the
 * second cave. CloseUeTestLoopCnf answers the 3GPP test loop (conformance test mode);
 * nothing in the image refers to it but its own symbol-table entry.
 *
 * Code and the mutable block never share a cache line.
 */

MEMORY
{
    M1_CODE   (rx) : ORIGIN = 0x841de8dc, LENGTH = 2340
    COLD_CODE (rx) : ORIGIN = 0x8446e4c8, LENGTH = 592
    M1_BLK    (rw) : ORIGIN = 0x841b5900, LENGTH = 256
}

ENTRY(m1_aqm_shim)

SECTIONS
{
    /* The periodic code, by v0-mangled path. Listed first: the first matching rule
     * places a section, and .m1code takes everything else. A function the compiler
     * inlines or renames lands in .m1code, which the region size then guards. */
    .m1cold : ALIGN(4)
    {
        *(.text.*17witcher_modem_aqm3pie*6update)
        *(.text.*17witcher_modem_aqm3pie*7pi_step)
        *(.text.*17witcher_modem_aqm5codel7spacing)
        *(.text.*17witcher_modem_aqm5codel5isqrt)
    } > COLD_CODE

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
ASSERT(SIZEOF(.m1cold) == 0 || ADDR(.m1cold) == 0x8446e4c8, ".m1cold must start at 0x8446e4c8")
ASSERT(ADDR(.m1blk) == 0x841b5900, ".m1blk must start at 0x841b5900")
ASSERT(SIZEOF(.m1blk) == 256, ".m1blk must be exactly 256 bytes")
ASSERT(SIZEOF(.rodata) == 0, "unexpected .rodata in the code cave")
ASSERT(SIZEOF(.data) == 0, "unexpected .data outside .m1blk")
ASSERT(SIZEOF(.bss) == 0, "unexpected .bss (the patch has no zero-init)")
