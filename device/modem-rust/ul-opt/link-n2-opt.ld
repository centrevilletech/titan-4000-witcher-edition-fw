/* Linker script for witcher-modem-ul-opt (Lane N2 PDCP/RLC/BSR hot-path optimizations).
 *
 * Caves (both proven dead via full-image cavecheck + rdcheck, 0 real refs,
 * disjoint from IMG4, N4/R4, N5/N1, N6H, C1, N7, U14, M1, and all keeper words):
 *   .n2opt : 0x841867e4..0x84186b38 (852 B, dead grf_cancellation_rpll_mutual_interference_sd_init)
 *   .n2blk : 0x841bb5be..0x841bb87c (702 B, dead UMM_DisplayUSIMPINInfo; 2 B pad + 64 B N2OptState @ 0x841bb5c0)
 */
OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)

MEMORY
{
    N2OPT (rx) : ORIGIN = 0x841867e4, LENGTH = 852
    N2BLK (rw) : ORIGIN = 0x841bb5c0, LENGTH = 700
}

SECTIONS
{
    .n2opt : {
        KEEP(*(.n2opt.entry))
        *(.n2opt*)
        *(.text .text.*)
        *(.rodata .rodata.*)
    } > N2OPT

    .n2blk : {
        KEEP(*(.n2blk*))
    } > N2BLK

    /DISCARD/ : {
        *(.ARM.exidx*)
        *(.ARM.extab*)
        *(.ARM.attributes*)
        *(.comment*)
        *(.debug*)
        *(.note*)
    }
}
