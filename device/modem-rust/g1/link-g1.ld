/*
 * Linker script for the G1 MAC UL timeline tracer (`witcher-modem-g1`).
 *
 * Dead caves (all three proven 0 external Thumb/ARM/data refs, disjoint from every other lane):
 *   - G1_CODE : 0x8411927c..0x84119840 (1,476 B, dead `ihs_keypad_down..is_secure_disable`)
 *   - G1_COLD : 0x8450ce94..0x8450d1e0 (  844 B, dead `lte_agent_bip_control_ind..lte_agent_service_handler`)
 *   - G1_BLK  : 0x8412a340..0x8412a3c0 (  128 B, 64-B aligned inside dead `ossDupWorld` 0x8412a308..0x8412a538)
 *
 * Ring buffer (NOT in tk.bin; Normal Non-Cacheable SDRAM at runtime):
 *   - G1_RING : 0x87f70000..0x87f90000 (128 KiB, 4,096 x 32 B records inside dead `srch_run_pss_*`)
 */

MEMORY
{
    G1_CODE (rx) : ORIGIN = 0x8411927c, LENGTH = 1476
    G1_COLD (rx) : ORIGIN = 0x8450ce94, LENGTH = 844
    G1_BLK  (rw) : ORIGIN = 0x8412a340, LENGTH = 128
}

ENTRY(g1_hook_pre_ce)

SECTIONS
{
    .g1cold 0x8450ce94 : ALIGN(2)
    {
        KEEP(*(.text.g1_on_retx_rust))
        KEEP(*(.text.g1_on_sr_rust))
        KEEP(*(.text.g1_on_tti_end_rust))
        *(.text.*on_tti_end*)
    } > G1_COLD

    .g1code 0x8411927c : ALIGN(2)
    {
        KEEP(*(.text.g1_shims))
        KEEP(*(.text.g1_on_newtx_rust))
        *(.text .text.*)
    } > G1_CODE

    .g1blk 0x8412a340 : ALIGN(4)
    {
        KEEP(*(.g1blk))
    } > G1_BLK

    .rodata : { *(.rodata .rodata.*) } > G1_CODE
    .data   : { *(.data .data.*) } > G1_CODE
    .bss    : { *(.bss .bss.*) *(COMMON) } > G1_CODE

    /DISCARD/ :
    {
        *(.ARM.exidx* .ARM.extab* .ARM.attributes)
        *(.comment .note* .eh_frame* .debug*)
    }
}

ASSERT(SIZEOF(.g1blk) == 128, ".g1blk must be exactly 128 bytes")
ASSERT(SIZEOF(.rodata) == 0, "unexpected .rodata in .g1code cave")
ASSERT(SIZEOF(.data) == 0, "unexpected .data in .g1code cave")
ASSERT(SIZEOF(.bss) == 0, "unexpected .bss (modem patch has no CRT zero-init)")
