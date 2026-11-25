/*
 * Linker script for the no_std Rust Thumb-2 port of N5 (`witcher-modem-n5`).
 *
 * Fits entirely inside N5's already proven-dead `ChangeCalmodFunc` cave
 * (`0x8418_f768..0x8418_ff4c`, 2,020 B) while leaving N6H's `n6_u2_lnack_filter_code`
 * (`0x8418_fd78..0x8418_fe10`), N7's extended `n6_u2_lnack_filter_code`
 * (`0x8418_fd78..0x8418_fe8a`), and N6H's `n6_u2_control_block`
 * (`0x8418_ff00..0x8418_ff42`, 66 B) completely untouched:
 *
 *   .n5cave_g      0x8418_f768..0x8418_fd78  (1,552 B, exact assembly N5 primary slot)
 *     - 0x8418_f768  n5_flow_classify  (fixed VA called by R4 hook_gipc_rx / N4 Hook A)
 *     - 0x8418_fc9c  n5_pdcp_limit     (fixed VA tail-called by R4 hook_pdcp_limit / N4 Hook B)
 *     - 0x8418_fd0a  n5_ring0_submit   (fixed VA called by Hook C at 0x842d_cd24)
 *   .n5cave_g_tail 0x8418_fe90..0x8418_ff00  (up to 112 B, post-N7 tail of ChangeCalmodFunc)
 *   .n5blk         0x8448_9a62..0x8448_9f14  (1,202 B, dead FSM_ATM_CMD_LAPI_REGISTRATION_ATTACH_IND)
 */

MEMORY
{
    CAVE_G      (rx) : ORIGIN = 0x8418f768, LENGTH = 1552
    CAVE_G_TAIL (rx) : ORIGIN = 0x8418fe90, LENGTH = 112
    N5_BLK      (rw) : ORIGIN = 0x84489a62, LENGTH = 1202
}

ENTRY(n5_flow_classify)

SECTIONS
{
    /* Fill alignment gaps between fixed-VA entry points with Thumb NOP (bytes 00 bf -> 0x00bf). */
    .n5cave_g 0x8418f768 : SUBALIGN(2)
    {
        KEEP(*(.text.n5_flow_classify))
        KEEP(*(.text.n5_flow_classify_rust))
        *(.text.*parse_ipv4*)
        *(.text.*parse_ipv6*)
        *(.text.*parse_l4*)
        *(.text.*get_be16*)
        ASSERT(. <= 0x534, "N5 pre-0x8418fc9c region overflowed");
        . = 0x534;
        KEEP(*(.text.n5_pdcp_limit))
        KEEP(*(.text.n5_ring0_sum_rust))
        ASSERT(. <= 0x5a2, "n5_pdcp_limit + n5_ring0_sum_rust overflowed into 0x8418fd0a");
        . = 0x5a2;
        KEEP(*(.text.n5_ring0_submit))
        KEEP(*(.text.n5_ring0_record_rust))
        ASSERT(. <= 0x610, "n5_ring0_submit + n5_ring0_record_rust overflowed 0x8418fd78");
        . = 0x610;
    } > CAVE_G =0x00bf

    .n5cave_g_tail 0x8418fe90 : SUBALIGN(2)
    {
        KEEP(*(.text.n5_pdcp_limit_rust))
        *(.text .text.*)
    } > CAVE_G_TAIL

    .n5blk 0x84489a62 : SUBALIGN(2)
    {
        SHORT(0x0000);
        KEEP(*(.n5blk))
    } > N5_BLK

    .rodata : { *(.rodata .rodata.*) } > CAVE_G_TAIL
    .data   : { *(.data .data.*) } > CAVE_G_TAIL
    .bss    : { *(.bss .bss.*) *(COMMON) } > CAVE_G_TAIL

    /DISCARD/ :
    {
        *(.ARM.exidx* .ARM.extab* .ARM.attributes)
        *(.comment .note* .eh_frame* .debug*)
    }
}

ASSERT(SIZEOF(.n5cave_g) == 1552, ".n5cave_g must be exactly 1552 bytes (0x8418f768..0x8418fd78)")
ASSERT(SIZEOF(.n5blk) == 1202, ".n5blk must be exactly 1202 bytes (0x84489a62..0x84489f14)")
ASSERT(SIZEOF(.rodata) == 0, "unexpected .rodata in N5 code cave")
ASSERT(SIZEOF(.data) == 0, "unexpected .data in N5 code cave")
ASSERT(SIZEOF(.bss) == 0, "unexpected .bss (modem patch has no CRT zero-init)")
