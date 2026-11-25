# G1 MAC UL Timeline Tracer (`device/modem-rust/g1`)

Boot-off, observation-only `#![no_std]` Thumb-2 Rust tracer for the Titan 4000 modem (`tk.bin`,
CPU1). Built on top of the v1.0.16 image (`n6h-r4-r1`) as manifest `n6h-r4-r1-g1`.

## Memory map

| Region | Address range | Size | Backing |
| --- | --- | --- | --- |
| `.g1code` | `0x8411_927c..0x8411_9840` | 1,476 B | Dead `ihs_keypad_down..is_secure_disable` (0 refs; 1,232 B used) |
| `.g1cold` | `0x8450_ce94..0x8450_d1e0` | 844 B | Dead `lte_agent_bip_control_ind..lte_agent_service_handler` (0 refs; 622 B used) |
| `.g1blk` | `0x8412_a340..0x8412_a3c0` | 128 B | Dead `ossDupWorld` (`0x8412_a308..0x8412_a538`, 0 refs) |
| `G1_RING` | `0x87f7_0000..0x87f9_0000` | 128 KiB | Dead `srch_run_pss_*` non-cacheable SDRAM (`0x87f6_ed40..0x87f9_4540`, `cmd_phy`-only) |

## Control words (`G1_BLK` at `0x8412_a340`, live via `wm`)

| Offset | Address | Word | Boot | Meaning |
| --- | --- | --- | --- | --- |
| `+0x00` | `0x8412a340` | `magic` | `0x47315452` | `"G1TR"` |
| `+0x04` | `0x8412a344` | `version` | `0x20261125` | ABI version |
| `+0x08` | `0x8412a348` | `enable` | `0` | `1` = record; `0` or any other value = off |
| `+0x0c` | `0x8412a34c` | `freeze` | `0` | `0` = running; non-zero = frozen for `vm` dump |
| `+0x1c` | `0x8412a35c` | `wr_idx` | `0` | Total records written (`slot = wr_idx & 0xfff`) |
| `+0x20` | `0x8412a360` | `af_mode` | `0` | Auto-freeze mask: `1`=SCell drop, `2`=PCell drop, `4`=both-stall, `8`=allow-unseen |
| `+0x24` | `0x8412a364` | `af_tti_thresh` | `10` | Missing-CC grant-TTI streak (10 = 50 ms at TDD Config 2) |
| `+0x28` | `0x8412a368` | `af_bo_thresh` | `16000` | Minimum `ring1 + rlc_bo` bytes to arm drop detector |
| `+0x2c` | `0x8412a36c` | `af_post_events` | `128` | Extra events captured after trigger before freezing |

## Commands

```bash
# Thumb-2 build, clippy for armv7 Thumb-2, and static audit
device/modem-rust/g1/build-thumb.sh /tmp/g1-out

# Decode a dm.sh vm dump into timeline + analytics
python3 scripts/decode-mac-trace.py capture.dm
```
