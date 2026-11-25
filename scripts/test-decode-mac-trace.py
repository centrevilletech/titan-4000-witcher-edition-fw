#!/usr/bin/env python3
"""Unit tests for scripts/decode-mac-trace.py (DM `vm` parser, 3GPP BSR/PHR decode, analytics)."""
import importlib.util
import io
import os
import struct
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("decode_mac_trace", REPO / "scripts" / "decode-mac-trace.py")
dec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dec)


def format_dm_vm(base_va, data):
    """Format raw bytes in the exact big-endian-word hex dump layout produced by Titan DM `vm`."""
    lines = [
        "LOG-MODE: INTERACTIVE(0)",
        "DM> ",
        "-" * 76,
        f" HEX DUMP  | {len(data)}({len(data):#x}) Bytes @ {base_va:#010X}",
        "-" * 76,
        "           | 03 02 01 00  07 06 05 04  0B 0A 09 08  0F 0E 0D 0C",
        "-" * 76,
    ]
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        groups = []
        for w in range(0, 16, 4):
            if w + 4 <= len(chunk):
                b0, b1, b2, b3 = chunk[w : w + 4]
                groups.append(f"{b3:02x} {b2:02x} {b1:02x} {b0:02x}")
            else:
                groups.append(".. .. .. ..")
        lines.append(f"0x{base_va + off:08X} | " + "  ".join(groups) + " ")
    lines.append("-" * 76)
    lines.append("DM> dcm_send_ul_ack_nack_result_with_cc_id.E.diff cc_id(0,0) tx_sti(9602,9607)")
    return "\n".join(lines) + "\n"


def pack_rec(
    tti_ms, air_sti, kind, cc, hq_id, ext_bsr, ce_mask, has_pad, bsr_fmt,
    tbs, used_or_retx, bsr_trig, bsr_ce, phr0_pv, phr0_pc, phr1_pv, phr1_pc,
    ring1, rlc_bo, seq,
):
    flags0 = (kind & 7) | ((cc & 1) << 3) | ((hq_id & 7) << 4) | (0x80 if ext_bsr else 0)
    flags1 = (ce_mask & 0x1F) | (0x20 if has_pad else 0) | ((bsr_fmt & 3) << 6)
    return struct.pack(
        "<IHBBHHBBBBBBBBIII",
        tti_ms, air_sti, flags0, flags1, tbs, used_or_retx,
        bsr_trig, bsr_ce[0], bsr_ce[1], bsr_ce[2],
        phr0_pv, phr0_pc, phr1_pv, phr1_pc, ring1, rlc_bo, seq,
    )


def pack_blk(wr_idx, freeze=1, af_reason=1, af_seq=12, af_tti=5060, af_sti=5062):
    words = [0] * 32
    words[0] = dec.MAGIC
    words[1] = 0x20261125
    words[2] = 1
    words[3] = freeze
    words[4] = dec.RING_VA_DEFAULT
    words[5] = dec.RING_SLOTS_DEFAULT
    words[6] = dec.REC_SIZE
    words[7] = wr_idx
    words[8] = 3
    words[9] = 5
    words[10] = 16000
    words[11] = 8
    words[13] = af_reason
    words[14] = af_seq
    words[15] = af_tti
    words[29] = af_sti
    return struct.pack("<32I", *words)


def test_roundtrip_and_analytics():
    recs_raw = bytearray()
    seq = 0

    def add(**kw):
        nonlocal seq
        recs_raw.extend(pack_rec(seq=seq, **kw))
        seq += 1

    # Idle -> BSR jump at t=5000 ms (Short BSR LCG 3 idx 54 = 42,502 B),
    # grants respond 2 UL TTIs (10 ms) later on both PCell and SCell!
    add(
        tti_ms=5000, air_sti=5002, kind=1, cc=0, hq_id=0, ext_bsr=False,
        ce_mask=0x0A, has_pad=False, bsr_fmt=1, tbs=200, used_or_retx=200,
        bsr_trig=0x12, bsr_ce=(0xC0 | 54, 0, 0),
        phr0_pv=0x80 | 38, phr0_pc=52, phr1_pv=0x80 | 35, phr1_pc=52,
        ring1=20000, rlc_bo=2500,
    )
    add(
        tti_ms=5005, air_sti=5007, kind=1, cc=0, hq_id=1, ext_bsr=False,
        ce_mask=0x02, has_pad=False, bsr_fmt=1, tbs=200, used_or_retx=200,
        bsr_trig=0x01, bsr_ce=(0xC0 | 54, 0, 0),
        phr0_pv=0, phr0_pc=0xFF, phr1_pv=0, phr1_pc=0xFF,
        ring1=20000, rlc_bo=2500,
    )
    # 2CC active for 4 UL TTIs (5010..5025 ms): SCell has 1000 B pad on each TB.
    for i in range(4):
        t = 5010 + i * 5
        sti = 5012 + i * 5
        add(
            tti_ms=t, air_sti=sti, kind=1, cc=0, hq_id=i & 1, ext_bsr=False,
            ce_mask=0x00, has_pad=False, bsr_fmt=0, tbs=6792, used_or_retx=6792,
            bsr_trig=0, bsr_ce=(0, 0, 0),
            phr0_pv=0, phr0_pc=0xFF, phr1_pv=0, phr1_pc=0xFF,
            ring1=22000, rlc_bo=3000,
        )
        add(
            tti_ms=t, air_sti=sti, kind=1, cc=1, hq_id=i & 1, ext_bsr=False,
            ce_mask=0x02, has_pad=True, bsr_fmt=1, tbs=6792, used_or_retx=5792,
            bsr_trig=0x01, bsr_ce=(0xC0 | 54, 0, 0),
            phr0_pv=0, phr0_pc=0xFF, phr1_pv=0, phr1_pc=0xFF,
            ring1=22000, rlc_bo=2000,
        )
    # Carrier flip to PCell-only for 4 UL TTIs (5030..5045 ms) with ExtPHR showing low SCell PH!
    for i in range(4):
        t = 5030 + i * 5
        sti = 5032 + i * 5
        ce = 0x0A if i == 0 else 0x02
        add(
            tti_ms=t, air_sti=sti, kind=1, cc=0, hq_id=i & 1, ext_bsr=False,
            ce_mask=ce, has_pad=False, bsr_fmt=1, tbs=6792, used_or_retx=6792,
            bsr_trig=0x01, bsr_ce=(0xC0 | 54, 0, 0),
            phr0_pv=(0x80 | 30) if i == 0 else 0, phr0_pc=52 if i == 0 else 0xFF,
            phr1_pv=(0x80 | 0x40 | 18) if i == 0 else 0, phr1_pc=0xFF,
            ring1=25000, rlc_bo=4000,
        )
    # One Retx + one PUCCH SR.
    add(
        tti_ms=5050, air_sti=5052, kind=3, cc=0, hq_id=0, ext_bsr=False,
        ce_mask=0, has_pad=False, bsr_fmt=0, tbs=6792, used_or_retx=(24 | (2 << 10) | (3 << 8)),
        bsr_trig=0, bsr_ce=(0, 0, 0),
        phr0_pv=0, phr0_pc=0xFF, phr1_pv=0, phr1_pc=0xFF,
        ring1=25000, rlc_bo=4000,
    )
    add(
        tti_ms=5055, air_sti=5057, kind=4, cc=0, hq_id=0, ext_bsr=False,
        ce_mask=0, has_pad=False, bsr_fmt=0, tbs=1, used_or_retx=0,
        bsr_trig=0x12, bsr_ce=(0, 0, 0),
        phr0_pv=0, phr0_pc=0xFF, phr1_pv=0, phr1_pc=0xFF,
        ring1=25000, rlc_bo=4000,
    )

    blk_raw = pack_blk(wr_idx=seq, af_seq=10, af_tti=5030, af_sti=5032)
    dm_text = format_dm_vm(dec.BLK_VA, blk_raw) + format_dm_vm(dec.RING_VA_DEFAULT, bytes(recs_raw))

    with tempfile.TemporaryDirectory() as tmp:
        dm_path = os.path.join(tmp, "capture.dm")
        csv_path = os.path.join(tmp, "out.csv")
        open(dm_path, "w").write(dm_text)
        mem = dec.parse_vm_files([dm_path])
        b_raw, b_n = dec.extract_region(mem, dec.BLK_VA, dec.BLK_SIZE)
        assert b_n == dec.BLK_SIZE
        blk = dec.parse_block(b_raw)
        assert blk["magic"] == dec.MAGIC and blk["wr_idx"] == seq
        ring_raw, _ = dec.extract_region(mem, dec.RING_VA_DEFAULT, len(recs_raw))
        recs = dec.load_records(blk, ring_raw)
        assert len(recs) == seq
        stats = dec.analyze(recs, blk)

        # Verify padding share: PCell 0%, SCell 4000 / (4*6792) = 14.72%.
        assert stats["pad_stats"][0]["pad"] == 0
        assert stats["pad_stats"][1]["pad"] == 4000
        assert abs(stats["pad_stats"][1]["pad_pct"] - 100.0 * 4000 / (4 * 6792)) < 0.01

        # Verify step-up lag detected at 10 ms (2 UL TTIs) for both PCell and SCell!
        assert stats["step_lags"][0] == [(10, 2)], stats["step_lags"][0]
        assert stats["step_lags"][1] == [(10, 2)], stats["step_lags"][1]

        # Verify SCell bucket 40..60K shows SCell scheduled.
        assert stats["scell_by_bucket"]["40..60K"]["scell_on"] == 4

        # Verify one-carrier flip (2CC -> 1CC-P at 5030 ms) detected with surrounding PHRs!
        assert any(fl["from"] == "2CC" and fl["to"] == "1CC-P" and fl["tti_ms"] == 5030 for fl in stats["flips"])
        flip = next(fl for fl in stats["flips"] if fl["from"] == "2CC" and fl["to"] == "1CC-P")
        assert len(flip["phrs"]) == 2
        assert flip["phrs"][1]["phr1"]["ph_db"] == 18 - 23  # -5 dB
        assert flip["phrs"][1]["phr1"]["v"] == 1

        # Smoke-test print_report and CSV export.
        buf = io.StringIO()
        with redirect_stdout(buf):
            dec.print_report(blk, recs, stats)
        out = buf.getvalue()
        assert "10ms" in out and "2CC -> 1CC-P" in out and "<<< AF-TRIG" in out
        dec.write_csv(recs, csv_path)
        assert len(open(csv_path).readlines()) == seq + 1

    print("ALL PASS: decode-mac-trace.py roundtrip, DM vm parser, lag, SCell buckets, padding, and flip PHR tests")


if __name__ == "__main__":
    test_roundtrip_and_analytics()
