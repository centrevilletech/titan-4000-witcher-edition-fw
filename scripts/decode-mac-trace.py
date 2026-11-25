#!/usr/bin/env python3
"""Decode Titan 4000 G1 MAC UL timeline tracer dumps (`dm.sh` `vm` output or raw binary).

Parses `G1_BLK` (`0x8412a340`, 128 B) and `G1_RING` (`0x87f70000..0x87f90000`, 4,096 x 32 B)
from one or more `dm.sh` `vm` hex-dump logs (or raw binary files), reconstructs chronological
per-TTI MAC UL events, and reports:
  1. Control block status, wrap/continuity check, and event counts;
  2. Per-TTI timeline (SFN.SF, CC, grant TBS, used/pad, BSR, PHR, SR, Ring-1, RLC BO);
  3. Report-to-grant lag distribution per CC (step-response and cross-correlation);
  4. SCell grant size and scheduling share against reported BSR buffer buckets;
  5. Padding share per CC (PCell vs SCell);
  6. Per-carrier PHR (PH dB, V bit, Pcmax,c dBm) around every one-carrier flip.
"""
import argparse
import csv
import re
import statistics
import struct
import sys
from collections import defaultdict

BLK_VA = 0x8412A340
BLK_SIZE = 128
RING_VA_DEFAULT = 0x87F70000
RING_SLOTS_DEFAULT = 4096
REC_SIZE = 32
MAGIC = 0x47315452  # "G1TR"

# 3GPP TS 36.321 Table 6.1.3.1-1 (Standard BSR) upper bounds for idx 0..62; idx 63 = >150000.
STD_BSR = [
    0, 10, 12, 14, 17, 19, 22, 26, 31, 36, 42, 49, 57, 67, 78, 91, 107, 125, 146, 171, 200, 234,
    274, 321, 376, 440, 515, 603, 706, 826, 967, 1132, 1326, 1552, 1817, 2127, 2490, 2915, 3413,
    3995, 4677, 5476, 6411, 7505, 8787, 10287, 12043, 14099, 16507, 19325, 22624, 26487, 31009,
    36304, 42502, 49759, 58255, 68201, 79846, 93479, 109439, 128125, 150000,
]

# 3GPP TS 36.321 Table 6.1.3.1-2 (Extended BSR-r10) upper bounds for idx 0..62; idx 63 = >3000000.
EXT_BSR = [
    0, 10, 13, 16, 19, 23, 29, 35, 43, 53, 65, 80, 98, 120, 147, 181, 223, 274, 337, 414, 509,
    625, 769, 945, 1162, 1429, 1757, 2161, 2657, 3267, 4017, 4940, 6074, 7469, 9185, 11294, 13888,
    17077, 20999, 25822, 31752, 39045, 48012, 59039, 72598, 89272, 109774, 134986, 165989, 204111,
    250990, 308634, 379519, 466683, 573866, 705666, 867737, 1067031, 1312097, 1613447, 1984009,
    2439678, 3000000,
]

KIND_NAMES = {0: "EMPTY", 1: "NEW", 2: "ARX", 3: "NRX", 4: "SR"}
BSR_FMT_NAMES = {0: "-", 1: "S", 2: "T", 3: "L"}
FREEZE_REASONS = {0: "none", 1: "scell-drop/manual", 2: "pcell-drop", 3: "both-stall"}

# DM `vm` prints 4-byte little-endian words in big-endian byte order:
#   0x8412A340 | 47 31 54 52  20 26 11 25  00 00 00 01  00 00 00 00
VM_LINE_RE = re.compile(r"^\s*0x([0-9a-fA-F]{8})\s*\|\s*(.+?)\s*$")
HEX_BYTE_RE = re.compile(r"^[0-9a-fA-F]{2}$")


def bsr_idx_to_bytes(idx, ext=False):
    tbl = EXT_BSR if ext else STD_BSR
    if idx <= 0:
        return 0
    if idx >= 63:
        return tbl[62] + 1
    return tbl[idx]


def ph_idx_to_db(idx):
    # 3GPP TS 36.133 Table 9.1.8.4-1: 0 = -23 dB .. 63 = +40 dB
    return idx - 23


def pcmax_idx_to_dbm(idx):
    # 3GPP TS 36.133 Table 9.1.8.4-2: 0 = -29 dBm .. 63 = +33 dBm
    return idx - 29


def parse_vm_files(paths):
    """Parse one or more DM `vm` text files into a dict of {addr_u32: byte_val}."""
    mem = {}
    for path in paths:
        with open(path, "r", errors="replace") as f:
            for line in f:
                m = VM_LINE_RE.match(line)
                if not m:
                    continue
                base = int(m.group(1), 16)
                tokens = m.group(2).split()
                # Process in 4-byte word groups (MSB-first in DM `vm` output -> LE in RAM).
                for w_idx in range(0, len(tokens), 4):
                    grp = tokens[w_idx : w_idx + 4]
                    if len(grp) < 4:
                        break
                    if all(HEX_BYTE_RE.match(t) for t in grp):
                        # grp = [b3, b2, b1, b0] -> LE bytes [b0, b1, b2, b3]
                        waddr = base + w_idx
                        mem[waddr + 0] = int(grp[3], 16)
                        mem[waddr + 1] = int(grp[2], 16)
                        mem[waddr + 2] = int(grp[1], 16)
                        mem[waddr + 3] = int(grp[0], 16)
    return mem


def extract_region(mem, base, size):
    """Extract a contiguous byte array from `mem` (returning None if completely absent)."""
    present = sum(1 for a in range(base, base + size) if a in mem)
    if present == 0:
        return None, 0
    buf = bytearray(size)
    for off in range(size):
        b = mem.get(base + off)
        if b is not None:
            buf[off] = b
    return bytes(buf), present


def parse_block(raw):
    fields = struct.unpack_from("<32I", raw, 0)
    names = [
        "magic", "version", "enable", "freeze",
        "ring_base", "ring_slots", "record_size", "wr_idx",
        "af_mode", "af_tti_thresh", "af_bo_thresh", "af_post_events",
        "af_post_countdown", "af_trigger_reason", "af_trigger_seq", "af_trigger_tti",
        "cc0_nogrant_streak", "cc1_nogrant_streak", "cc_seen_mask", "last_grant_tti",
        "cnt_newtx_cc0", "cnt_newtx_cc1", "cnt_retx", "cnt_sr",
        "cnt_bsr", "cnt_phr", "snap_ce_buf", "snap_bsr_trig",
        "snap_phr_evt", "af_trigger_sti", "res0", "res1",
    ]
    return dict(zip(names, fields))


def decode_bsr_trig(trig_byte):
    mask = trig_byte & 0x1F
    is_pad = bool(trig_byte & 0x20)
    if is_pad or mask == 0x02:
        return "PAD"
    if mask == 0x14:
        return "RTX"
    if mask & 0x10:
        return "REG"
    if mask & 0x01:
        return "PER"
    return f"0x{mask:02x}" if mask else "-"


def decode_bsr_ce(bsr_fmt, bsr_ce, ext):
    if bsr_fmt == 0:
        return None
    if bsr_fmt in (1, 2):  # Short or Truncated: 1 byte [LCG:2 | idx:6]
        b0 = bsr_ce[0]
        lcg = (b0 >> 6) & 3
        idx = b0 & 0x3F
        rep = bsr_idx_to_bytes(idx, ext)
        return {
            "fmt": BSR_FMT_NAMES[bsr_fmt],
            "lcg": lcg,
            "idx": idx,
            "bytes": rep,
            "total_bytes": rep,
            "text": f"L{lcg}:{idx}({rep}B)",
        }
    if bsr_fmt == 3:  # Long: 3 bytes = 4 x 6-bit big-endian
        w = (bsr_ce[0] << 16) | (bsr_ce[1] << 8) | bsr_ce[2]
        idxs = [(w >> 18) & 0x3F, (w >> 12) & 0x3F, (w >> 6) & 0x3F, w & 0x3F]
        bs = [bsr_idx_to_bytes(i, ext) for i in idxs]
        nz = [f"L{k}:{idxs[k]}({bs[k]}B)" for k in range(4) if idxs[k] > 0]
        return {
            "fmt": "L",
            "idxs": idxs,
            "lcg_bytes": bs,
            "total_bytes": sum(bs),
            "text": ",".join(nz) if nz else "all0",
        }
    return None


def decode_phr_cell(ph_v, pcmax):
    if (ph_v & 0x80) == 0:
        return None
    virt = bool(ph_v & 0x40)
    ph_idx = ph_v & 0x3F
    ph_db = ph_idx_to_db(ph_idx)
    pc_dbm = None if (virt or pcmax == 0xFF) else pcmax_idx_to_dbm(pcmax & 0x3F)
    return {"ph_idx": ph_idx, "ph_db": ph_db, "v": int(virt), "pcmax_idx": pcmax, "pcmax_dbm": pc_dbm}


def decode_record(raw, offset=0):
    (
        tti_ms, air_sti, flags0, flags1, tbs_bytes, used_or_retx,
        bsr_trig, b0, b1, b2, phr0_pv, phr0_pc, phr1_pv, phr1_pc,
        ring1, rlc_bo, seq,
    ) = struct.unpack_from("<IHBBHHBBBBBBBBIII", raw, offset)
    kind = flags0 & 0x07
    cc = (flags0 >> 3) & 0x01
    hq_id = (flags0 >> 4) & 0x07
    ext_bsr = bool(flags0 & 0x80)
    ce_mask = flags1 & 0x1F
    has_pad = bool(flags1 & 0x20)
    bsr_fmt = (flags1 >> 6) & 0x03

    rec = {
        "tti_ms": tti_ms,
        "air_sti": air_sti,
        "sfn": air_sti // 10,
        "sf": air_sti % 10,
        "kind": kind,
        "kind_name": KIND_NAMES.get(kind, f"?{kind}"),
        "cc": cc,
        "hq_id": hq_id,
        "ext_bsr": ext_bsr,
        "ce_mask": ce_mask,
        "has_pad": has_pad,
        "bsr_fmt": bsr_fmt,
        "tbs": tbs_bytes,
        "used": used_or_retx if kind == 1 else 0,
        "pad": max(0, tbs_bytes - used_or_retx) if kind == 1 else 0,
        "mcs": (used_or_retx & 0xFF) if kind in (2, 3) else None,
        "tx_nb": ((used_or_retx >> 10) & 0x3F) if kind in (2, 3) else None,
        "rv": ((used_or_retx >> 8) & 0x03) if kind in (2, 3) else None,
        "bsr_trig_raw": bsr_trig,
        "bsr_trig": decode_bsr_trig(bsr_trig) if (bsr_fmt != 0 or kind == 4) else "-",
        "bsr": decode_bsr_ce(bsr_fmt, (b0, b1, b2), ext_bsr),
        "phr_type": ("DC" if ce_mask & 0x10 else ("Ext" if ce_mask & 0x08 else ("Reg" if ce_mask & 0x04 else "-"))),
        "phr0": decode_phr_cell(phr0_pv, phr0_pc),
        "phr1": decode_phr_cell(phr1_pv, phr1_pc),
        "ring1": ring1,
        "rlc_bo": rlc_bo,
        "seq": seq,
    }
    return rec


def load_records(blk, ring_bytes, ring_present_mask=None):
    slots = blk["ring_slots"] if blk else RING_SLOTS_DEFAULT
    wr_idx = blk["wr_idx"] if blk else None
    recs = []
    n_slots = len(ring_bytes) // REC_SIZE
    for i in range(min(slots, n_slots)):
        if ring_present_mask is not None and not ring_present_mask[i]:
            continue
        r = decode_record(ring_bytes, i * REC_SIZE)
        if r["kind"] == 0:
            continue
        if wr_idx is not None:
            if wr_idx == 0:
                continue
            lo_seq = max(0, wr_idx - slots)
            if not (lo_seq <= r["seq"] < wr_idx):
                continue
            if (r["seq"] % slots) != i:
                continue
        recs.append(r)
    recs.sort(key=lambda r: r["seq"])
    return recs


def analyze(recs, blk=None):
    """Compute all required summary analytics from chronological records."""
    # 1. Padding share per CC (NewTx only).
    pad_stats = {}
    for cc in (0, 1):
        ntx = [r for r in recs if r["kind"] == 1 and r["cc"] == cc]
        tot_tbs = sum(r["tbs"] for r in ntx)
        tot_used = sum(r["used"] for r in ntx)
        tot_pad = sum(r["pad"] for r in ntx)
        padded_cnt = sum(1 for r in ntx if r["has_pad"] or r["pad"] > 0)
        pad_stats[cc] = {
            "count": len(ntx),
            "tbs": tot_tbs,
            "used": tot_used,
            "pad": tot_pad,
            "pad_pct": (100.0 * tot_pad / tot_tbs) if tot_tbs else 0.0,
            "padded_tbs": padded_cnt,
            "padded_tb_pct": (100.0 * padded_cnt / len(ntx)) if ntx else 0.0,
        }

    # Group NewTx/Retx grants by (tti_ms // 5) or air_sti to form per-TTI views.
    # Use exact air_sti (paired with tti_ms bucket to distinguish 10.24 s wraps).
    ttis = []
    by_tti = {}
    for r in recs:
        if r["kind"] not in (1, 2, 3):
            continue
        key = (r["tti_ms"] // 10000, r["air_sti"])
        entry = by_tti.get(key)
        if entry is None:
            entry = {
                "tti_ms": r["tti_ms"],
                "air_sti": r["air_sti"],
                "cc0_tbs": 0,
                "cc1_tbs": 0,
                "bsr_bytes": None,
                "ring1": r["ring1"],
                "rlc_bo": r["rlc_bo"],
                "recs": [],
            }
            by_tti[key] = entry
            ttis.append(entry)
        entry["recs"].append(r)
        if r["cc"] == 0:
            entry["cc0_tbs"] = max(entry["cc0_tbs"], r["tbs"])
        else:
            entry["cc1_tbs"] = max(entry["cc1_tbs"], r["tbs"])
        if r["bsr"] is not None:
            entry["bsr_bytes"] = r["bsr"]["total_bytes"]
        entry["ring1"] = r["ring1"]
        entry["rlc_bo"] = r["rlc_bo"]

    # 2. Report-to-grant lag per CC.
    # (a) Event-based step-up lag: when BSR jumps from <= 1024 B to >= 2048 B (or jumps >= +4096 B),
    #     measure ms / UL TTIs until first grant >= 1500 B (or TBS increase >= 1000 B) on each CC.
    step_lags = {0: [], 1: []}
    prev_bsr = 0
    for idx, t in enumerate(ttis):
        if t["bsr_bytes"] is None:
            continue
        b = t["bsr_bytes"]
        jumped = (prev_bsr <= 1024 and b >= 2048) or (b >= prev_bsr + 4096)
        if jumped:
            base0, base1 = t["cc0_tbs"], t["cc1_tbs"]
            found = {0: False, 1: False}
            for j in range(idx + 1, min(len(ttis), idx + 12)):
                dt_ms = ttis[j]["tti_ms"] - t["tti_ms"]
                if dt_ms <= 0 or dt_ms > 60:
                    continue
                if not found[0] and ttis[j]["cc0_tbs"] >= max(base0 + 500, 1000):
                    step_lags[0].append((dt_ms, round(dt_ms / 5.0)))
                    found[0] = True
                if not found[1] and ttis[j]["cc1_tbs"] >= max(base1 + 500, 1000):
                    step_lags[1].append((dt_ms, round(dt_ms / 5.0)))
                    found[1] = True
                if found[0] and found[1]:
                    break
        prev_bsr = b

    # (b) Cross-correlation of reported BSR(t) vs grant TBS(t + k UL TTIs) for k = 1..6.
    xcorr = {0: {}, 1: {}}
    bsr_series = [(t["tti_ms"], t["bsr_bytes"], t["cc0_tbs"], t["cc1_tbs"]) for t in ttis if t["bsr_bytes"] is not None]
    for cc in (0, 1):
        for lag_tti in range(1, 7):
            target_dt = lag_tti * 5
            xs, ys = [], []
            j = 0
            for t_ms, bsr_b, _, _ in bsr_series:
                while j < len(ttis) and ttis[j]["tti_ms"] < t_ms + target_dt - 2:
                    j += 1
                if j < len(ttis) and abs(ttis[j]["tti_ms"] - (t_ms + target_dt)) <= 2:
                    xs.append(bsr_b)
                    ys.append(ttis[j]["cc0_tbs"] if cc == 0 else ttis[j]["cc1_tbs"])
            if len(xs) >= 3:
                mx, my = statistics.mean(xs), statistics.mean(ys)
                vx = sum((x - mx) ** 2 for x in xs)
                vy = sum((y - my) ** 2 for y in ys)
                r = (sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / ((vx * vy) ** 0.5)) if vx > 0 and vy > 0 else 0.0
                xcorr[cc][lag_tti] = (r, len(xs))

    # 3. SCell grant size vs reported BSR buffer (matched at 2 UL TTIs = ~10 ms earlier, fallback latest BSR).
    buckets = [
        (0, 2000, "0..2K"),
        (2000, 5000, "2..5K"),
        (5000, 10000, "5..10K"),
        (10000, 15000, "10..15K"),
        (15000, 20000, "15..20K"),
        (20000, 30000, "20..30K"),
        (30000, 40000, "30..40K"),
        (40000, 60000, "40..60K"),
        (60000, 10**9, "60K+"),
    ]
    scell_by_bucket = {lbl: {"ttis": 0, "scell_on": 0, "scell_tbs": [], "pcell_tbs": []} for _, _, lbl in buckets}
    bsr_hist = []  # (tti_ms, bsr_bytes)
    for t in ttis:
        # Look up BSR from ~10 ms (2 UL TTIs) earlier; fallback to most recent BSR before t.
        rep = None
        for bt, bb in reversed(bsr_hist):
            if 7 <= t["tti_ms"] - bt <= 15:
                rep = bb
                break
        if rep is None and bsr_hist:
            rep = bsr_hist[-1][1]
        if rep is not None:
            for lo, hi, lbl in buckets:
                if lo <= rep < hi:
                    st = scell_by_bucket[lbl]
                    st["ttis"] += 1
                    st["pcell_tbs"].append(t["cc0_tbs"])
                    if t["cc1_tbs"] > 0:
                        st["scell_on"] += 1
                        st["scell_tbs"].append(t["cc1_tbs"])
                    break
        if t["bsr_bytes"] is not None:
            bsr_hist.append((t["tti_ms"], t["bsr_bytes"]))

    # 4. One-carrier flips and surrounding PHR reports.
    def cc_mode(t):
        if t["cc0_tbs"] > 0 and t["cc1_tbs"] > 0:
            return "2CC"
        if t["cc0_tbs"] > 0:
            return "1CC-P"
        if t["cc1_tbs"] > 0:
            return "1CC-S"
        return "IDLE"

    flips = []
    if len(ttis) >= 4:
        modes = [cc_mode(t) for t in ttis]
        cur_state = modes[0]
        run_mode = modes[0]
        run_start = 0
        for i, m in enumerate(modes):
            if m != run_mode:
                run_mode = m
                run_start = i
            # Confirm state transition after 2 consecutive TTIs in a new mode.
            if m != cur_state and (i - run_start + 1) >= 2:
                if "1CC" in m or "1CC" in cur_state:
                    ft = ttis[run_start]
                    # Collect PHRs within +/- 200 ms of the flip.
                    phrs = [
                        r for r in recs
                        if (r["phr0"] is not None or r["phr1"] is not None)
                        and abs(r["tti_ms"] - ft["tti_ms"]) <= 200
                    ]
                    flips.append({
                        "tti_ms": ft["tti_ms"],
                        "air_sti": ft["air_sti"],
                        "from": cur_state,
                        "to": m,
                        "ring1": ft["ring1"],
                        "rlc_bo": ft["rlc_bo"],
                        "bsr": ft["bsr_bytes"],
                        "phrs": phrs,
                    })
                cur_state = m

    return {
        "pad_stats": pad_stats,
        "ttis": ttis,
        "step_lags": step_lags,
        "xcorr": xcorr,
        "scell_by_bucket": scell_by_bucket,
        "flips": flips,
    }


def fmt_phr(cell):
    if cell is None:
        return "-"
    v = "V" if cell["v"] else "R"
    pc = f"/{cell['pcmax_dbm']:+d}dBm" if cell["pcmax_dbm"] is not None else ""
    return f"{cell['ph_db']:+d}dB({v}){pc}"


def print_report(blk, recs, stats, show_timeline=True, limit=0):
    print("=" * 96)
    print("G1 MAC UL TIMELINE TRACER DECODE")
    print("=" * 96)
    if blk:
        magic_ok = "OK" if blk["magic"] == MAGIC else f"BAD({blk['magic']:#x})"
        print(
            f"Block @ {BLK_VA:#010x}: magic={blk['magic']:#010x} ({magic_ok}) "
            f"ver={blk['version']:#010x} enable={blk['enable']} freeze={blk['freeze']} "
            f"({FREEZE_REASONS.get(blk['freeze'], 'custom')})"
        )
        print(
            f"Ring: base={blk['ring_base']:#010x} slots={blk['ring_slots']} rec={blk['record_size']}B "
            f"wr_idx={blk['wr_idx']} (wrapped={'yes' if blk['wr_idx'] > blk['ring_slots'] else 'no'})"
        )
        print(
            f"Counters: NewTx(CC0={blk['cnt_newtx_cc0']}, CC1={blk['cnt_newtx_cc1']}) "
            f"Retx={blk['cnt_retx']} SR={blk['cnt_sr']} BSR={blk['cnt_bsr']} PHR={blk['cnt_phr']}"
        )
        if blk["af_mode"] or blk["af_trigger_reason"]:
            print(
                f"Auto-freeze: mode={blk['af_mode']:#x} tti_thresh={blk['af_tti_thresh']} "
                f"bo_thresh={blk['af_bo_thresh']}B post_ev={blk['af_post_events']} | "
                f"triggered={FREEZE_REASONS.get(blk['af_trigger_reason'], blk['af_trigger_reason'])} "
                f"seq={blk['af_trigger_seq']} tti={blk['af_trigger_tti']} "
                f"sti={blk['af_trigger_sti'] // 10}.{blk['af_trigger_sti'] % 10}"
            )

    gaps = sum(1 for a, b in zip(recs, recs[1:]) if b["seq"] != a["seq"] + 1)
    span_ms = (recs[-1]["tti_ms"] - recs[0]["tti_ms"]) if len(recs) >= 2 else 0
    print(f"Decoded records: {len(recs)} (span {span_ms} ms, seq gaps={gaps})")

    if show_timeline and recs:
        print("\n--- Timeline ---")
        print(
            f"{'seq':>6} {'tti_ms':>8} {'dt':>4} {'SFN.SF':>6} {'CC':>2} {'KND':>3} {'HQ':>2} "
            f"{'TBS':>5} {'USED':>5} {'PAD':>5} {'BSR':24s} {'PHR':28s} {'R1':>7} {'RLC':>7}"
        )
        view = recs[-limit:] if limit > 0 else recs
        prev_t = view[0]["tti_ms"]
        trig_seq = blk["af_trigger_seq"] if (blk and blk["af_trigger_reason"]) else None
        for r in view:
            dt = r["tti_ms"] - prev_t
            prev_t = r["tti_ms"]
            cc_s = "P" if r["cc"] == 0 else "S"
            if r["kind"] == 1:
                used_s, pad_s = f"{r['used']:5d}", f"{r['pad']:5d}"
            elif r["kind"] in (2, 3):
                used_s, pad_s = f"m{r['mcs']:2d}t{r['tx_nb']}", f"rv{r['rv']}"
            else:
                used_s, pad_s = "    -", "    -"
            bsr_s = f"{r['bsr']['fmt']}/{r['bsr_trig']}:{r['bsr']['text']}" if r["bsr"] else (
                f"trig:{r['bsr_trig']}" if r["kind"] == 4 else "-"
            )
            phr_s = "-"
            if r["phr0"] or r["phr1"]:
                phr_s = f"{r['phr_type']} P:{fmt_phr(r['phr0'])}"
                if r["phr1"]:
                    phr_s += f" S:{fmt_phr(r['phr1'])}"
            mark = " <<< AF-TRIG" if trig_seq is not None and r["seq"] == trig_seq else ""
            print(
                f"{r['seq']:6d} {r['tti_ms']:8d} {dt:4d} {r['sfn']:4d}.{r['sf']} "
                f"{cc_s:>2} {r['kind_name']:>3} {r['hq_id']:2d} "
                f"{r['tbs']:5d} {used_s:>5} {pad_s:>5} {bsr_s:24s} {phr_s:28s} "
                f"{r['ring1']:7d} {r['rlc_bo']:7d}{mark}"
            )

    print("\n--- 1. Padding share per CC (NewTx) ---")
    for cc, label in ((0, "PCell (CC0)"), (1, "SCell (CC1)")):
        ps = stats["pad_stats"][cc]
        print(
            f"  {label}: {ps['count']:5d} TBs | TBS={ps['tbs']:9,d} B  used={ps['used']:9,d} B  "
            f"pad={ps['pad']:8,d} B ({ps['pad_pct']:5.2f}%) | padded TBs={ps['padded_tbs']} ({ps['padded_tb_pct']:5.1f}%)"
        )

    print("\n--- 2. Report-to-grant lag distribution per CC ---")
    for cc, label in ((0, "PCell (CC0)"), (1, "SCell (CC1)")):
        lags = stats["step_lags"][cc]
        if lags:
            ms_vals = sorted(x[0] for x in lags)
            tti_vals = [x[1] for x in lags]
            p50 = ms_vals[len(ms_vals) // 2]
            p90 = ms_vals[int(0.9 * (len(ms_vals) - 1))]
            hist = defaultdict(int)
            for tv in tti_vals:
                hist[tv] += 1
            h_str = " ".join(f"{k}TTI:{v}" for k, v in sorted(hist.items()))
            print(f"  {label} step-up lag (n={len(lags)}): min={ms_vals[0]}ms p50={p50}ms p90={p90}ms max={ms_vals[-1]}ms | {h_str}")
        else:
            print(f"  {label} step-up lag: no BSR step-up events observed")
        xc = stats["xcorr"][cc]
        if xc:
            xc_str = "  ".join(f"lag {k}TTI({k*5}ms): r={r:+.3f}(n={n})" for k, (r, n) in sorted(xc.items()))
            print(f"  {label} BSR->TBS xcorr: {xc_str}")

    print("\n--- 3. SCell grant size vs reported BSR buffer (~2 UL TTIs earlier) ---")
    print(f"  {'BSR bucket':>10} {'TTIs':>6} {'SCell%':>7} {'SCell mean':>11} {'SCell med':>10} {'PCell mean':>11}")
    for lbl, st in stats["scell_by_bucket"].items():
        if st["ttis"] == 0:
            continue
        pct = 100.0 * st["scell_on"] / st["ttis"]
        sm = statistics.mean(st["scell_tbs"]) if st["scell_tbs"] else 0.0
        smed = statistics.median(st["scell_tbs"]) if st["scell_tbs"] else 0.0
        pm = statistics.mean(st["pcell_tbs"]) if st["pcell_tbs"] else 0.0
        print(f"  {lbl:>10} {st['ttis']:6d} {pct:6.1f}% {sm:9.0f} B {smed:8.0f} B {pm:9.0f} B")

    print("\n--- 4. PHR per carrier around each one-carrier flip ---")
    flips = stats["flips"]
    if not flips:
        print("  No one-carrier flips observed in this capture.")
    for idx, fl in enumerate(flips):
        print(
            f"  Flip #{idx + 1}: tti={fl['tti_ms']}ms ({fl['air_sti'] // 10}.{fl['air_sti'] % 10}) "
            f"{fl['from']} -> {fl['to']} | BSR={fl['bsr']}B Ring1={fl['ring1']}B RLC={fl['rlc_bo']}B"
        )
        if not fl["phrs"]:
            print("    (no PHR MAC CE within +/- 200 ms)")
        for p in fl["phrs"]:
            rel = p["tti_ms"] - fl["tti_ms"]
            print(
                f"    {rel:+5d}ms (SFN {p['sfn']:4d}.{p['sf']} CC{p['cc']} {p['phr_type']:3s}): "
                f"PCell={fmt_phr(p['phr0']):18s} SCell={fmt_phr(p['phr1']):18s} "
                f"R1={p['ring1']}B RLC={p['rlc_bo']}B"
            )


def write_csv(recs, out_path):
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "seq", "tti_ms", "air_sti", "sfn", "sf", "cc", "kind", "hq_id",
            "tbs", "used", "pad", "bsr_fmt", "bsr_trig", "bsr_bytes",
            "phr_type", "phr_cc0_db", "phr_cc0_v", "phr_cc0_pcmax_dbm",
            "phr_cc1_db", "phr_cc1_v", "phr_cc1_pcmax_dbm", "ring1", "rlc_bo",
        ])
        for r in recs:
            w.writerow([
                r["seq"], r["tti_ms"], r["air_sti"], r["sfn"], r["sf"], r["cc"], r["kind_name"], r["hq_id"],
                r["tbs"], r["used"], r["pad"],
                r["bsr"]["fmt"] if r["bsr"] else "",
                r["bsr_trig"],
                r["bsr"]["total_bytes"] if r["bsr"] else "",
                r["phr_type"],
                r["phr0"]["ph_db"] if r["phr0"] else "",
                r["phr0"]["v"] if r["phr0"] else "",
                r["phr0"]["pcmax_dbm"] if (r["phr0"] and r["phr0"]["pcmax_dbm"] is not None) else "",
                r["phr1"]["ph_db"] if r["phr1"] else "",
                r["phr1"]["v"] if r["phr1"] else "",
                r["phr1"]["pcmax_dbm"] if (r["phr1"] and r["phr1"]["pcmax_dbm"] is not None) else "",
                r["ring1"], r["rlc_bo"],
            ])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dumps", nargs="*", help="One or more dm.sh vm dump files")
    ap.add_argument("--raw-blk", help="Optional raw 128 B binary G1_BLK file")
    ap.add_argument("--raw-ring", help="Optional raw binary G1_RING file")
    ap.add_argument("--no-timeline", action="store_true", help="Print only summary analytics")
    ap.add_argument("--limit", type=int, default=0, help="Show only the last N timeline rows (0 = all)")
    ap.add_argument("--csv", help="Optional path to export decoded timeline CSV")
    args = ap.parse_args()

    blk = None
    ring_bytes = None
    present_mask = None

    if args.raw_blk or args.raw_ring:
        if args.raw_blk:
            blk = parse_block(open(args.raw_blk, "rb").read())
        if args.raw_ring:
            ring_bytes = open(args.raw_ring, "rb").read()
    else:
        if not args.dumps:
            ap.error("Provide one or more dm.sh vm dump files, or --raw-blk / --raw-ring")
        mem = parse_vm_files(args.dumps)
        blk_raw, blk_n = extract_region(mem, BLK_VA, BLK_SIZE)
        if blk_raw is not None and blk_n == BLK_SIZE:
            blk = parse_block(blk_raw)
        ring_base = blk["ring_base"] if blk else RING_VA_DEFAULT
        ring_slots = blk["ring_slots"] if blk else RING_SLOTS_DEFAULT
        ring_raw, _ = extract_region(mem, ring_base, ring_slots * REC_SIZE)
        if ring_raw is None:
            sys.exit(f"No ring bytes found at {ring_base:#010x} in {args.dumps}")
        ring_bytes = ring_raw
        present_mask = [
            all((ring_base + i * REC_SIZE + k) in mem for k in range(REC_SIZE))
            for i in range(ring_slots)
        ]

    recs = load_records(blk, ring_bytes, present_mask)
    stats = analyze(recs, blk)
    print_report(blk, recs, stats, show_timeline=not args.no_timeline, limit=args.limit)
    if args.csv:
        write_csv(recs, args.csv)


if __name__ == "__main__":
    main()
