//! Boot confirm for a full firmware update, with one switch back to the old
//! bank.
//!
//! The Titan 4000 keeps two complete firmware banks in NAND: kernel
//! (`mtd13`/`mtd14`), root filesystem (`mtd15`/`mtd16`) and modem firmware
//! (`mtd17`/`mtd18`). NV item 23 in the `cmnnv` partition holds the bank table:
//! six 36-byte records, two per part, then four unused records (360 bytes).
//! Each record is little-endian:
//!
//! | Offset | Field |
//! | --- | --- |
//! | `0x00` | Adler-32 with seed 0 of bytes `0x04..0x24` |
//! | `0x04` | magic `0xcafebabe` |
//! | `0x08` | header length, 36 |
//! | `0x0c` | sequence number |
//! | `0x10` | Adler-32 with seed 0 of the image as written |
//! | `0x14` | image size in bytes |
//!
//! For each part, the boot code and `modem.ko` take the bank whose record has
//! the higher sequence number. The vendor updater writes the inactive bank and
//! then raises that bank's sequence numbers. Nothing ever switches back: a bank
//! that boots but never brings up management stays selected until someone
//! drives to the roof.
//!
//! This module decides when the keeper's bank guard switches back:
//! - It arms only on the first boot of a bank that an updater just wrote and
//!   marked (`Marker`). A unit that was not just updated is never touched.
//! - The new bank must prove itself within `confirm_secs` of boot: an address
//!   on the management bearer, a ping answer through the core, and a keeper
//!   that started this boot and stays up. Optionally the customer bearer too.
//! - Without that proof the guard raises the old bank's sequence numbers in one
//!   NV write and reboots once. It refuses if the old bank fails its own checks
//!   (`kernel_ok`, `modem_ok`, `UbiTally`).
//! - A boot counter and a switch counter, both written before acting, bound it:
//!   at most three guard reboots for one update, then it gives up.
//!
//! The table rewrite is idempotent: it computes "select bank N" from the table
//! it reads, never "toggle". The vendor's own toggle (`Upgrade_toggleFormatProgram`)
//! writes the three parts in three separate NV writes, ignores write errors,
//! and flips relative to the current state, so a second run after a torn first
//! run splits the banks again. One NV write is one program of one `cmnnv`
//! block to the older of its two copies (`cmn_copy`), so a power cut leaves the
//! old table or the new one, never a mix.
//!
//! The NV layer keeps its table in RAM and updates that copy before it
//! programs flash. A read through the vendor library after a failed program
//! still shows the new table. The guard therefore reads the `cmnnv` blocks
//! itself, the way the kernel does at boot, before and after it writes.

use crate::sha256;
use serde::{Deserialize, Serialize};

/// One record of the bank table.
pub const RECORD: usize = 36;
/// NV item 23: ten records, of which the first six are used.
pub const TABLE: usize = 360;
pub const MAGIC: u32 = 0xcafe_babe;
/// Kernel, root filesystem, modem firmware.
pub const PARTS: [&str; 3] = ["kernel", "rootfs", "modem"];
/// Partition names in `/proc/mtd`, by part and bank.
pub const PARTITIONS: [[&str; 2]; 3] = [["linux", "linux2"], ["rootfs", "rootfs2"], ["tk", "tk2"]];
/// Partition sizes, by part. The image in a record must fit.
pub const LIMITS: [u32; 3] = [4 << 20, 60 << 20, 8 << 20];
/// NAND erase block on this unit.
pub const ERASE: usize = 0x20000;
/// The `cmnnv` NV block: a 36-byte wrapper, then the NV items. Item 23 is first.
pub const CMN_WRAPPER: usize = 36;
/// MTD number of a part in a bank: `mtd13` (`linux`) to `mtd18` (`tk2`).
pub fn mtd_number(part: usize, bank: usize) -> usize {
    13 + part * 2 + bank
}

/// Default time a new bank has to prove itself, counted from boot.
pub const CONFIRM_SECS: u64 = 600;
const MIN_CONFIRM_SECS: u64 = 300;
const MAX_CONFIRM_SECS: u64 = 1800;
/// Seconds between ping rounds.
pub const PROBE_EVERY: u64 = 15;
/// A round with no answer after this long counts as silent.
pub const PROBE_TIMEOUT: u64 = 6;
/// The same keeper process must be seen this far apart to count as healthy.
pub const KEEPER_STABLE: u64 = 30;
/// Boots of one update, without proof, before the guard switches at once.
pub const BOOTS_BEFORE_SWITCH: u32 = 3;
/// Switch attempts for one update before the guard gives up.
pub const MAX_SWITCHES: u32 = 2;
const MAX_TARGETS: usize = 4;
const MAX_CONSUMED: usize = 8;
const MAX_HISTORY: usize = 12;

/// Adler-32 as the vendor computes it: both sums start at 0, not at 1.
#[derive(Clone, Copy, Debug, Default)]
pub struct Adler {
    a: u32,
    b: u32,
}

impl Adler {
    pub fn update(&mut self, data: &[u8]) {
        // 5552 bytes keep both sums below 2^32 before the reduction (zlib's NMAX).
        for chunk in data.chunks(5552) {
            for &byte in chunk {
                self.a += u32::from(byte);
                self.b += self.a;
            }
            self.a %= 65521;
            self.b %= 65521;
        }
    }

    pub fn finish(self) -> u32 {
        self.b << 16 | self.a
    }
}

pub fn adler0(data: &[u8]) -> u32 {
    let mut adler = Adler::default();
    adler.update(data);
    adler.finish()
}

/// CRC-32 (IEEE) with a caller-chosen start and no final inversion. UBI uses
/// it with start `0xffffffff`; the standard CRC-32 is `!crc32_raw(!0, ..)`.
pub fn crc32_raw(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { crc >> 1 ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    crc
}

pub fn crc32(data: &[u8]) -> u32 {
    !crc32_raw(!0, data)
}

fn le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn be(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// One part as a record describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub seq: u32,
    /// Adler-32 (seed 0) of the image as written.
    pub adler: u32,
    pub size: u32,
}

/// What a bank holds: size and checksum of each part, as written. The kernel
/// and modem firmware never change after the write. The root filesystem does
/// (UBI rewrites its headers), so its record checksum names the image written,
/// not the flash today.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Image {
    pub parts: [(u32, u32); 3],
}

/// One write of a bank: its image and the sequence numbers it got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Install {
    pub image: Image,
    pub seqs: [u32; 3],
}

/// The stock 4172 image, from the vendor `.prg` the build is pinned to. Witcher
/// keeps the kernel and modem firmware byte for byte; only the root
/// filesystem differs.
pub const STOCK_4172: Image = Image {
    parts: [(2_709_672, 0x32f9_689f), (31_195_136, 0xdb8d_d823), (4_652_511, 0x9c6e_9804)],
};

/// NV item 23.
#[derive(Clone, PartialEq, Eq)]
pub struct Table {
    pub bytes: [u8; TABLE],
}

impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&sha256::hex(&self.bytes[..RECORD * 6]))
    }
}

impl Table {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let bytes: [u8; TABLE] = bytes
            .try_into()
            .map_err(|_| format!("the bank table is {} bytes, not {TABLE}", bytes.len()))?;
        Ok(Self { bytes })
    }

    fn offset(part: usize, bank: usize) -> usize {
        (part * 2 + bank) * RECORD
    }

    pub fn record(&self, part: usize, bank: usize) -> Record {
        let o = Self::offset(part, bank);
        Record {
            seq: le(&self.bytes, o + 12),
            adler: le(&self.bytes, o + 16),
            size: le(&self.bytes, o + 20),
        }
    }

    /// Why a record is not one the boot code would take, if it is not.
    pub fn record_problem(&self, part: usize, bank: usize) -> Option<String> {
        let o = Self::offset(part, bank);
        let r = &self.bytes[o..o + RECORD];
        let name = PARTITIONS[part][bank];
        if le(r, 4) != MAGIC {
            return Some(format!("{name}: no record magic"));
        }
        if le(r, 8) != RECORD as u32 {
            return Some(format!("{name}: record length {} is not 36", le(r, 8)));
        }
        if le(r, 0) != adler0(&r[4..]) {
            return Some(format!("{name}: record checksum is wrong"));
        }
        let size = le(r, 20);
        if size == 0 || size > LIMITS[part] {
            return Some(format!("{name}: image size {size} does not fit the partition"));
        }
        None
    }

    /// All six records valid.
    pub fn check(&self) -> Result<(), String> {
        for part in 0..3 {
            for bank in 0..2 {
                if let Some(problem) = self.record_problem(part, bank) {
                    return Err(problem);
                }
            }
        }
        Ok(())
    }

    /// The bank all three parts boot from. Ties, the largest sequence number,
    /// and parts that disagree are refused, as titan-api's updater refuses them.
    pub fn selected(&self) -> Result<usize, String> {
        self.check()?;
        let mut selected = None;
        for part in 0..3 {
            let (a, b) = (self.record(part, 0).seq, self.record(part, 1).seq);
            if a == b || a == u32::MAX || b == u32::MAX {
                return Err(format!("{}: both banks have sequence {a}/{b}", PARTS[part]));
            }
            let bank = usize::from(b > a);
            if selected.is_some_and(|s| s != bank) {
                return Err("kernel, root filesystem and modem select different banks".into());
            }
            selected = Some(bank);
        }
        Ok(selected.unwrap_or(0))
    }

    pub fn image(&self, bank: usize) -> Image {
        let mut parts = [(0, 0); 3];
        for (part, slot) in parts.iter_mut().enumerate() {
            let r = self.record(part, bank);
            *slot = (r.size, r.adler);
        }
        Image { parts }
    }

    pub fn install(&self, bank: usize) -> Install {
        Install {
            image: self.image(bank),
            seqs: [0, 1, 2].map(|part| self.record(part, bank).seq),
        }
    }

    /// The table with every part on `bank`. Only that bank's sequence numbers
    /// and record checksums change. A part already on `bank` keeps its record.
    /// `extra` raises the new sequence numbers further, so a retry writes
    /// different bytes (the NV layer skips a write that matches its RAM copy).
    pub fn select(&self, bank: usize, extra: u32) -> Result<Self, String> {
        self.check()?;
        let other = 1 - bank;
        let mut next = self.clone();
        for part in 0..3 {
            let mine = self.record(part, bank).seq;
            let theirs = self.record(part, other).seq;
            if mine > theirs && extra == 0 {
                continue;
            }
            let seq = theirs
                .max(mine)
                .checked_add(1 + extra)
                .filter(|seq| *seq != u32::MAX)
                .ok_or_else(|| format!("{}: sequence numbers are exhausted", PARTS[part]))?;
            let o = Self::offset(part, bank);
            next.bytes[o + 12..o + 16].copy_from_slice(&seq.to_le_bytes());
            let sum = adler0(&next.bytes[o + 4..o + RECORD]);
            next.bytes[o..o + 4].copy_from_slice(&sum.to_le_bytes());
        }
        if next.selected()? != bank || !next.changed_only(self, bank) {
            return Err("the rewritten bank table failed its own check".into());
        }
        Ok(next)
    }

    /// True when `self` differs from `before` only in the sequence numbers and
    /// record checksums of `bank`.
    pub fn changed_only(&self, before: &Self, bank: usize) -> bool {
        (0..TABLE).all(|i| {
            if self.bytes[i] == before.bytes[i] {
                return true;
            }
            let record = i / RECORD;
            let field = i % RECORD;
            record < 6 && record % 2 == bank && (field < 4 || (12..16).contains(&field))
        })
    }
}

/// A `cmnnv` copy, checked the way the kernel's `load_nv` checks it: magic,
/// wrapper checksum, then the block checksum (or a stored 0). The sequence
/// number on success.
pub fn cmn_copy(block: &[u8]) -> Result<u32, String> {
    if block.len() < CMN_WRAPPER + TABLE {
        return Err("short block".into());
    }
    if le(block, 4) != MAGIC {
        return Err("no wrapper magic".into());
    }
    if le(block, 0) != adler0(&block[4..CMN_WRAPPER]) {
        return Err("wrapper checksum is wrong".into());
    }
    let stored = le(block, 16);
    if stored != 0 && stored != adler0(&block[CMN_WRAPPER..]) {
        return Err("block checksum is wrong (torn or damaged write)".into());
    }
    Ok(le(block, 12))
}

/// The copy the kernel boots with: both valid, the first unless the second
/// has the higher sequence number; else the one valid copy. Returns its index
/// and NV item 23 from it.
pub fn cmn_select(copies: [Option<&[u8]>; 2]) -> Result<(usize, Table), String> {
    let seqs = copies.map(|copy| copy.map(cmn_copy));
    let index = match (&seqs[0], &seqs[1]) {
        (Some(Ok(a)), Some(Ok(b))) => usize::from(a <= b),
        (Some(Ok(_)), _) => 0,
        (_, Some(Ok(_))) => 1,
        _ => return Err("neither cmnnv copy is valid".into()),
    };
    let block = copies[index].unwrap();
    Ok((index, Table::from_bytes(&block[CMN_WRAPPER..CMN_WRAPPER + TABLE])?))
}

/// The kernel keeps the two copies in the second and third good blocks of the
/// partition (the first good block is not one of them).
pub fn cmn_copy_blocks(bad: &[bool]) -> Option<[usize; 2]> {
    let good: Vec<usize> = (0..bad.len()).filter(|&i| !bad[i]).collect();
    (good.len() >= 3).then(|| [good[1], good[2]])
}

/// The bank `/proc/cmdline` booted, checked against the mounted root.
pub fn running_bank(cmdline: &str) -> Result<usize, String> {
    let bank = match cmdline.split_whitespace().find_map(|v| v.strip_prefix("active=")) {
        Some("linux,rootfs,tk") => 0,
        Some("linux2,rootfs2,tk2") => 1,
        other => return Err(format!("unsupported active= on the kernel command line: {other:?}")),
    };
    let root = format!("ubi.mtd={},2048", mtd_number(1, bank));
    if !cmdline.split_whitespace().any(|v| v == root) {
        return Err("the mounted root does not match active=".into());
    }
    Ok(bank)
}

/// The partition line `/proc/mtd` must show for each MTD the guard reads.
pub fn expected_mtd_lines() -> Vec<(usize, String)> {
    let mut lines = vec![(8, "mtd8: 00100000 00020000 \"cmnnv\"".to_owned())];
    for part in 0..3 {
        for bank in 0..2 {
            let n = mtd_number(part, bank);
            lines.push((
                n,
                format!("mtd{n}: {:08x} 00020000 \"{}\"", LIMITS[part], PARTITIONS[part][bank]),
            ));
        }
    }
    lines
}

pub fn mtd_layout_ok(proc_mtd: &str) -> Result<(), String> {
    for (n, line) in expected_mtd_lines() {
        if !proc_mtd.lines().any(|l| l.trim() == line) {
            return Err(format!("mtd{n} is not where the guard expects it"));
        }
    }
    Ok(())
}

/// The first 64 bytes of a kernel bank: a uImage header with a good header
/// CRC, sized to fill the record.
pub fn kernel_header_ok(header: &[u8], size: u32) -> Result<(), String> {
    if header.len() < 64 || be(header, 0) != 0x2705_1956 {
        return Err("no uImage header".into());
    }
    let mut copy = header[..64].to_vec();
    copy[4..8].fill(0);
    if crc32(&copy) != be(header, 4) {
        return Err("uImage header CRC is wrong".into());
    }
    if u64::from(be(header, 12)) + 64 != u64::from(size) {
        return Err("uImage length does not match the bank record".into());
    }
    Ok(())
}

/// The first bytes of a modem bank: gzip, deflate, no flags `modem.ko` refuses.
pub fn modem_header_ok(header: &[u8]) -> Result<(), String> {
    if header.len() < 4 || header[..3] != [0x1f, 0x8b, 0x08] || header[3] & 0xe2 != 0 {
        return Err("no gzip header modem.ko accepts".into());
    }
    Ok(())
}

/// One UBI physical eraseblock of a root filesystem bank.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Peb {
    /// Never written since the last erase.
    Erased,
    /// Erase counter header only.
    Free,
    Leb { volume: u32, lnum: u32 },
    Corrupt(String),
}

pub const UBI_LAYOUT_VOLUME: u32 = 0x7fff_efff;

/// The erase counter header: `None` for an erased block, else the offsets of
/// the volume header and the data.
pub fn ubi_ec(header: &[u8]) -> Result<Option<(usize, usize)>, String> {
    if header.len() < 64 {
        return Err("short erase counter header".into());
    }
    if header[..64].iter().all(|&b| b == 0xff) {
        return Ok(None);
    }
    if &header[..4] != b"UBI#" || header[4] != 1 {
        return Err("no erase counter header".into());
    }
    if crc32_raw(!0, &header[..60]) != be(header, 60) {
        return Err("erase counter header CRC is wrong".into());
    }
    let vid = be(header, 16) as usize;
    let data = be(header, 20) as usize;
    if vid < 64 || vid + 64 > data || data >= ERASE {
        return Err("erase counter header offsets are wrong".into());
    }
    Ok(Some((vid, data)))
}

/// The volume header: `None` for a free block, else volume and LEB number.
pub fn ubi_vid(header: &[u8]) -> Result<Option<(u32, u32)>, String> {
    if header.len() < 64 {
        return Err("short volume header".into());
    }
    if header[..64].iter().all(|&b| b == 0xff) {
        return Ok(None);
    }
    if &header[..4] != b"UBI!" || header[4] != 1 {
        return Err("no volume header".into());
    }
    if crc32_raw(!0, &header[..60]) != be(header, 60) {
        return Err("volume header CRC is wrong".into());
    }
    Ok(Some((be(header, 8), be(header, 12))))
}

/// Tally of a root filesystem bank. The rootfs record checksum cannot be used
/// after the bank has run: UBI writes erase counter headers on attach. So the
/// guard checks structure instead: every header's CRC, both copies of the
/// volume table naming `rootfs`, logical blocks 0 to 2 present, and the UBIFS
/// superblock magic at the start of block 0.
#[derive(Clone, Debug, Default)]
pub struct UbiTally {
    pub pebs: usize,
    pub erased: usize,
    pub free: usize,
    pub used: usize,
    pub layout: usize,
    pub layout_rootfs: usize,
    pub head_lebs: [bool; 3],
    pub superblock: bool,
    pub corrupt: Vec<String>,
}

impl UbiTally {
    /// `data` is the start of the block's data area: at least 172 bytes for a
    /// volume table block, 4 bytes for a rootfs block.
    pub fn add(&mut self, index: usize, ec: &[u8], vid: Option<&[u8]>, data: Option<&[u8]>) {
        self.pebs += 1;
        let peb = match ubi_ec(ec) {
            Err(e) => Peb::Corrupt(e),
            Ok(None) => Peb::Erased,
            Ok(Some(_)) => match vid.map(ubi_vid) {
                None => Peb::Corrupt("volume header not read".into()),
                Some(Err(e)) => Peb::Corrupt(e),
                Some(Ok(None)) => Peb::Free,
                Some(Ok(Some((volume, lnum)))) => Peb::Leb { volume, lnum },
            },
        };
        match peb {
            Peb::Erased => self.erased += 1,
            Peb::Free => self.free += 1,
            Peb::Corrupt(e) => self.corrupt.push(format!("PEB {index}: {e}")),
            Peb::Leb { volume, lnum } => {
                self.used += 1;
                let data = data.unwrap_or_default();
                if volume == UBI_LAYOUT_VOLUME {
                    self.layout += 1;
                    if volume_table_names_rootfs(data) {
                        self.layout_rootfs += 1;
                    }
                } else if volume == 0 && lnum < 3 {
                    self.head_lebs[lnum as usize] = true;
                    if lnum == 0 && data.len() >= 4 && data[..4] == [0x31, 0x18, 0x10, 0x06] {
                        self.superblock = true;
                    }
                }
            }
        }
    }

    pub fn verdict(&self) -> Result<(), String> {
        if let Some(first) = self.corrupt.first() {
            return Err(format!("{} damaged UBI headers, first {first}", self.corrupt.len()));
        }
        if self.layout < 2 || self.layout_rootfs < 2 {
            return Err("the UBI volume table does not hold rootfs twice".into());
        }
        if !self.head_lebs.iter().all(|&seen| seen) {
            return Err("UBIFS blocks 0 to 2 are not all present".into());
        }
        if !self.superblock {
            return Err("no UBIFS superblock at the start of the volume".into());
        }
        Ok(())
    }
}

/// The first record of a UBI volume table: volume 0 named `rootfs`, with a
/// good record CRC.
pub fn volume_table_names_rootfs(record: &[u8]) -> bool {
    if record.len() < 172 {
        return false;
    }
    let length = u16::from_be_bytes([record[14], record[15]]) as usize;
    length == 6 && &record[16..22] == b"rootfs" && crc32_raw(!0, &record[..168]) == be(record, 168)
}

/// Guard settings, `/mnt/titan-api/bank-guard/config`: `enabled=0|1`,
/// `confirm_secs=<300..1800>`, up to four `target=<address>` lines (else the
/// deaf watchdog's targets), `require_customer=0|1` and up to four
/// `customer_target=<address>` lines. Bad lines are ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    pub confirm_secs: u64,
    pub targets: Vec<std::net::IpAddr>,
    pub require_customer: bool,
    pub customer_targets: Vec<std::net::IpAddr>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            confirm_secs: CONFIRM_SECS,
            targets: Vec::new(),
            require_customer: false,
            customer_targets: Vec::new(),
        }
    }
}

pub fn parse_settings(text: &str) -> Settings {
    let mut settings = Settings::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let flag = match value {
            "0" | "false" | "off" => Some(false),
            "1" | "true" | "on" => Some(true),
            _ => None,
        };
        match key.trim() {
            "enabled" => settings.enabled = flag.unwrap_or(settings.enabled),
            "require_customer" => settings.require_customer = flag.unwrap_or(settings.require_customer),
            "confirm_secs" => {
                if let Ok(secs) = value.parse::<u64>() {
                    settings.confirm_secs = secs.clamp(MIN_CONFIRM_SECS, MAX_CONFIRM_SECS);
                }
            }
            key @ ("target" | "customer_target") => {
                let list = if key == "target" {
                    &mut settings.targets
                } else {
                    &mut settings.customer_targets
                };
                if let Ok(addr) = value.parse::<std::net::IpAddr>() {
                    if !addr.is_unspecified() && !list.contains(&addr) && list.len() < MAX_TARGETS {
                        list.push(addr);
                    }
                }
            }
            _ => {}
        }
    }
    settings
}

/// Evidence that this boot is the first boot of a bank an updater just wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marker {
    /// `titan-api`, `arm` or `first-witcher-boot`.
    pub source: &'static str,
    /// Same evidence, same fingerprint: one marker arms once.
    pub fingerprint: String,
    pub target: usize,
    /// Part sizes the updater wrote, when it says.
    pub sizes: Option<[u32; 3]>,
    /// The write the updater recorded, when it says.
    pub install: Option<Install>,
}

/// titan-api's `firmware-operation.json`. It writes `verified-awaiting-reboot`
/// after a checked install, and `selected-awaiting-reboot` after a manual bank
/// switch, before the reboot in both cases.
pub fn titan_api_marker(text: &str) -> Option<Marker> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let state = value["state"].as_str()?;
    if !matches!(state, "verified-awaiting-reboot" | "selected-awaiting-reboot") {
        return None;
    }
    let target = value["target_bank"].as_u64().filter(|b| *b < 2)? as usize;
    let sizes = if state == "verified-awaiting-reboot" {
        let image = &value["image"];
        let size = |key: &str| image[key].as_u64().and_then(|v| u32::try_from(v).ok());
        Some([size("kernel_bytes")?, size("rootfs_bytes")?, size("modem_bytes")?])
    } else {
        None
    };
    Some(Marker {
        source: "titan-api",
        fingerprint: format!("titan-api:{}", sha256::hex(&sha256::digest(text.as_bytes()))),
        target,
        sizes,
        install: None,
    })
}

/// `titan-pd-keeper bank-guard arm`, run by an updater after its write and
/// before its reboot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmRecord {
    pub target: u8,
    pub install: Install,
    pub boot_id: String,
}

pub fn arm_marker(record: &ArmRecord, boot_id: &str) -> Option<Marker> {
    // Written in this boot: the reboot that tests it has not happened yet.
    if record.target > 1 || record.boot_id.trim() == boot_id.trim() || record.boot_id.trim().is_empty() {
        return None;
    }
    Some(Marker {
        source: "arm",
        fingerprint: format!("arm:{}:{}", record.boot_id.trim(), install_text(&record.install)),
        target: record.target as usize,
        sizes: None,
        install: Some(record.install),
    })
}

/// `witcher-state` creates the data volume on the first Witcher boot after a
/// stock flash, and records that boot's id. The stock updater leaves no other
/// trace.
pub fn first_boot_marker(created_boot_id: &str, boot_id: &str, running: usize) -> Option<Marker> {
    let created = created_boot_id.trim();
    (!created.is_empty() && created == boot_id.trim()).then(|| Marker {
        source: "first-witcher-boot",
        fingerprint: format!("first-witcher-boot:{created}"),
        target: running,
        sizes: None,
        install: None,
    })
}

fn install_text(install: &Install) -> String {
    let p = install.image.parts;
    format!(
        "{}/{:08x}/{} {}/{:08x}/{} {}/{:08x}/{}",
        p[0].0, p[0].1, install.seqs[0], p[1].0, p[1].1, install.seqs[1], p[2].0, p[2].1, install.seqs[2]
    )
}

/// A bank the guard saw prove itself, or the bank an updater ran on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownGood {
    pub bank: u8,
    pub image: Image,
    /// `confirmed`: this guard saw it answer. Kept across switches.
    pub how: String,
}

/// One update under watch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub source: String,
    pub marker: String,
    pub target: u8,
    pub fallback: u8,
    pub install: Install,
    pub fallback_image: Image,
    /// The fallback is the bank this guard last confirmed. When false, the
    /// fallback only proved it could run the updater.
    pub fallback_confirmed: bool,
    pub boots: u32,
    pub switches: u32,
    /// `None` while open, else `confirmed`, `rolled-back`, `switched-away`,
    /// `replaced`, `gave-up`, `refused`, `nv-mismatch` or `nv-changed`.
    pub outcome: Option<String>,
    pub detail: String,
}

impl Session {
    pub fn open(&self) -> bool {
        self.outcome.is_none()
    }
}

/// `/mnt/titan-api/bank-guard/state.json`. Missing fields load as empty, so
/// an older or partial file is read, not refused.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub version: u32,
    pub known_good: Option<KnownGood>,
    pub session: Option<Session>,
    /// Markers already used, newest last.
    pub consumed: Vec<String>,
    /// Closed sessions and other events, newest last.
    pub history: Vec<String>,
}

impl State {
    fn remember(&mut self, line: String) {
        self.history.push(line);
        let excess = self.history.len().saturating_sub(MAX_HISTORY);
        self.history.drain(..excess);
    }

    fn consume(&mut self, fingerprint: &str) {
        self.consumed.retain(|f| f != fingerprint);
        self.consumed.push(fingerprint.to_owned());
        let excess = self.consumed.len().saturating_sub(MAX_CONSUMED);
        self.consumed.drain(..excess);
    }

    fn close(&mut self, outcome: &str, detail: String) {
        if let Some(session) = self.session.as_mut().filter(|s| s.open()) {
            session.outcome = Some(outcome.to_owned());
            session.detail = detail.clone();
            let line = format!(
                "{outcome}: update to bank {} ({}) after {} boot(s), {} switch(es): {detail}",
                session.target, session.source, session.boots, session.switches
            );
            self.remember(line);
        }
    }

    /// The bank that proved itself, if `table` still holds what it proved.
    pub fn confirmed_bank(&self, table: &Table) -> Option<usize> {
        self.known_good
            .as_ref()
            .filter(|k| k.bank < 2 && table.image(k.bank as usize) == k.image)
            .map(|k| k.bank as usize)
    }
}

/// What the guard does this boot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Not armed. Watch only to record the running bank as known good.
    Idle,
    /// Armed: confirm before the deadline or switch back.
    Watch,
    /// Switch back now.
    SwitchNow(String),
    /// Nothing more this boot.
    Stop(String),
}

/// The boot facts, read and cross-checked by the caller: the bank booted
/// (`/proc/cmdline`), NV item 23 as the vendor library and the raw `cmnnv`
/// flash both show it (`None` if they disagree or cannot be read), and the
/// markers found.
pub struct Boot<'a> {
    pub running: usize,
    pub table: Option<&'a Table>,
    pub markers: &'a [Marker],
}

/// Decide this boot. Changes `state` in memory; the caller writes it, and
/// must not act on `Watch` or `SwitchNow` unless that write succeeded and read
/// back, because the boot and switch counters are what bound the loop.
pub fn on_boot(state: &mut State, boot: &Boot) -> (Plan, Vec<String>) {
    let mut notes = Vec::new();
    let running = boot.running;
    let Some(table) = boot.table else {
        if state.session.as_ref().is_some_and(Session::open) {
            notes.push("bank guard: cannot read the bank table both ways; the open update is left as it is this boot".into());
        }
        return (Plan::Stop("bank table unreadable or views disagree".into()), notes);
    };
    let selected = match table.selected() {
        Ok(bank) => bank,
        Err(err) => {
            state.close("nv-mismatch", format!("the bank table is not usable at boot: {err}"));
            notes.push(format!("bank guard: the bank table is not usable ({err}); not arming"));
            return (Plan::Stop(err), notes);
        }
    };
    if selected != running {
        // The boot code did not take the bank the table names. Nothing the
        // guard knows about bank selection can be trusted on this unit.
        let detail = format!("booted bank {running}, but the table selects bank {selected}");
        state.close("nv-mismatch", detail.clone());
        notes.push(format!("bank guard: {detail}; never switching on this boot"));
        return (Plan::Stop(detail), notes);
    }

    if let Some(session) = state.session.clone().filter(Session::open) {
        let target = session.target as usize;
        if running == session.fallback as usize {
            let (outcome, how) = if session.switches > 0 {
                ("rolled-back", "the guard switched back")
            } else {
                ("switched-away", "someone else switched banks")
            };
            state.close(outcome, format!("running the old bank {running} again ({how})"));
            notes.push(format!("bank guard: running the old bank {running} again; {how}"));
        } else if running == target && table.install(target) != session.install {
            state.close("replaced", "a newer write replaced the watched bank".into());
            notes.push("bank guard: the watched bank was written again; closing that update".into());
        } else if running == target {
            let s = state.session.as_mut().unwrap();
            s.boots = s.boots.saturating_add(1);
            let (boots, switches) = (s.boots, s.switches);
            if switches >= MAX_SWITCHES {
                state.close("gave-up", format!("{switches} bank switches did not take effect"));
                notes.push(format!(
                    "bank guard: {switches} bank switches did not take effect; giving up on this update"
                ));
                return (Plan::Stop("gave up".into()), notes);
            }
            if switches > 0 {
                return (Plan::SwitchNow("the last bank switch did not take effect".into()), notes);
            }
            if boots >= BOOTS_BEFORE_SWITCH {
                return (
                    Plan::SwitchNow(format!("{} boots of this update ended without proof", boots - 1)),
                    notes,
                );
            }
            notes.push(format!(
                "bank guard: boot {boots} of the update to bank {target}; watching for proof"
            ));
            return (Plan::Watch, notes);
        }
    }

    // No open update. A fresh marker for the running bank arms one.
    for marker in boot.markers {
        if state.consumed.iter().any(|f| f == &marker.fingerprint) || marker.target != running {
            continue;
        }
        let install = table.install(running);
        if marker.sizes.is_some_and(|sizes| sizes != install.image.parts.map(|p| p.0)) {
            notes.push(format!(
                "bank guard: the {} marker does not match the running bank's sizes; not arming",
                marker.source
            ));
            state.consume(&marker.fingerprint);
            continue;
        }
        if marker.install.is_some_and(|recorded| recorded != install) {
            notes.push(format!(
                "bank guard: the {} marker names another write of bank {running}; not arming",
                marker.source
            ));
            state.consume(&marker.fingerprint);
            continue;
        }
        let fallback = 1 - running;
        let fallback_image = table.image(fallback);
        let fallback_confirmed = state.confirmed_bank(table) == Some(fallback);
        if !fallback_confirmed {
            let lost = state
                .known_good
                .as_ref()
                .is_some_and(|k| k.bank as usize == running && k.image != install.image);
            notes.push(if lost {
                "bank guard: warning: this update overwrote the last confirmed bank; the old bank only proved it could run the updater".into()
            } else {
                "bank guard: the old bank has no confirmed boot on record; it proved it could run the updater".into()
            });
        }
        state.consume(&marker.fingerprint);
        state.session = Some(Session {
            source: marker.source.to_owned(),
            marker: marker.fingerprint.clone(),
            target: running as u8,
            fallback: fallback as u8,
            install,
            fallback_image,
            fallback_confirmed,
            boots: 1,
            switches: 0,
            outcome: None,
            detail: String::new(),
        });
        notes.push(format!(
            "bank guard: armed by {}: first boot of bank {running}; without proof the guard switches back to bank {fallback}",
            marker.source
        ));
        return (Plan::Watch, notes);
    }
    (Plan::Idle, notes)
}

/// Record a proof. Armed: closes the update. Either way the running bank
/// becomes the known good one. Returns true when `state` changed.
pub fn on_confirmed(state: &mut State, table: &Table, running: usize) -> bool {
    let before = state.clone();
    if state
        .session
        .as_ref()
        .is_some_and(|s| s.open() && s.target as usize == running)
    {
        state.close("confirmed", "management answered through the core and the keeper stayed up".into());
    }
    state.known_good = Some(KnownGood {
        bank: running as u8,
        image: table.image(running),
        how: "confirmed".into(),
    });
    *state != before
}

/// Count a switch attempt before making it.
pub fn on_switching(state: &mut State) -> bool {
    match state.session.as_mut().filter(|s| s.open()) {
        Some(session) => {
            session.switches = session.switches.saturating_add(1);
            true
        }
        None => false,
    }
}

/// Refuse a switch and stop watching this update.
pub fn on_refused(state: &mut State, why: &str) {
    state.close("refused", why.to_owned());
}

/// What one round of checks saw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Round {
    /// Uptime in seconds.
    pub uptime: u64,
    /// The management bearer has carrier and an IPv4 or global IPv6 address.
    pub mgmt_up: bool,
    /// One target answered this round. `None`: no targets to ask.
    pub heard: Option<bool>,
    /// The keeper process that started this boot, if one is running.
    pub keeper_pid: Option<u32>,
    /// The customer bearer passed its check (true when not required).
    pub customer_ok: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Hold,
    Confirmed,
    Expired,
}

/// The proof window of one boot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirm {
    pub deadline: u64,
    rounds: u32,
    keeper: Option<(u32, u64)>,
}

impl Confirm {
    pub fn new(confirm_secs: u64) -> Self {
        Self {
            deadline: confirm_secs,
            rounds: 0,
            keeper: None,
        }
    }

    /// Proof is all of: management address, an answer, the customer check,
    /// and the same keeper process seen at least `KEEPER_STABLE` seconds
    /// apart. The window expires only after two rounds by this process, so a
    /// guard that starts late still looks before it acts.
    pub fn observe(&mut self, round: Round) -> Verdict {
        self.rounds = self.rounds.saturating_add(1);
        let keeper_stable = match (round.keeper_pid, self.keeper) {
            (Some(pid), Some((seen, since))) if pid == seen => round.uptime.saturating_sub(since) >= KEEPER_STABLE,
            (Some(pid), _) => {
                self.keeper = Some((pid, round.uptime));
                false
            }
            (None, _) => {
                self.keeper = None;
                false
            }
        };
        if round.mgmt_up && round.heard == Some(true) && round.customer_ok && keeper_stable {
            return Verdict::Confirmed;
        }
        if round.uptime >= self.deadline && self.rounds >= 2 {
            return Verdict::Expired;
        }
        Verdict::Hold
    }

    pub fn keeper_stable_since(&self) -> Option<u64> {
        self.keeper.map(|(_, since)| since)
    }
}

/// Before an updater writes the inactive bank. `Err` means refuse.
pub fn preflight(state: &State, table: &Table, running: usize) -> Result<Vec<String>, String> {
    let selected = table.selected()?;
    if selected != running {
        return Err(format!(
            "the table already selects bank {selected} for the next boot; restart and confirm it first"
        ));
    }
    let inactive = 1 - running;
    if let Some(session) = state.session.as_ref().filter(|s| s.open()) {
        return Err(format!(
            "the update to bank {} has not proved itself yet (boot {}); wait for the boot confirm",
            session.target, session.boots
        ));
    }
    let mut notes = Vec::new();
    match state.confirmed_bank(table) {
        Some(bank) if bank == running => {}
        Some(_) => {
            return Err(format!(
                "bank {inactive} holds the last confirmed image and bank {running} has no confirmed boot; an update now would leave no confirmed image"
            ));
        }
        None => notes.push("no confirmed image on record; the guard has not seen this unit prove a bank".into()),
    }
    if table.image(inactive) == STOCK_4172 && table.image(running) != STOCK_4172 {
        notes.push(format!(
            "bank {inactive} holds the only stock 4172 image; after this update a return to stock needs a stock .prg upload"
        ));
    }
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NV item 23 read from a Titan 4000 (`nv_read(23, buf, 0, 360)`) during a
    /// return-to-stock audit on 2026-10-15. Bank 0 is selected (kernel 27 over
    /// 26, rootfs 54 over 52, modem 55 over 53). Its kernel and modem records
    /// match the stock 4172 image, and both checksums match the raw partition
    /// dumps taken at the same time.
    const CAPTURED: &str = "da0642a4bebafeca240000001b0000009f68f932a8582900000000000000000000000000\
c9061ba3bebafeca240000001a000000fa4d2f9cb858290000000000000000000000000\
05e0744adbebafeca2400000036000000a2b994f80000dc010000000000000000000000\
00d3053891bebafeca2400000034000000117ea04d0000be01000000000000000000000\
00063074baabebafeca240000003700000004986e9cdffd460000000000000000000000\
000061071baabebafeca240000003500000004986e9cdffd4600000000000000000000000000";

    fn captured() -> Table {
        let mut bytes = (0..CAPTURED.len() / 2)
            .map(|i| u8::from_str_radix(&CAPTURED[i * 2..i * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>();
        bytes.resize(TABLE, 0);
        Table::from_bytes(&bytes).unwrap()
    }

    fn synthetic(seqs: [[u32; 2]; 3]) -> Table {
        let mut bytes = [0u8; TABLE];
        for part in 0..3 {
            for bank in 0..2 {
                let o = (part * 2 + bank) * RECORD;
                let size = [2_709_672u32, 31_195_136, 4_652_511][part] - bank as u32;
                for (off, v) in [(4, MAGIC), (8, 36), (12, seqs[part][bank]), (16, 0x1234_5678 + part as u32), (20, size)] {
                    bytes[o + off..o + off + 4].copy_from_slice(&v.to_le_bytes());
                }
                let sum = adler0(&bytes[o + 4..o + RECORD]);
                bytes[o..o + 4].copy_from_slice(&sum.to_le_bytes());
            }
        }
        Table { bytes }
    }

    #[test]
    fn adler_is_the_vendor_seed_zero_variant() {
        assert_eq!(adler0(b""), 0);
        // zlib's adler32 starts at 1: "abc" is 0x024d0127 there.
        assert_eq!(adler0(b"abc"), 0x024a_0126);
        let big = vec![0xffu8; 100_000];
        let mut split = Adler::default();
        split.update(&big[..33_333]);
        split.update(&big[33_333..]);
        assert_eq!(split.finish(), adler0(&big));
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn captured_table_parses_and_selects_bank_0() {
        let table = captured();
        table.check().unwrap();
        assert_eq!(table.selected().unwrap(), 0);
        assert_eq!(table.record(0, 0), Record { seq: 27, adler: 0x32f9_689f, size: 2_709_672 });
        assert_eq!(table.record(2, 1).seq, 53);
        assert_eq!(table.image(0).parts[0], STOCK_4172.parts[0]);
        assert_eq!(table.image(0).parts[2], STOCK_4172.parts[2]);
        assert_ne!(table.image(0), STOCK_4172, "bank 0 held a Witcher root filesystem");
        assert!(table.bytes[RECORD * 6..].iter().all(|&b| b == 0));
    }

    #[test]
    fn select_raises_only_the_old_bank_and_is_idempotent() {
        let table = captured();
        let flipped = table.select(1, 0).unwrap();
        assert_eq!(flipped.selected().unwrap(), 1);
        assert_eq!(
            [0, 1, 2].map(|p| flipped.record(p, 1).seq),
            [28, 55, 56],
            "each part goes one above the bank it leaves"
        );
        for part in 0..3 {
            assert_eq!(flipped.record(part, 0), table.record(part, 0), "the bad bank is not touched");
            assert_eq!(flipped.record(part, 1).adler, table.record(part, 1).adler);
            assert_eq!(flipped.record(part, 1).size, table.record(part, 1).size);
        }
        assert!(flipped.changed_only(&table, 1));
        assert!(!flipped.changed_only(&table, 0));
        assert_eq!(flipped.bytes[RECORD * 6..], table.bytes[RECORD * 6..]);
        // Selecting what is already selected writes nothing new.
        assert_eq!(flipped.select(1, 0).unwrap(), flipped);
        assert_eq!(table.select(0, 0).unwrap(), table);
        // A retry gives different bytes that still select the same bank.
        let retry = flipped.select(1, 1).unwrap();
        assert_ne!(retry, flipped);
        assert_eq!(retry.selected().unwrap(), 1);
        assert_eq!(retry.record(0, 1).seq, 30);
    }

    #[test]
    fn select_repairs_a_split_table_in_one_write() {
        // A torn vendor toggle: kernel already on bank 1, the rest on bank 0.
        let split = synthetic([[5, 6], [9, 3], [9, 3]]);
        assert!(split.selected().is_err());
        let one = split.select(1, 0).unwrap();
        assert_eq!(one.selected().unwrap(), 1);
        assert_eq!(one.record(0, 1).seq, 6, "the kernel record was already right");
        assert_eq!(one.record(1, 1).seq, 10);
        let zero = split.select(0, 0).unwrap();
        assert_eq!(zero.selected().unwrap(), 0);
        assert_eq!(zero.record(0, 0).seq, 7);
    }

    #[test]
    fn select_refuses_damaged_or_exhausted_tables() {
        let mut bad = captured();
        bad.bytes[RECORD + 12] ^= 1; // linux2 sequence without a new checksum
        assert!(bad.check().unwrap_err().contains("linux2"));
        assert!(bad.select(1, 0).is_err());
        let mut magic = captured();
        magic.bytes[4] = 0;
        assert!(magic.select(1, 0).is_err());
        let mut empty = captured();
        empty.bytes[2 * RECORD + 20..2 * RECORD + 24].fill(0);
        let sum = adler0(&empty.bytes[2 * RECORD + 4..3 * RECORD]);
        empty.bytes[2 * RECORD..2 * RECORD + 4].copy_from_slice(&sum.to_le_bytes());
        assert!(empty.check().unwrap_err().contains("size 0"));
        assert!(synthetic([[u32::MAX - 1, 1], [3, 1], [3, 1]]).select(1, 0).is_err());
        assert!(synthetic([[4, 4], [3, 1], [3, 1]]).selected().is_err());
        assert!(Table::from_bytes(&[0; 359]).is_err());
    }

    fn cmn_block(seq: u32, table: &Table, fill: u8) -> Vec<u8> {
        let mut block = vec![fill; ERASE];
        block[CMN_WRAPPER..CMN_WRAPPER + TABLE].copy_from_slice(&table.bytes);
        for (off, v) in [(4, MAGIC), (8, 36), (12, seq), (20, (ERASE - CMN_WRAPPER) as u32)] {
            block[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
        let payload = adler0(&block[CMN_WRAPPER..]);
        block[16..20].copy_from_slice(&payload.to_le_bytes());
        let sum = adler0(&block[4..CMN_WRAPPER]);
        block[..4].copy_from_slice(&sum.to_le_bytes());
        block
    }

    #[test]
    fn cmn_copy_selection_follows_the_kernel() {
        let old = captured();
        let new = old.select(1, 0).unwrap();
        let a = cmn_block(7, &old, 0x00);
        let b = cmn_block(8, &new, 0x00);
        assert_eq!(cmn_select([Some(&a[..]), Some(&b[..])]).unwrap(), (1, new.clone()));
        assert_eq!(cmn_select([Some(&b[..]), Some(&a[..])]).unwrap(), (0, new.clone()));
        // Equal sequence numbers: the kernel takes the second copy.
        let a8 = cmn_block(8, &old, 0x00);
        assert_eq!(cmn_select([Some(&b[..]), Some(&a8[..])]).unwrap().0, 1);
        // A torn write: the header landed, the block did not. The old copy wins.
        let mut torn = b.clone();
        torn[ERASE / 2..].fill(0xff);
        assert!(cmn_copy(&torn).unwrap_err().contains("torn"));
        assert_eq!(cmn_select([Some(&a[..]), Some(&torn[..])]).unwrap(), (0, old.clone()));
        // An erased block.
        let erased = vec![0xffu8; ERASE];
        assert_eq!(cmn_select([Some(&erased[..]), Some(&a[..])]).unwrap(), (1, old.clone()));
        // A stored block checksum of 0 is accepted, as the kernel accepts it.
        let mut zero = a.clone();
        zero[16..20].fill(0);
        let sum = adler0(&zero[4..CMN_WRAPPER]);
        zero[..4].copy_from_slice(&sum.to_le_bytes());
        assert!(cmn_copy(&zero).is_ok());
        assert!(cmn_select([Some(&erased[..]), Some(&erased[..])]).is_err());
        assert!(cmn_select([None, None]).is_err());
        assert_eq!(cmn_copy_blocks(&[false; 8]), Some([1, 2]));
        assert_eq!(cmn_copy_blocks(&[true, false, true, false, false]), Some([3, 4]));
        assert_eq!(cmn_copy_blocks(&[false, true, true, false]), None);
    }

    #[test]
    fn running_bank_matches_the_mounted_root() {
        assert_eq!(running_bank("console=x ubi.mtd=15,2048 active=linux,rootfs,tk").unwrap(), 0);
        assert_eq!(running_bank("ubi.mtd=16,2048 active=linux2,rootfs2,tk2").unwrap(), 1);
        assert!(running_bank("ubi.mtd=15,2048 active=linux2,rootfs2,tk2").is_err());
        assert!(running_bank("ubi.mtd=15,2048 active=linux,rootfs2,tk").is_err());
        assert!(running_bank("").is_err());
        let proc_mtd = expected_mtd_lines().into_iter().map(|(_, l)| l).collect::<Vec<_>>().join("\n");
        assert!(mtd_layout_ok(&proc_mtd).is_ok());
        assert!(mtd_layout_ok(&proc_mtd.replace("\"tk2\"", "\"other\"")).is_err());
    }

    fn uimage(size: u32) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
        h[12..16].copy_from_slice(&(size - 64).to_be_bytes());
        let crc = crc32(&h);
        h[4..8].copy_from_slice(&crc.to_be_bytes());
        h
    }

    #[test]
    fn kernel_and_modem_headers() {
        let h = uimage(2_709_672);
        assert!(kernel_header_ok(&h, 2_709_672).is_ok());
        assert!(kernel_header_ok(&h, 2_709_688).is_err());
        let mut bad = h.clone();
        bad[20] ^= 1;
        assert!(kernel_header_ok(&bad, 2_709_672).unwrap_err().contains("CRC"));
        assert!(modem_header_ok(&[0x1f, 0x8b, 0x08, 0x00]).is_ok());
        assert!(modem_header_ok(&[0x1f, 0x8b, 0x08, 0x02]).is_err());
        assert!(modem_header_ok(&[0x1f, 0x8b, 0x09, 0x00]).is_err());
    }

    fn ubi_header(magic: &[u8; 4], fields: &[(usize, u32)]) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(magic);
        h[4] = 1;
        for &(off, v) in fields {
            h[off..off + 4].copy_from_slice(&v.to_be_bytes());
        }
        let crc = crc32_raw(!0, &h[..60]);
        h[60..].copy_from_slice(&crc.to_be_bytes());
        h
    }

    fn volume_record() -> Vec<u8> {
        let mut r = vec![0u8; 172];
        r[14..16].copy_from_slice(&6u16.to_be_bytes());
        r[16..22].copy_from_slice(b"rootfs");
        let crc = crc32_raw(!0, &r[..168]);
        r[168..].copy_from_slice(&crc.to_be_bytes());
        r
    }

    fn healthy_bank() -> UbiTally {
        let ec = ubi_header(b"UBI#", &[(16, 2048), (20, 4096)]);
        let mut tally = UbiTally::default();
        for copy in 0..2 {
            let vid = ubi_header(b"UBI!", &[(8, UBI_LAYOUT_VOLUME), (12, copy)]);
            tally.add(copy as usize, &ec, Some(&vid[..]), Some(&volume_record()[..]));
        }
        for lnum in 0..3u32 {
            let vid = ubi_header(b"UBI!", &[(8, 0), (12, lnum)]);
            tally.add(2 + lnum as usize, &ec, Some(&vid[..]), Some(&[0x31u8, 0x18, 0x10, 0x06][..]));
        }
        tally.add(5, &ec, Some(&[0xffu8; 64][..]), None);
        tally.add(6, &[0xff; 64], None, None);
        tally
    }

    #[test]
    fn ubi_bank_structure() {
        let tally = healthy_bank();
        assert_eq!((tally.used, tally.free, tally.erased), (5, 1, 1));
        assert!(tally.verdict().is_ok());
        let mut damaged = healthy_bank();
        let mut ec = ubi_header(b"UBI#", &[(16, 2048), (20, 4096)]);
        ec[30] ^= 1;
        damaged.add(7, &ec, None, None);
        assert!(damaged.verdict().unwrap_err().contains("PEB 7"));
        let mut vid_bad = healthy_bank();
        let mut vid = ubi_header(b"UBI!", &[(8, 0), (12, 9)]);
        vid[20] ^= 1;
        vid_bad.add(8, &ubi_header(b"UBI#", &[(16, 2048), (20, 4096)]), Some(&vid[..]), None);
        assert!(vid_bad.verdict().is_err());
        let mut missing = UbiTally::default();
        let ec = ubi_header(b"UBI#", &[(16, 2048), (20, 4096)]);
        for copy in 0..2 {
            let vid = ubi_header(b"UBI!", &[(8, UBI_LAYOUT_VOLUME), (12, copy)]);
            missing.add(copy as usize, &ec, Some(&vid[..]), Some(&volume_record()[..]));
        }
        assert!(missing.verdict().unwrap_err().contains("0 to 2"));
        let mut wrong = volume_record();
        wrong[16] = b'R';
        assert!(!volume_table_names_rootfs(&wrong));
        assert!(ubi_ec(&ubi_header(b"UBI#", &[(16, 2048), (20, 1024)])).is_err());
    }

    #[test]
    fn settings_parse_with_bounds() {
        let s = parse_settings("enabled=0\nconfirm_secs=60\ntarget=192.0.2.1\ntarget=bogus\nrequire_customer=1\ncustomer_target=2001:db8::1\n");
        assert!(!s.enabled);
        assert_eq!(s.confirm_secs, 300);
        assert_eq!(s.targets.len(), 1);
        assert!(s.require_customer);
        assert_eq!(s.customer_targets.len(), 1);
        assert_eq!(parse_settings("confirm_secs=99999").confirm_secs, 1800);
        assert_eq!(parse_settings("").confirm_secs, CONFIRM_SECS);
    }

    const OP: &str = r#"{"state":"verified-awaiting-reboot","target_bank":1,"image":{"build":4172,"kernel_bytes":2709671,"rootfs_bytes":31195135,"modem_bytes":4652510}}"#;

    #[test]
    fn titan_api_markers() {
        let m = titan_api_marker(OP).unwrap();
        assert_eq!((m.target, m.sizes), (1, Some([2_709_671, 31_195_135, 4_652_510])));
        assert!(titan_api_marker(&OP.replace("verified-awaiting-reboot", "writing")).is_none());
        assert!(titan_api_marker(&OP.replace("verified-awaiting-reboot", "uncertain")).is_none());
        assert!(titan_api_marker(&OP.replace("\"target_bank\":1", "\"target_bank\":2")).is_none());
        let switch = titan_api_marker(r#"{"state":"selected-awaiting-reboot","target_bank":0}"#).unwrap();
        assert_eq!((switch.target, switch.sizes), (0, None));
        assert!(titan_api_marker("garbage").is_none());
        assert_ne!(titan_api_marker(OP).unwrap().fingerprint, switch.fingerprint);
    }

    fn arm_record(table: &Table, bank: usize, boot: &str) -> ArmRecord {
        ArmRecord { target: bank as u8, install: table.install(bank), boot_id: boot.into() }
    }

    #[test]
    fn arm_and_first_boot_markers() {
        let table = synthetic([[1, 2], [1, 2], [1, 2]]);
        let record = arm_record(&table, 1, "boot-a");
        assert!(arm_marker(&record, "boot-a").is_none(), "not before the reboot");
        let m = arm_marker(&record, "boot-b").unwrap();
        assert_eq!(m.install, Some(table.install(1)));
        assert!(first_boot_marker("boot-b\n", "boot-b", 1).is_some());
        assert!(first_boot_marker("boot-a", "boot-b", 1).is_none());
        assert!(first_boot_marker("", "", 1).is_none());
    }

    /// The flash of a fake unit: what the boot code would take after each step.
    struct Unit {
        table: Table,
        state: State,
    }

    impl Unit {
        fn boot(&mut self, markers: &[Marker]) -> Plan {
            let running = self.table.selected().unwrap();
            let (plan, _) = on_boot(&mut self.state, &Boot { running, table: Some(&self.table), markers });
            plan
        }
    }

    /// A unit on bank 0 (confirmed by the guard) that titan-api updated into
    /// bank 1.
    fn updated_unit() -> (Unit, Marker) {
        let before = synthetic([[10, 9], [10, 9], [10, 9]]);
        let mut state = State::default();
        assert!(on_confirmed(&mut state, &before, 0));
        let after = before.select(1, 0).unwrap();
        let marker = titan_api_marker(&format!(
            r#"{{"state":"verified-awaiting-reboot","target_bank":1,"image":{{"kernel_bytes":{},"rootfs_bytes":{},"modem_bytes":{}}}}}"#,
            after.record(0, 1).size,
            after.record(1, 1).size,
            after.record(2, 1).size
        ))
        .unwrap();
        (Unit { table: after, state }, marker)
    }

    #[test]
    fn never_arms_without_a_fresh_marker() {
        let (mut unit, marker) = updated_unit();
        assert_eq!(unit.boot(&[]), Plan::Idle);
        assert!(unit.state.session.is_none());
        // A marker for the other bank (the update boot itself) does nothing.
        let mut other = marker.clone();
        other.target = 0;
        assert_eq!(unit.boot(&[other]), Plan::Idle);
        // Wrong sizes: consumed, not armed.
        let mut sizes = marker.clone();
        sizes.sizes = Some([1, 2, 3]);
        assert_eq!(unit.boot(&[sizes.clone()]), Plan::Idle);
        assert_eq!(unit.boot(&[sizes]), Plan::Idle);
        assert!(unit.state.session.is_none());
    }

    #[test]
    fn confirmed_update_closes_and_moves_known_good() {
        let (mut unit, marker) = updated_unit();
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Watch);
        let s = unit.state.session.clone().unwrap();
        assert_eq!((s.target, s.fallback, s.boots, s.fallback_confirmed), (1, 0, 1, true));
        assert!(on_confirmed(&mut unit.state, &unit.table, 1));
        assert_eq!(unit.state.session.as_ref().unwrap().outcome.as_deref(), Some("confirmed"));
        assert_eq!(unit.state.known_good.as_ref().unwrap().bank, 1);
        // The same marker never arms again, on any later boot.
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Idle);
        assert_eq!(unit.boot(&[marker]), Plan::Idle);
        assert!(!on_confirmed(&mut unit.state, &unit.table, 1), "an unchanged proof writes nothing");
    }

    #[test]
    fn failed_update_switches_back_once_and_stays_back() {
        let (mut unit, marker) = updated_unit();
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Watch);
        // The window expired: count the switch, then write the table.
        assert!(on_switching(&mut unit.state));
        unit.table = unit.table.select(0, 0).unwrap();
        // Reboot: the boot code now takes bank 0.
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Idle);
        let s = unit.state.session.clone().unwrap();
        assert_eq!(s.outcome.as_deref(), Some("rolled-back"));
        assert_eq!(unit.state.known_good.as_ref().unwrap().bank, 0, "still the old bank");
        // Later boots of bank 0 never switch, even with the marker still on disk.
        for _ in 0..5 {
            assert_eq!(unit.boot(&[marker.clone()]), Plan::Idle);
        }
    }

    #[test]
    fn a_switch_that_did_not_land_is_retried_once_then_abandoned() {
        let (mut unit, marker) = updated_unit();
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Watch);
        assert!(on_switching(&mut unit.state));
        // The write did not reach flash: bank 1 boots again.
        assert!(matches!(unit.boot(&[marker.clone()]), Plan::SwitchNow(_)));
        assert!(on_switching(&mut unit.state));
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Stop("gave up".into()));
        assert_eq!(unit.state.session.as_ref().unwrap().outcome.as_deref(), Some("gave-up"));
        for _ in 0..5 {
            assert_eq!(unit.boot(&[marker.clone()]), Plan::Idle, "never acts again on this update");
        }
    }

    #[test]
    fn a_reboot_loop_on_the_new_bank_switches_on_the_third_boot() {
        let (mut unit, marker) = updated_unit();
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Watch);
        // The new image reboots by itself before the window ends, twice.
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Watch);
        let plan = unit.boot(&[marker.clone()]);
        assert_eq!(plan, Plan::SwitchNow("2 boots of this update ended without proof".into()));
        assert_eq!(unit.state.session.as_ref().unwrap().boots, 3);
    }

    #[test]
    fn guard_reboots_are_bounded_whatever_happens() {
        // Worst case: no write ever lands, and every boot dies early.
        let (mut unit, marker) = updated_unit();
        let mut guard_reboots = 0;
        for _ in 0..20 {
            match unit.boot(&[marker.clone()]) {
                Plan::SwitchNow(_) => {
                    assert!(on_switching(&mut unit.state));
                    guard_reboots += 1;
                }
                Plan::Watch => {
                    // Half the boots die before the window, half expire.
                    if unit.state.session.as_ref().unwrap().boots % 2 == 0 {
                        assert!(on_switching(&mut unit.state));
                        guard_reboots += 1;
                    }
                }
                Plan::Idle | Plan::Stop(_) => {}
            }
        }
        assert!(guard_reboots <= 3, "{guard_reboots} guard reboots");
        assert!(!unit.state.session.as_ref().unwrap().open());
    }

    #[test]
    fn a_boot_the_table_does_not_explain_never_switches() {
        let (mut unit, marker) = updated_unit();
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Watch);
        // The table says bank 0, yet bank 1 booted.
        let table = unit.table.select(0, 0).unwrap();
        let (plan, notes) = on_boot(&mut unit.state, &Boot { running: 1, table: Some(&table), markers: &[marker] });
        assert!(matches!(plan, Plan::Stop(_)));
        assert!(notes[0].contains("never switching"));
        assert_eq!(unit.state.session.as_ref().unwrap().outcome.as_deref(), Some("nv-mismatch"));
    }

    #[test]
    fn unreadable_or_disagreeing_views_never_arm() {
        let (mut unit, marker) = updated_unit();
        let (plan, _) = on_boot(&mut unit.state, &Boot { running: 1, table: None, markers: &[marker.clone()] });
        assert!(matches!(plan, Plan::Stop(_)));
        assert!(unit.state.session.is_none());
        assert!(!unit.state.consumed.contains(&marker.fingerprint), "the marker waits for a readable boot");
    }

    #[test]
    fn a_new_write_of_the_watched_bank_replaces_the_session() {
        let (mut unit, marker) = updated_unit();
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Watch);
        unit.table = unit.table.select(1, 3).unwrap();
        assert_eq!(unit.boot(&[marker]), Plan::Idle);
        assert_eq!(unit.state.session.as_ref().unwrap().outcome.as_deref(), Some("replaced"));
    }

    #[test]
    fn first_witcher_boot_arms_against_the_stock_bank() {
        let table = synthetic([[1, 2], [1, 2], [1, 2]]);
        let mut unit = Unit { table, state: State::default() };
        let marker = first_boot_marker("b1", "b1", 1).unwrap();
        assert_eq!(unit.boot(&[marker.clone()]), Plan::Watch);
        let s = unit.state.session.clone().unwrap();
        assert_eq!((s.source.as_str(), s.fallback, s.fallback_confirmed), ("first-witcher-boot", 0, false));
    }

    #[test]
    fn update_over_the_last_confirmed_bank_is_flagged() {
        // Confirmed on bank 1; then an update from an unconfirmed bank 0 wrote bank 1.
        let before = synthetic([[1, 2], [1, 2], [1, 2]]);
        let mut state = State::default();
        on_confirmed(&mut state, &before, 1);
        let mut moved = before.select(0, 0).unwrap();
        // Bank 1 gets a new image.
        let o = 2 * RECORD + RECORD;
        moved.bytes[o + 16] ^= 0x55;
        let sum = adler0(&moved.bytes[o + 4..o + RECORD]);
        moved.bytes[o..o + 4].copy_from_slice(&sum.to_le_bytes());
        let updated = moved.select(1, 0).unwrap();
        let mut unit = Unit { table: updated, state };
        let marker = first_boot_marker("b9", "b9", 1).unwrap();
        let running = unit.table.selected().unwrap();
        let (plan, notes) = on_boot(&mut unit.state, &Boot { running, table: Some(&unit.table), markers: &[marker] });
        assert_eq!(plan, Plan::Watch);
        assert!(notes.iter().any(|n| n.contains("overwrote the last confirmed bank")));
        assert!(!unit.state.session.unwrap().fallback_confirmed);
    }

    fn round(uptime: u64, mgmt: bool, heard: Option<bool>, pid: Option<u32>) -> Round {
        Round { uptime, mgmt_up: mgmt, heard, keeper_pid: pid, customer_ok: true }
    }

    #[test]
    fn confirm_needs_every_proof_and_a_stable_keeper() {
        let mut c = Confirm::new(600);
        assert_eq!(c.observe(round(40, true, Some(true), Some(7))), Verdict::Hold, "keeper just seen");
        assert_eq!(c.observe(round(55, true, Some(true), Some(7))), Verdict::Hold);
        assert_eq!(c.observe(round(70, true, Some(true), Some(7))), Verdict::Confirmed);
        // A restarting keeper resets the clock.
        let mut c = Confirm::new(600);
        c.observe(round(40, true, Some(true), Some(7)));
        assert_eq!(c.observe(round(80, true, Some(true), Some(8))), Verdict::Hold);
        assert_eq!(c.observe(round(95, true, Some(true), None)), Verdict::Hold);
        // No address, no answer, no targets, or no customer: no proof.
        let mut c = Confirm::new(600);
        c.observe(round(10, true, Some(true), Some(7)));
        assert_eq!(c.observe(round(50, false, Some(true), Some(7))), Verdict::Hold);
        assert_eq!(c.observe(round(60, true, Some(false), Some(7))), Verdict::Hold);
        assert_eq!(c.observe(round(70, true, None, Some(7))), Verdict::Hold);
        let mut r = round(80, true, Some(true), Some(7));
        r.customer_ok = false;
        assert_eq!(c.observe(r), Verdict::Hold);
        assert_eq!(c.observe(round(90, true, Some(true), Some(7))), Verdict::Confirmed);
    }

    #[test]
    fn confirm_expires_only_after_the_deadline_and_two_rounds() {
        let mut c = Confirm::new(300);
        assert_eq!(c.observe(round(299, false, Some(false), None)), Verdict::Hold);
        assert_eq!(c.observe(round(300, false, Some(false), None)), Verdict::Expired);
        // A guard that starts after the deadline still looks twice.
        let mut late = Confirm::new(300);
        assert_eq!(late.observe(round(900, false, None, None)), Verdict::Hold);
        assert_eq!(late.observe(round(915, false, None, None)), Verdict::Expired);
    }

    #[test]
    fn preflight_refuses_to_overwrite_the_last_confirmed_bank() {
        let table = synthetic([[10, 9], [10, 9], [10, 9]]);
        let mut state = State::default();
        assert!(preflight(&state, &table, 0).unwrap()[0].contains("no confirmed image"));
        on_confirmed(&mut state, &table, 0);
        assert!(preflight(&state, &table, 0).unwrap().is_empty());
        // Known good is bank 1, running bank 0 has no proof: refuse.
        let mut other = State::default();
        on_confirmed(&mut other, &table, 1);
        assert!(preflight(&other, &table, 0).unwrap_err().contains("no confirmed image"));
        // An open update: refuse.
        let (mut unit, marker) = updated_unit();
        unit.boot(&[marker]);
        assert!(preflight(&unit.state, &unit.table, 1).unwrap_err().contains("not proved itself"));
        // The table already selects the other bank: refuse.
        assert!(preflight(&state, &table.select(1, 0).unwrap(), 0).is_err());
    }

    #[test]
    fn preflight_warns_before_overwriting_the_only_stock_image() {
        let mut table = synthetic([[1, 2], [1, 2], [1, 2]]);
        for part in 0..3 {
            let o = part * 2 * RECORD;
            table.bytes[o + 16..o + 20].copy_from_slice(&STOCK_4172.parts[part].1.to_le_bytes());
            table.bytes[o + 20..o + 24].copy_from_slice(&STOCK_4172.parts[part].0.to_le_bytes());
            let sum = adler0(&table.bytes[o + 4..o + RECORD]);
            table.bytes[o..o + 4].copy_from_slice(&sum.to_le_bytes());
        }
        let mut state = State::default();
        on_confirmed(&mut state, &table, 1);
        let notes = preflight(&state, &table, 1).unwrap();
        assert!(notes.iter().any(|n| n.contains("only stock 4172")));
    }

    #[test]
    fn state_round_trips_through_json() {
        let (mut unit, marker) = updated_unit();
        unit.boot(&[marker]);
        let text = serde_json::to_string(&unit.state).unwrap();
        assert_eq!(serde_json::from_str::<State>(&text).unwrap(), unit.state);
        assert_eq!(serde_json::from_str::<State>("{}").unwrap(), State::default());
    }
}
