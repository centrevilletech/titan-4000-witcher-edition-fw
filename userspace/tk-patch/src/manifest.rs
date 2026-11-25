//! The patch manifest: Witcher's bytes and hashes, never the vendor's.
//!
//! ```text
//! # comments and blank lines are ignored
//! witcher-tk-manifest 1
//! name m1
//! base 0x84100000
//! stock 9553965 <sha256 of the stock image>
//! image 9553965 <sha256 of the patched image>
//! gzip 4655664 <sha256 of the gzip file the loader stages>
//! site 0x842d0914 4 hook1_mac_tb <sha256 of the 4 stock bytes there> 1cf199f3
//! site 0x843de954 888 img2_cave_a <sha256> <hex> @0x842d8bd1:61 <hex>
//! ```
//!
//! A site replaces `len` stock bytes at its VA. Its replacement is hex
//! (Witcher's bytes) and `@VA:LEN` references to stock bytes earlier in the
//! image, which the unit copies from its own stock firmware. The header
//! lines come first and in this order. Sites are sorted, do not overlap, sit
//! at even addresses inside the image, and every reference ends before its
//! site begins, so one pass over the stock image builds the result.

use alloc::vec::Vec;
use core::fmt;

use crate::Error;
use crate::gzip::{LOADER_MAX_BYTES, LOADER_MIN_BYTES};
use crate::sha256::{Digest, nibble};

pub const VERSION_LINE: &str = "witcher-tk-manifest 1";

/// A size and SHA-256 the build must reproduce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    pub size: u64,
    pub sha256: Digest,
}

/// One piece of a site's replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Part {
    /// Witcher's bytes.
    Bytes(Vec<u8>),
    /// `len` stock bytes from `va`, earlier in the image.
    Stock { va: u32, len: u32 },
}

impl Part {
    pub fn len(&self) -> usize {
        match self {
            Part::Bytes(b) => b.len(),
            Part::Stock { len, .. } => *len as usize,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site<'a> {
    pub va: u32,
    pub len: u32,
    pub name: &'a str,
    /// SHA-256 of the stock bytes this site replaces.
    pub original: Digest,
    pub parts: Vec<Part>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest<'a> {
    pub name: &'a str,
    /// The load VA of the image's first byte.
    pub base: u32,
    pub stock: Pin,
    pub image: Pin,
    pub gzip: Pin,
    pub sites: Vec<Site<'a>>,
}

fn is_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn hex_u32(s: &str) -> Option<u32> {
    let digits = s.strip_prefix("0x")?;
    if digits.is_empty() || digits.len() > 8 {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

fn bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    s.chunks_exact(2).map(|p| Some(nibble(p[0])? << 4 | nibble(p[1])?)).collect()
}

fn part(s: &str) -> Option<Part> {
    match s.strip_prefix('@') {
        Some(reference) => {
            let (va, len) = reference.split_once(':')?;
            let len: u32 = len.parse().ok().filter(|&n| n > 0)?;
            Some(Part::Stock { va: hex_u32(va)?, len })
        }
        None => bytes(s).map(Part::Bytes),
    }
}

impl<'a> Manifest<'a> {
    pub fn parse(text: &'a str) -> Result<Self, Error> {
        let mut lines = text
            .lines()
            .enumerate()
            .map(|(i, line)| (i + 1, line))
            .filter(|(_, line)| !line.trim().is_empty() && !line.starts_with('#'));
        let mut header = |key: &'static str, fields: usize| -> Result<(usize, Vec<&'a str>), Error> {
            let (at, line) = lines.next().ok_or(Error::Manifest(0, "the header is incomplete"))?;
            let words: Vec<&str> = line.split_ascii_whitespace().collect();
            if words.first() != Some(&key) || words.len() != fields + 1 {
                return Err(Error::Manifest(at, "expected the next header line in order"));
            }
            Ok((at, words[1..].to_vec()))
        };
        let (at, version) = header("witcher-tk-manifest", 1)?;
        if version[0] != "1" {
            return Err(Error::Manifest(at, "unknown manifest version"));
        }
        let (at, name) = header("name", 1)?;
        if !is_name(name[0]) {
            return Err(Error::Manifest(at, "the name must be letters, digits, '.', '_' or '-'"));
        }
        let (at, base) = header("base", 1)?;
        let base = hex_u32(base[0]).ok_or(Error::Manifest(at, "base must be 0x and hex"))?;
        let mut pins = [None; 3];
        for (slot, key) in pins.iter_mut().zip(["stock", "image", "gzip"]) {
            let (at, fields) = header(key, 2)?;
            let size = fields[0].parse().map_err(|_| Error::Manifest(at, "size must be decimal"))?;
            let sha256 = Digest::parse(fields[1]).ok_or(Error::Manifest(at, "bad SHA-256"))?;
            *slot = Some((at, Pin { size, sha256 }));
        }
        let [Some((_, stock)), Some((at, image)), Some((gzip_at, gzip))] = pins else {
            return Err(Error::Manifest(0, "the header is incomplete"));
        };
        if image.size != stock.size {
            return Err(Error::Manifest(at, "patches replace bytes in place: image and stock sizes must match"));
        }
        if !(LOADER_MIN_BYTES..=LOADER_MAX_BYTES).contains(&gzip.size) {
            return Err(Error::Manifest(gzip_at, "the boot loader stages no image of this size"));
        }
        let end = base as u64 + stock.size;
        let mut sites = Vec::new();
        let mut next_free = base as u64;
        for (at, line) in lines {
            let words: Vec<&str> = line.split_ascii_whitespace().collect();
            let [kind, va, len, name, original, parts @ ..] = &words[..] else {
                return Err(Error::Manifest(at, "a site line needs a VA, length, name, SHA-256 and replacement"));
            };
            if *kind != "site" || parts.is_empty() {
                return Err(Error::Manifest(at, "a site line needs a VA, length, name, SHA-256 and replacement"));
            }
            let va = hex_u32(va).ok_or(Error::Manifest(at, "the VA must be 0x and hex"))?;
            let len: u32 = len.parse().ok().filter(|&n| n > 0).ok_or(Error::Manifest(at, "bad length"))?;
            if !is_name(name) {
                return Err(Error::Manifest(at, "bad site name"));
            }
            let original = Digest::parse(original).ok_or(Error::Manifest(at, "bad SHA-256"))?;
            let parts = parts
                .iter()
                .map(|p| part(p))
                .collect::<Option<Vec<Part>>>()
                .ok_or(Error::Manifest(at, "a part must be hex bytes or @0xVA:LEN"))?;
            if parts.iter().map(Part::len).sum::<usize>() != len as usize {
                return Err(Error::Manifest(at, "the parts do not add up to the length"));
            }
            if va & 1 != 0 || (va as u64) < next_free || va as u64 + len as u64 > end {
                return Err(Error::Manifest(at, "sites must be even, sorted, apart and inside the image"));
            }
            for p in &parts {
                if let Part::Stock { va: from, len: n } = *p {
                    if from < base || from as u64 + n as u64 > va as u64 {
                        return Err(Error::Manifest(at, "a reference must point at stock bytes before its site"));
                    }
                }
            }
            next_free = va as u64 + len as u64;
            sites.push(Site { va, len, name: *name, original, parts });
        }
        if sites.is_empty() {
            return Err(Error::Manifest(0, "no sites"));
        }
        Ok(Manifest { name: name[0], base, stock, image, gzip, sites })
    }

    /// The site's offset in the image.
    pub fn offset(&self, site: &Site) -> u64 {
        (site.va - self.base) as u64
    }

    /// Witcher's replacement bytes at `va..va + len`, when one site holds
    /// them all as its own bytes rather than stock references.
    pub fn replacement_at(&self, va: u32, len: usize) -> Option<Vec<u8>> {
        let end = va as u64 + len as u64;
        let site = self.sites.iter().find(|s| s.va <= va && end <= s.va as u64 + s.len as u64)?;
        let mut skip = (va - site.va) as usize;
        let mut out = Vec::with_capacity(len);
        for part in &site.parts {
            if out.len() == len {
                break;
            }
            if skip >= part.len() {
                skip -= part.len();
                continue;
            }
            let Part::Bytes(b) = part else { return None };
            let take = (b.len() - skip).min(len - out.len());
            out.extend_from_slice(&b[skip..skip + take]);
            skip = 0;
        }
        (out.len() == len).then_some(out)
    }
}

impl fmt::Display for Manifest<'_> {
    /// The canonical text, without comments.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{VERSION_LINE}")?;
        writeln!(f, "name {}", self.name)?;
        writeln!(f, "base {:#010x}", self.base)?;
        for (key, pin) in [("stock", self.stock), ("image", self.image), ("gzip", self.gzip)] {
            writeln!(f, "{key} {} {}", pin.size, pin.sha256)?;
        }
        for site in &self.sites {
            write!(f, "site {:#010x} {} {} {}", site.va, site.len, site.name, site.original)?;
            for part in &site.parts {
                match part {
                    Part::Bytes(b) => {
                        f.write_str(" ")?;
                        b.iter().try_for_each(|x| write!(f, "{x:02x}"))?;
                    }
                    Part::Stock { va, len } => write!(f, " @{va:#010x}:{len}")?,
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;

    const Z: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn text(sites: &str) -> String {
        format!(
            "# a comment\n{VERSION_LINE}\nname t\nbase 0x1000\nstock 256 {Z}\nimage 256 {Z}\ngzip 2048 {Z}\n\n{sites}"
        )
    }

    #[test]
    fn parses_and_prints_canonical_text() {
        let src = text(&format!("site 0x1010 4 a {Z} 0102 @0x1000:2\nsite 0x1020 2 b.c {Z} ffee\n"));
        let m = Manifest::parse(&src).unwrap();
        assert_eq!(m.sites.len(), 2);
        assert_eq!(m.sites[0].parts, [Part::Bytes([1, 2].into()), Part::Stock { va: 0x1000, len: 2 }]);
        assert_eq!(m.offset(&m.sites[1]), 0x20);
        let printed = format!("{m}");
        assert_eq!(Manifest::parse(&printed).unwrap(), m);
        assert!(printed.starts_with(VERSION_LINE));
        assert_eq!(m.replacement_at(0x1010, 2), Some([1, 2].into()));
        assert_eq!(m.replacement_at(0x1011, 1), Some([2].into()));
        assert_eq!(m.replacement_at(0x1012, 1), None, "a stock reference");
        assert_eq!(m.replacement_at(0x1010, 4), None, "partly a stock reference");
        assert_eq!(m.replacement_at(0x1020, 2), Some([0xff, 0xee].into()));
        assert_eq!(m.replacement_at(0x1021, 2), None, "past the site");
        assert_eq!(m.replacement_at(0x1030, 1), None, "no site");
    }

    #[test]
    fn rejects_rule_breaks() {
        let bad = [
            ("site 0x1011 2 a {Z} 0102", "sites must be even, sorted, apart and inside the image"),
            ("site 0x1010 4 a {Z} 01020304\nsite 0x1012 2 b {Z} 0102", "sites must be even, sorted, apart and inside the image"),
            ("site 0x1020 2 a {Z} 0102\nsite 0x1010 2 b {Z} 0102", "sites must be even, sorted, apart and inside the image"),
            ("site 0x10fe 4 a {Z} 01020304", "sites must be even, sorted, apart and inside the image"),
            ("site 0x0ffe 2 a {Z} 0102", "sites must be even, sorted, apart and inside the image"),
            ("site 0x1010 3 a {Z} 0102", "the parts do not add up to the length"),
            ("site 0x1010 2 a {Z} 012", "a part must be hex bytes or @0xVA:LEN"),
            ("site 0x1010 2 a {Z} @0x1010:2", "a reference must point at stock bytes before its site"),
            ("site 0x1010 2 a {Z} @0x0800:2", "a reference must point at stock bytes before its site"),
            ("site 0x1010 2 a {Z} @0x1000:0", "a part must be hex bytes or @0xVA:LEN"),
            ("site 0x1010 2 a/b {Z} 0102", "bad site name"),
            ("site 0x1010 2 a 00 0102", "bad SHA-256"),
            ("site 0x1010 2 a {Z}", "a site line needs a VA, length, name, SHA-256 and replacement"),
            ("patch 0x1010 2 a {Z} 0102", "a site line needs a VA, length, name, SHA-256 and replacement"),
        ];
        for (sites, why) in bad {
            let src = text(&sites.replace("{Z}", Z));
            match Manifest::parse(&src) {
                Err(Error::Manifest(_, got)) => assert_eq!(got, why, "{sites}"),
                other => panic!("{sites}: {other:?}"),
            }
        }
        assert_eq!(Manifest::parse(&text("")), Err(Error::Manifest(0, "no sites")));
        let swapped = text(&format!("site 0x1010 2 a {Z} 0102")).replace("name t\nbase 0x1000", "base 0x1000\nname t");
        assert!(matches!(Manifest::parse(&swapped), Err(Error::Manifest(_, "expected the next header line in order"))));
        let wrong_size = text(&format!("site 0x1010 2 a {Z} 0102")).replace("image 256", "image 257");
        assert!(matches!(Manifest::parse(&wrong_size), Err(Error::Manifest(_, _))));
        let huge = text(&format!("site 0x1010 2 a {Z} 0102")).replace("gzip 2048", "gzip 9000000");
        assert!(matches!(
            Manifest::parse(&huge),
            Err(Error::Manifest(_, "the boot loader stages no image of this size"))
        ));
    }

    #[test]
    fn carried_manifests_parse() {
        for text in crate::manifests::ALL {
            let m = Manifest::parse(text).unwrap();
            assert_eq!(m.base, 0x8410_0000);
            assert_eq!(format!("{}", m.stock.sha256), "555362d9c050862ac462017df54cbcedc00b0963454b332438d70bbef70f82ea");
            // The committed text is the canonical text plus its comment lines.
            let data: String = text.lines().filter(|l| !l.starts_with('#')).flat_map(|l| [l, "\n"]).collect();
            assert_eq!(format!("{m}"), data, "{}", m.name);
        }
    }
}
