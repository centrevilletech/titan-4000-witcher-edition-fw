//! tkpatch.py specs to manifests.
//!
//! A spec (the JSON tkpatch.py reads) carries each site's stock bytes in
//! `expected`. A manifest keeps their SHA-256 instead, and writes a run of
//! the replacement that is a copy of stock bytes from earlier in the image as
//! a reference: at each position, when the next 16 bytes hold at least 8
//! distinct values and occur in the stock image before the site, the longest
//! such match (the first occurrence among the longest) becomes `@VA:LEN`.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde_json::Value;
use witcher_tk_patch::gzip;
use witcher_tk_patch::manifest::VERSION_LINE;
use witcher_tk_patch::sha256::digest;

/// tkpatch.py's constants: the load VA and the stock image.
pub const BASE: u32 = 0x8410_0000;
pub const STOCK_SIZE: usize = 9_553_965;
pub const STOCK_SHA256: &str = "555362d9c050862ac462017df54cbcedc00b0963454b332438d70bbef70f82ea";
const MIN_RUN: usize = 16;
const MIN_DISTINCT: usize = 8;

pub struct Site {
    pub offset: usize,
    pub va: u32,
    pub expected: Vec<u8>,
    pub new: Vec<u8>,
    pub name: String,
    pub reason: String,
}

pub struct Spec {
    pub name: String,
    pub sites: Vec<Site>,
}

fn int(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    match s.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

fn unhex(v: &Value) -> Option<Vec<u8>> {
    let s = v.as_str()?;
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn parse(json: &str) -> Result<Spec, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("spec: {e}"))?;
    let name = v["name"].as_str().unwrap_or_default().to_owned();
    let raw = v["sites"].as_array().cloned().unwrap_or_default();
    if name.is_empty() || raw.is_empty() {
        return Err("empty patch set".into());
    }
    let mut sites = Vec::new();
    for (i, s) in raw.iter().enumerate() {
        let bad = |what: &str| format!("site {i}: bad or missing {what}");
        sites.push(Site {
            offset: int(&s["offset"]).ok_or_else(|| bad("offset"))? as usize,
            va: int(&s["va"]).and_then(|va| u32::try_from(va).ok()).ok_or_else(|| bad("va"))?,
            expected: unhex(&s["expected"]).ok_or_else(|| bad("expected"))?,
            new: unhex(&s["new"]).ok_or_else(|| bad("new"))?,
            name: s["name"].as_str().ok_or_else(|| bad("name"))?.to_owned(),
            reason: s["reason"].as_str().ok_or_else(|| bad("reason"))?.to_owned(),
        });
    }
    Ok(Spec { name, sites })
}

fn is_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Where each qualifying 16-byte run occurs in the stock image, ascending.
fn occurrences(stock: &[u8], sites: &[Site]) -> HashMap<[u8; MIN_RUN], Vec<usize>> {
    let mut found: HashMap<[u8; MIN_RUN], Vec<usize>> = HashMap::new();
    for site in sites {
        for w in site.new.windows(MIN_RUN) {
            let mut seen = [false; 256];
            w.iter().for_each(|&b| seen[b as usize] = true);
            if seen.iter().filter(|&&s| s).count() >= MIN_DISTINCT {
                found.entry(w.try_into().unwrap()).or_default();
            }
        }
    }
    for (at, w) in stock.windows(MIN_RUN).enumerate() {
        if let Some(list) = found.get_mut(w) {
            list.push(at);
        }
    }
    found
}

/// A site's replacement as manifest parts: hex, and references to stock
/// bytes before `site.offset`.
fn parts(stock: &[u8], site: &Site, index: &HashMap<[u8; MIN_RUN], Vec<usize>>) -> Vec<String> {
    let (new, end) = (&site.new, site.offset);
    let mut out = Vec::new();
    let mut lit = String::new();
    let mut i = 0;
    while i < new.len() {
        let mut best = (0, 0);
        if let Some(list) = new.get(i..i + MIN_RUN).and_then(|head| index.get(head)) {
            for &at in list.iter().take_while(|&&at| at + MIN_RUN <= end) {
                let mut n = MIN_RUN;
                while i + n < new.len() && at + n < end && stock[at + n] == new[i + n] {
                    n += 1;
                }
                if n > best.0 {
                    best = (n, at);
                }
            }
        }
        if best.0 > 0 {
            if !lit.is_empty() {
                out.push(std::mem::take(&mut lit));
            }
            out.push(format!("@{:#010x}:{}", BASE as usize + best.1, best.0));
            i += best.0;
        } else {
            let _ = write!(lit, "{:02x}", new[i]);
            i += 1;
        }
    }
    if !lit.is_empty() {
        out.push(lit);
    }
    out
}

/// The manifest for `spec` over `stock`, and the patched image. The checks
/// are tkpatch.py's: sorted by offset, even, `va == BASE + offset`, apart,
/// inside the image, `expected` is what the stock image holds there, and
/// every site has a name and a reason.
pub fn manifest(stock: &[u8], spec: &Spec, name: &str) -> Result<(String, Vec<u8>), String> {
    if !is_name(name) {
        return Err("the manifest name must be letters, digits, '.', '_' or '-'".into());
    }
    let mut order: Vec<&Site> = spec.sites.iter().collect();
    order.sort_by_key(|s| s.offset);
    let mut image = stock.to_vec();
    let mut last = 0;
    for s in &order {
        let end = s.offset + s.expected.len();
        if s.expected.is_empty()
            || s.expected.len() != s.new.len()
            || s.offset & 1 != 0
            || s.va as u64 != BASE as u64 + s.offset as u64
            || s.offset < last
            || end > stock.len()
            || stock[s.offset..end] != s.expected[..]
            || s.reason.trim().is_empty()
            || !is_name(&s.name)
        {
            return Err(format!("invalid offset, overlap, size, name or preimage at {:#x}", s.offset));
        }
        image[s.offset..end].copy_from_slice(&s.new);
        last = end;
    }
    let packed = gzip::compress(&image);
    let index = occurrences(stock, &spec.sites);
    let mut text = String::new();
    let _ = writeln!(text, "# Witcher tk patch manifest: Witcher bytes and hashes only (docs/tk-patch.md).");
    let _ = writeln!(text, "# From spec: {}", spec.name);
    let _ = writeln!(text, "{VERSION_LINE}\nname {name}\nbase {BASE:#010x}");
    let _ = writeln!(text, "stock {} {}", stock.len(), digest(stock));
    let _ = writeln!(text, "image {} {}", image.len(), digest(&image));
    let _ = writeln!(text, "gzip {} {}", packed.len(), digest(&packed));
    for s in &order {
        let original = digest(&s.expected);
        let _ = writeln!(text, "site {:#010x} {} {} {original} {}", s.va, s.new.len(), s.name, parts(stock, s, &index).join(" "));
    }
    Ok((text, image))
}

#[cfg(test)]
mod tests {
    use super::*;
    use witcher_tk_patch::manifest::Manifest;
    use witcher_tk_patch::{manifests, pipeline, prg};

    fn site(offset: usize, expected: &[u8], new: &[u8]) -> Site {
        Site {
            offset,
            va: BASE + offset as u32,
            expected: expected.to_vec(),
            new: new.to_vec(),
            name: format!("s{offset:x}"),
            reason: "test".into(),
        }
    }

    /// Random bytes (xorshift32, seed 1): they do not compress, so the gzip
    /// image is a size the boot loader stages.
    fn stock() -> Vec<u8> {
        let mut x = 1u32;
        (0..4096)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    #[test]
    fn applies_tkpatch_rules() {
        let stock = stock();
        let good = Spec { name: "t".into(), sites: vec![site(0x200, &stock[0x200..0x204], &[1, 2, 3, 4]), site(0x100, &stock[0x100..0x102], &[5, 6])] };
        let (text, image) = manifest(&stock, &good, "t").unwrap();
        let m = Manifest::parse(&text).unwrap();
        assert_eq!(m.sites.iter().map(|s| s.va).collect::<Vec<_>>(), [BASE + 0x100, BASE + 0x200], "sorted");
        assert_eq!(&image[0x100..0x102], &[5, 6]);
        let bad = [
            site(0x101, &stock[0x101..0x103], &[1, 2]),
            site(0x100, &[0, 0], &[1, 2]),
            site(0x100, &stock[0x100..0x102], &[1, 2, 3]),
            site(0xffe, &[stock[0xffe], stock[0xfff], 0, 0], &[1, 2, 3, 4]),
            Site { va: BASE + 0x102, ..site(0x100, &stock[0x100..0x102], &[1, 2]) },
            Site { reason: " ".into(), ..site(0x100, &stock[0x100..0x102], &[1, 2]) },
            Site { name: "a b".into(), ..site(0x100, &stock[0x100..0x102], &[1, 2]) },
        ];
        for s in bad {
            let offset = s.offset;
            let spec = Spec { name: "t".into(), sites: vec![s] };
            assert!(manifest(&stock, &spec, "t").is_err(), "site at {offset:#x}");
        }
        let overlap = Spec { name: "t".into(), sites: vec![site(0x100, &stock[0x100..0x104], &[1; 4]), site(0x102, &stock[0x102..0x104], &[2; 2])] };
        assert!(manifest(&stock, &overlap, "t").is_err());
    }

    #[test]
    fn copies_of_earlier_stock_bytes_become_references() {
        let stock = stock();
        let mut new = vec![0xaa, 0xbb];
        new.extend_from_slice(&stock[0x40..0x60]);
        new.push(0xcc);
        let spec = Spec { name: "t".into(), sites: vec![site(0x400, &stock[0x400..0x400 + new.len()], &new)] };
        let (text, image) = manifest(&stock, &spec, "t").unwrap();
        let line = text.lines().last().unwrap();
        assert!(line.ends_with(&format!(" aabb @{:#010x}:32 cc", BASE + 0x40)), "{line}");
        let m = Manifest::parse(&text).unwrap();
        let mut out = Vec::new();
        pipeline::from_raw(&m, &mut &stock[..], &mut out).unwrap();
        assert!(out == gzip::compress(&image));
    }

    /// The committed manifests came from the Python twin of this code. Turn
    /// each back into a spec with the stock image, convert it here, and get
    /// the same text: the Rust tool and the bench images agree.
    #[test]
    fn spec_round_trip_on_the_stock_image() {
        let Some(path) = std::env::var_os("WITCHER_STOCK_PRG") else {
            assert!(std::env::var("WITCHER_REQUIRE_STOCK").as_deref() != Ok("1"), "WITCHER_STOCK_PRG is not set");
            eprintln!("skipped: set WITCHER_STOCK_PRG to the stock .prg");
            return;
        };
        let prg = std::fs::read(path).unwrap();
        let mut stock = Vec::new();
        gzip::decompress(&mut prg::tk_section(&prg).unwrap(), &mut |c| {
            stock.extend_from_slice(c);
            Ok(())
        })
        .unwrap();
        assert_eq!(digest(&stock).to_string(), STOCK_SHA256);
        for text in manifests::ALL {
            let m = Manifest::parse(text).unwrap();
            let mut image = Vec::new();
            pipeline::from_raw(&m, &mut &stock[..], &mut image).unwrap();
            let mut patched = Vec::new();
            gzip::decompress(&mut &image[..], &mut |c| {
                patched.extend_from_slice(c);
                Ok(())
            })
            .unwrap();
            let sites = m
                .sites
                .iter()
                .map(|s| {
                    let at = m.offset(s) as usize;
                    let len = s.len as usize;
                    Site { offset: at, va: s.va, expected: stock[at..at + len].to_vec(), new: patched[at..at + len].to_vec(), name: s.name.into(), reason: "round trip".into() }
                })
                .collect();
            let spec_name = text.lines().nth(1).unwrap().trim_start_matches("# From spec: ").to_owned();
            let (again, _) = manifest(&stock, &Spec { name: spec_name, sites }, m.name).unwrap();
            assert!(again == text, "{}: the Rust conversion differs from the committed manifest", m.name);
        }
    }
}
