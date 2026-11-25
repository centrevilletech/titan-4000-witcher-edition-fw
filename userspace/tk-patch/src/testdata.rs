//! Generated test inputs. scripts/test-tk-patch.py has the same generators,
//! and the expected values in the tests come from Python's zlib on them.

use alloc::vec::Vec;

pub struct Xorshift32(pub u32);

impl Xorshift32 {
    pub fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
}

pub fn random_bytes(seed: u32, n: usize) -> Vec<u8> {
    let mut r = Xorshift32(seed);
    (0..n).map(|_| r.next() as u8).collect()
}

/// Random runs, byte runs, copies from up to 40000 back (window slides,
/// far matches, length-3 matches past TOO_FAR) and short text.
pub fn mixed(seed: u32, units: usize) -> Vec<u8> {
    let mut r = Xorshift32(seed);
    let mut out = Vec::new();
    for _ in 0..units {
        let kind = r.next() % 4;
        let n = (r.next() % 300 + 1) as usize;
        match kind {
            0 => {
                for _ in 0..n {
                    out.push(r.next() as u8);
                }
            }
            1 => {
                let b = r.next() as u8;
                out.extend(core::iter::repeat_n(b, n));
            }
            2 if !out.is_empty() => {
                let d = r.next() as usize % out.len().min(40_000) + 1;
                for _ in 0..n {
                    let b = out[out.len() - d];
                    out.push(b);
                }
            }
            _ => {
                let pattern = &b"abcabcabd"[..n % 9 + 1];
                for _ in 0..n / 9 + 1 {
                    out.extend_from_slice(pattern);
                }
            }
        }
    }
    out
}

/// A geometric byte distribution: Huffman code lengths of many sizes.
pub fn skewed(seed: u32, n: usize) -> Vec<u8> {
    let mut r = Xorshift32(seed);
    (0..n)
        .map(|_| {
            let mut w = r.next();
            let mut v = 0u32;
            while w & 1 == 1 && v < 31 {
                v += 1;
                w >>= 1;
            }
            if v >= 12 {
                v = 32 + (r.next() & 15);
            }
            (v * 7) as u8
        })
        .collect()
}
