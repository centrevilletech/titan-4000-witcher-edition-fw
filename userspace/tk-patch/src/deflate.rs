//! zlib 1.3's deflate at level 9, so the output is byte for byte zlib's.
//!
//! The modem's loader (lib/inflate.c inside the vendor modem.ko) rejects
//! some valid streams, such as incomplete distance trees that other
//! compressors write. zlib's output is what the bench loads, so this port
//! reproduces it exactly: `zlib.compressobj(9, DEFLATED, -15, 8, 0)`, which
//! is what Python's `gzip.compress(data, 9)` uses. Like zlib, the output
//! does not depend on how the input is split across [`Deflater::write`] calls.
//!
//! This file and `trees.rs` are a Rust translation of the level-9 path of
//! zlib 1.3's deflate.c (deflate_slow, longest_match, fill_window) and
//! trees.c, for windowBits 15, memLevel 8 and the default strategy:
//!
//! > deflate.c -- compress data using the deflation algorithm.
//! > Copyright (C) 1995-2023 Jean-loup Gailly and Mark Adler.
//! > trees.c -- output deflated data using Huffman coding.
//! > Copyright (C) 1995-2021 Jean-loup Gailly.
//! >
//! > This software is provided 'as-is', without any express or implied
//! > warranty. In no event will the authors be held liable for any damages
//! > arising from the use of this software.
//! >
//! > Permission is granted to anyone to use this software for any purpose,
//! > including commercial applications, and to alter it and redistribute it
//! > freely, subject to the following restrictions:
//! >
//! > 1. The origin of this software must not be misrepresented; you must not
//! >    claim that you wrote the original software. If you use this software
//! >    in a product, an acknowledgment in the product documentation would be
//! >    appreciated but is not required.
//! > 2. Altered source versions must be plainly marked as such, and must not
//! >    be misrepresented as being the original software.
//! > 3. This notice may not be removed or altered from any source distribution.
//!
//! Altered: translated to Rust and cut to the one configuration above. The
//! `insert` and `high_water` bookkeeping is gone: without flushes before
//! the end `insert` stays 0, and zeroing past the data only quiets memory
//! checkers (matches never extend past the lookahead).

use alloc::vec;
use alloc::vec::Vec;

use crate::trees::Trees;
use crate::{Error, Sink};

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const W_SIZE: usize = 1 << 15;
const W_MASK: usize = W_SIZE - 1;
const WINDOW_SIZE: usize = 2 * W_SIZE;
const HASH_BITS: u32 = 8 + 7;
const HASH_SIZE: usize = 1 << HASH_BITS;
const HASH_MASK: u32 = HASH_SIZE as u32 - 1;
const HASH_SHIFT: u32 = (HASH_BITS + MIN_MATCH as u32 - 1) / MIN_MATCH as u32;
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;
const MAX_DIST: usize = W_SIZE - MIN_LOOKAHEAD;
/// zlib's configuration_table[9].
const GOOD_MATCH: usize = 32;
const MAX_LAZY: usize = 258;
const NICE_MATCH: usize = 258;
const MAX_CHAIN: usize = 4096;
/// Length-3 matches farther back than this are not worth it.
const TOO_FAR: usize = 4096;

/// A raw DEFLATE encoder. About 300 KiB of state, all on the heap.
pub struct Deflater {
    window: Vec<u8>,
    /// Earlier positions with the same hash, by position & W_MASK. 0 ends a chain.
    prev: Vec<u16>,
    /// The latest position for each hash.
    head: Vec<u16>,
    ins_h: u32,
    strstart: usize,
    /// Where the current block starts. Negative once the window has slid past it.
    block_start: isize,
    lookahead: usize,
    /// zlib's match_start. It can go stale (and wrap) across a slide, as in
    /// zlib, but a stale value never reaches the output.
    match_start: usize,
    match_length: usize,
    prev_length: usize,
    prev_match: usize,
    match_available: bool,
    trees: Trees,
}

impl Default for Deflater {
    fn default() -> Self {
        Self::new()
    }
}

impl Deflater {
    pub fn new() -> Self {
        Deflater {
            window: vec![0; WINDOW_SIZE],
            prev: vec![0; W_SIZE],
            head: vec![0; HASH_SIZE],
            ins_h: 0,
            strstart: 0,
            block_start: 0,
            lookahead: 0,
            match_start: 0,
            match_length: MIN_MATCH - 1,
            prev_length: MIN_MATCH - 1,
            prev_match: 0,
            match_available: false,
            trees: Trees::new(),
        }
    }

    /// Compress the next input bytes. Finished blocks go to `sink`.
    pub fn write(&mut self, mut data: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        self.deflate_slow(&mut data, false);
        self.drain(sink)
    }

    /// Compress what is left and end the stream with the last block.
    pub fn finish(mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.deflate_slow(&mut &[][..], true);
        self.drain(sink)
    }

    fn drain(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let out = self.trees.output();
        if out.is_empty() {
            return Ok(());
        }
        let result = sink.write(out);
        out.clear();
        result
    }

    /// zlib's fill_window: slide the window when it is nearly full, then read
    /// as much input as fits.
    fn fill_window(&mut self, input: &mut &[u8]) {
        loop {
            let mut more = WINDOW_SIZE - self.lookahead - self.strstart;
            if self.strstart >= W_SIZE + MAX_DIST {
                self.window.copy_within(W_SIZE..2 * W_SIZE - more, 0);
                self.match_start = self.match_start.wrapping_sub(W_SIZE);
                self.strstart -= W_SIZE;
                self.block_start -= W_SIZE as isize;
                slide(&mut self.head);
                slide(&mut self.prev);
                more += W_SIZE;
            }
            if input.is_empty() {
                return;
            }
            let n = more.min(input.len());
            let at = self.strstart + self.lookahead;
            self.window[at..at + n].copy_from_slice(&input[..n]);
            *input = &input[n..];
            self.lookahead += n;
            if self.lookahead >= MIN_MATCH {
                let s = self.strstart;
                self.ins_h = self.window[s] as u32;
                self.ins_h = ((self.ins_h << HASH_SHIFT) ^ self.window[s + 1] as u32) & HASH_MASK;
            }
            if self.lookahead >= MIN_LOOKAHEAD || input.is_empty() {
                return;
            }
        }
    }

    /// zlib's INSERT_STRING: hash the 3 bytes at `s`, chain `s` in. Returns
    /// the previous head of its chain.
    fn insert_string(&mut self, s: usize) -> usize {
        self.ins_h = ((self.ins_h << HASH_SHIFT) ^ self.window[s + MIN_MATCH - 1] as u32) & HASH_MASK;
        let head = self.head[self.ins_h as usize];
        self.prev[s & W_MASK] = head;
        self.head[self.ins_h as usize] = s as u16;
        head as usize
    }

    /// zlib's longest_match: walk the hash chain from `cur_match` for the
    /// longest match at strstart, longer than prev_length. Sets match_start.
    fn longest_match(&mut self, mut cur_match: usize) -> usize {
        let w = &self.window;
        let scan = self.strstart;
        let mut chain_length = MAX_CHAIN;
        let mut best_len = self.prev_length;
        let mut nice_match = NICE_MATCH;
        let limit = self.strstart.saturating_sub(MAX_DIST);
        let mut scan_end1 = w[scan + best_len - 1];
        let mut scan_end = w[scan + best_len];
        if self.prev_length >= GOOD_MATCH {
            chain_length >>= 2;
        }
        // zlib: do not look past the input, so the result is deterministic.
        if nice_match > self.lookahead {
            nice_match = self.lookahead;
        }
        loop {
            let m = cur_match;
            if w[m + best_len] == scan_end
                && w[m + best_len - 1] == scan_end1
                && w[m] == w[scan]
                && w[m + 1] == w[scan + 1]
            {
                // Byte 2 matches whenever the hash and bytes 0 and 1 do, so
                // zlib starts comparing at byte 3.
                let len = 3 + w[scan + 3..scan + MAX_MATCH]
                    .iter()
                    .zip(&w[m + 3..m + MAX_MATCH])
                    .take_while(|(a, b)| a == b)
                    .count();
                if len > best_len {
                    self.match_start = cur_match;
                    best_len = len;
                    if len >= nice_match {
                        break;
                    }
                    scan_end1 = w[scan + best_len - 1];
                    scan_end = w[scan + best_len];
                }
            }
            cur_match = self.prev[cur_match & W_MASK] as usize;
            chain_length -= 1;
            if cur_match <= limit || chain_length == 0 {
                break;
            }
        }
        best_len.min(self.lookahead)
    }

    fn flush_block(&mut self, last: bool) {
        let stored = usize::try_from(self.block_start).ok().map(|start| &self.window[start..self.strstart]);
        self.trees.flush_block(stored, last);
        self.block_start = self.strstart as isize;
    }

    /// zlib's deflate_slow: lazy evaluation of matches. Without `finish` it
    /// stops when the input runs out, as zlib's need_more.
    fn deflate_slow(&mut self, input: &mut &[u8], finish: bool) {
        loop {
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(input);
                if self.lookahead < MIN_LOOKAHEAD && !finish {
                    return;
                }
                if self.lookahead == 0 {
                    break;
                }
            }
            let mut hash_head = 0;
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert_string(self.strstart);
            }
            self.prev_length = self.match_length;
            self.prev_match = self.match_start;
            self.match_length = MIN_MATCH - 1;
            if hash_head != 0 && self.prev_length < MAX_LAZY && self.strstart - hash_head <= MAX_DIST {
                self.match_length = self.longest_match(hash_head);
                // zlib: match_length <= 5 && (Z_FILTERED || (== MIN_MATCH && too far)).
                if self.match_length == MIN_MATCH && self.strstart.wrapping_sub(self.match_start) > TOO_FAR {
                    self.match_length = MIN_MATCH - 1;
                }
            }
            if self.prev_length >= MIN_MATCH && self.match_length <= self.prev_length {
                // The previous match is at least as good: emit it.
                let max_insert = self.strstart + self.lookahead - MIN_MATCH;
                let full = self
                    .trees
                    .tally_dist(self.strstart - 1 - self.prev_match, self.prev_length - MIN_MATCH);
                // Insert every string the match covers, but none past the input.
                self.lookahead -= self.prev_length - 1;
                self.prev_length -= 2;
                loop {
                    self.strstart += 1;
                    if self.strstart <= max_insert {
                        self.insert_string(self.strstart);
                    }
                    self.prev_length -= 1;
                    if self.prev_length == 0 {
                        break;
                    }
                }
                self.match_available = false;
                self.match_length = MIN_MATCH - 1;
                self.strstart += 1;
                if full {
                    self.flush_block(false);
                }
            } else if self.match_available {
                // No better match came: emit the byte before as a literal.
                if self.trees.tally_lit(self.window[self.strstart - 1]) {
                    self.flush_block(false);
                }
                self.strstart += 1;
                self.lookahead -= 1;
            } else {
                // Wait one byte to see whether the next match is longer.
                self.match_available = true;
                self.strstart += 1;
                self.lookahead -= 1;
            }
        }
        if self.match_available {
            self.trees.tally_lit(self.window[self.strstart - 1]);
            self.match_available = false;
        }
        self.flush_block(true);
    }
}

/// zlib's slide_hash: positions move down one window; older ones end chains.
fn slide(table: &mut [u16]) {
    for pos in table {
        *pos = pos.checked_sub(W_SIZE as u16).unwrap_or(0);
    }
}

/// Raw DEFLATE of `data` in one call.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut d = Deflater::new();
    // Vec sinks cannot fail.
    let _ = d.write(data, &mut out);
    let _ = d.finish(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inflate::{BitReader, inflate};
    use crate::sha256::digest;
    use crate::testdata;
    use alloc::format;

    fn sha(data: &[u8]) -> alloc::string::String {
        format!("{}", digest(data))
    }

    fn round_trip(data: &[u8], packed: &[u8]) {
        let mut src = packed;
        let mut br = BitReader::new(&mut src);
        let mut out = Vec::new();
        inflate(&mut br, &mut |c| {
            out.extend_from_slice(c);
            Ok(())
        })
        .unwrap();
        assert!(out == data, "inflate(deflate(x)) != x");
    }

    #[test]
    fn generators_match_the_python_twins() {
        let cases = [
            (testdata::random_bytes(1, 40_000), "41445f0664673767895103de6fa8e77b25237e94d3e88596ff65e7f359f6d78f"),
            (testdata::mixed(1, 1500), "7539b3d67e09eaaebd93e4c93b22ee5066d9f22d4bdb69a26e7e847401ace359"),
            (testdata::skewed(1, 60_000), "cf4437976e10886bce0019dc18e0ca3847128c4f815fb6e8fc04b05f3c39c109"),
            (testdata::mixed(3, 400), "9a535eb4233429025806cb6666e9f6d7a3fa2b793b4ea33b30025d740f3a220a"),
        ];
        for (data, want) in cases {
            assert_eq!(sha(&data), want);
        }
    }

    /// zlib 1.3 (Python 3.12 `zlib.compressobj(9, DEFLATED, -15, 8, 0)`) on
    /// the generated inputs: output length and SHA-256. Together they cover
    /// stored, static and dynamic blocks, full blocks, window slides and far
    /// matches. The bit length overflow repair runs in the stock-image tests.
    #[test]
    fn matches_zlib() {
        let cases: [(&str, Vec<u8>, usize, &str); 8] = [
            ("empty", Vec::new(), 2, "9b4fb24edd6d1d8830e272398263cdbf026b97392cc35387b991dc0248a628f9"),
            ("one", b"a".to_vec(), 3, "59fced9a2ff83dabdd7055cf3abd6c12b802e6397b6fba5b8251cdf95d2bc991"),
            (
                "hello",
                b"hello hello hello hello".to_vec(),
                10,
                "ecbeb577b4efc0838791464adb8800d3ac432a00aa4a005bae35f7b1b488640a",
            ),
            ("zeros", vec![0; 70_000], 85, "5de73a93ed1d02e62a25d5f5bb9927bb9563ea9c2ba2dc32d78e45a323bc7b38"),
            (
                "random",
                testdata::random_bytes(1, 40_000),
                40_015,
                "323a7c870ae3d82be57f0682c078facd18d728341a2d6b415e6ddf885acffae0",
            ),
            (
                "fox",
                b"The quick brown fox jumps over the lazy dog. ".repeat(3000),
                455,
                "856b45fafbd8c3f07d2ebf7bfce8e208318fefe1776273546d38e6adad57719b",
            ),
            (
                "mixed",
                testdata::mixed(1, 1500),
                58_859,
                "cd50f6c16ab3a9376fc033dddeeea391442ff1a2941068551448e425ffe9fb7b",
            ),
            (
                "skewed",
                testdata::skewed(1, 60_000),
                18_899,
                "54b9837691a6966c0e93ad55d3846f412cc7da55be2b271d4caf978c3671b451",
            ),
        ];
        for (name, data, len, want) in cases {
            let packed = deflate(&data);
            round_trip(&data, &packed);
            assert_eq!((packed.len(), sha(&packed).as_str()), (len, want), "{name}");
        }
    }

    #[test]
    fn output_does_not_depend_on_how_input_is_split() {
        let data = testdata::mixed(3, 400);
        let whole = deflate(&data);
        for chunk in [1, 7, 4093, 65_536] {
            let mut out = Vec::new();
            let mut d = Deflater::new();
            for piece in data.chunks(chunk) {
                d.write(piece, &mut out).unwrap();
            }
            d.finish(&mut out).unwrap();
            assert!(out == whole, "chunks of {chunk}");
        }
    }
}
