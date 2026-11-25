//! A DEFLATE (RFC 1951) decoder: small and strict rather than fast.
//!
//! Huffman codes decode one bit at a time from canonical code counts, the
//! method of Mark Adler's puff.c. Code rules are zlib's: no over-subscribed
//! code; a dynamic block's code length code must be complete, and its
//! literal/length and distance codes complete, empty or a lone one-bit code.
//! It reads the stock image once per build, at a few MB/s on the unit.

use alloc::vec;
use alloc::vec::Vec;

use crate::{Error, Source};

const WSIZE: usize = 32 * 1024;
const MAXBITS: usize = 15;
const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049,
    3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];
/// The order code length code lengths arrive in.
const ORDER: [u8; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Bits and bytes from a source, least significant bit first.
pub struct BitReader<'s> {
    src: &'s mut dyn Source,
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    bits: u32,
    count: u32,
}

impl<'s> BitReader<'s> {
    pub fn new(src: &'s mut dyn Source) -> Self {
        BitReader { src, buf: vec![0; 4096], pos: 0, len: 0, bits: 0, count: 0 }
    }

    /// The next whole byte. Call [`BitReader::align`] first inside a bit stream.
    pub fn byte(&mut self) -> Result<u8, Error> {
        if self.pos == self.len {
            self.len = self.src.read(&mut self.buf)?;
            self.pos = 0;
            if self.len == 0 {
                return Err(Error::Truncated);
            }
        }
        self.pos += 1;
        Ok(self.buf[self.pos - 1])
    }

    /// The next `n` bits (at most 16), first bit lowest.
    pub fn bits(&mut self, n: u32) -> Result<u32, Error> {
        while self.count < n {
            self.bits |= (self.byte()? as u32) << self.count;
            self.count += 8;
        }
        let value = self.bits & ((1 << n) - 1);
        self.bits >>= n;
        self.count -= n;
        Ok(value)
    }

    /// Drop the rest of the current byte. Whole bytes are never held back.
    pub fn align(&mut self) {
        self.bits = 0;
        self.count = 0;
    }
}

/// How complete a code must be.
#[derive(Clone, Copy)]
enum Fill {
    /// Not over-subscribed: the fixed codes (30 of 32 five-bit distance codes).
    Any,
    /// Complete: a dynamic block's code length code.
    Complete,
    /// Complete, empty, or a single one-bit code: a dynamic block's
    /// literal/length and distance codes.
    Usable,
}

/// A canonical Huffman code: how many codes have each length, and the
/// symbols in code order.
struct Huffman<const N: usize> {
    count: [u16; MAXBITS + 1],
    symbol: [u16; N],
}

impl<const N: usize> Huffman<N> {
    /// Build the code for `lengths`, as complete as `fill` asks.
    fn new(lengths: &[u8], fill: Fill) -> Result<Self, Error> {
        let mut h = Huffman { count: [0; MAXBITS + 1], symbol: [0; N] };
        for &len in lengths {
            h.count[len as usize] += 1;
        }
        let used = lengths.len() - h.count[0] as usize;
        let mut left: i32 = 1;
        for len in 1..=MAXBITS {
            left = (left << 1) - h.count[len] as i32;
            if left < 0 {
                return Err(Error::Inflate("over-subscribed Huffman code"));
            }
        }
        let allowed = match fill {
            Fill::Any => true,
            Fill::Complete => false,
            Fill::Usable => used == 0 || (used == 1 && h.count[1] == 1),
        };
        if left > 0 && !allowed {
            return Err(Error::Inflate("incomplete Huffman code"));
        }
        let mut offs = [0u16; MAXBITS + 1];
        for len in 1..MAXBITS {
            offs[len + 1] = offs[len] + h.count[len];
        }
        for (symbol, &len) in lengths.iter().enumerate() {
            if len != 0 {
                h.symbol[offs[len as usize] as usize] = symbol as u16;
                offs[len as usize] += 1;
            }
        }
        Ok(h)
    }

    fn decode(&self, br: &mut BitReader) -> Result<u16, Error> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAXBITS {
            code |= br.bits(1)? as i32;
            let count = self.count[len] as i32;
            if code - count < first {
                return Ok(self.symbol[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::Inflate("invalid Huffman code"))
    }
}

/// The last 32 KiB of output, which back-references copy from.
struct Window {
    buf: Vec<u8>,
    pos: usize,
    full: bool,
}

type Out<'a> = dyn FnMut(&[u8]) -> Result<(), Error> + 'a;

impl Window {
    fn put(&mut self, byte: u8, out: &mut Out<'_>) -> Result<(), Error> {
        self.buf[self.pos] = byte;
        self.pos += 1;
        if self.pos == WSIZE {
            out(&self.buf)?;
            self.pos = 0;
            self.full = true;
        }
        Ok(())
    }

    fn copy(&mut self, dist: usize, len: usize, out: &mut Out<'_>) -> Result<(), Error> {
        let written = if self.full { WSIZE } else { self.pos };
        if dist > written {
            return Err(Error::Inflate("distance too far back"));
        }
        for _ in 0..len {
            let byte = self.buf[(self.pos + WSIZE - dist) % WSIZE];
            self.put(byte, out)?;
        }
        Ok(())
    }
}

/// Decode one raw DEFLATE stream, handing the output to `out` in order in
/// pieces of at most 32 KiB. Stops after the last block, at a bit inside its
/// final byte.
pub fn inflate(br: &mut BitReader, out: &mut Out<'_>) -> Result<(), Error> {
    let mut window = Window { buf: vec![0; WSIZE], pos: 0, full: false };
    loop {
        let last = br.bits(1)? == 1;
        match br.bits(2)? {
            0 => stored(br, &mut window, out)?,
            1 => {
                let mut lengths = [0u8; 288];
                lengths[..144].fill(8);
                lengths[144..256].fill(9);
                lengths[256..280].fill(7);
                lengths[280..].fill(8);
                let lit = Huffman::<288>::new(&lengths, Fill::Any)?;
                let dist = Huffman::<30>::new(&[5; 30], Fill::Any)?;
                codes(br, &mut window, out, &lit, &dist)?;
            }
            2 => {
                let (lit, dist) = dynamic(br)?;
                codes(br, &mut window, out, &lit, &dist)?;
            }
            _ => return Err(Error::Inflate("invalid block type")),
        }
        if last {
            return out(&window.buf[..window.pos]);
        }
    }
}

fn stored(br: &mut BitReader, window: &mut Window, out: &mut Out<'_>) -> Result<(), Error> {
    br.align();
    let len = br.byte()? as u16 | (br.byte()? as u16) << 8;
    let nlen = br.byte()? as u16 | (br.byte()? as u16) << 8;
    if len != !nlen {
        return Err(Error::Inflate("stored block length check"));
    }
    for _ in 0..len {
        let byte = br.byte()?;
        window.put(byte, out)?;
    }
    Ok(())
}

fn dynamic(br: &mut BitReader) -> Result<(Huffman<288>, Huffman<30>), Error> {
    let nlen = br.bits(5)? as usize + 257;
    let ndist = br.bits(5)? as usize + 1;
    let ncode = br.bits(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Err(Error::Inflate("too many length or distance codes"));
    }
    let mut lengths = [0u8; 19];
    for &i in &ORDER[..ncode] {
        lengths[i as usize] = br.bits(3)? as u8;
    }
    let lencode = Huffman::<19>::new(&lengths, Fill::Complete)?;
    let mut lens = [0u8; 286 + 30];
    let mut index = 0;
    while index < nlen + ndist {
        let symbol = lencode.decode(br)?;
        if symbol < 16 {
            lens[index] = symbol as u8;
            index += 1;
            continue;
        }
        let (value, repeat) = match symbol {
            16 if index == 0 => return Err(Error::Inflate("repeat with no first length")),
            16 => (lens[index - 1], 3 + br.bits(2)? as usize),
            17 => (0, 3 + br.bits(3)? as usize),
            _ => (0, 11 + br.bits(7)? as usize),
        };
        if index + repeat > nlen + ndist {
            return Err(Error::Inflate("too many code lengths"));
        }
        lens[index..index + repeat].fill(value);
        index += repeat;
    }
    if lens[256] == 0 {
        return Err(Error::Inflate("no end-of-block code"));
    }
    Ok((Huffman::new(&lens[..nlen], Fill::Usable)?, Huffman::new(&lens[nlen..nlen + ndist], Fill::Usable)?))
}

fn codes(
    br: &mut BitReader,
    window: &mut Window,
    out: &mut Out<'_>,
    lit: &Huffman<288>,
    dist: &Huffman<30>,
) -> Result<(), Error> {
    loop {
        let symbol = lit.decode(br)? as usize;
        if symbol < 256 {
            window.put(symbol as u8, out)?;
            continue;
        }
        if symbol == 256 {
            return Ok(());
        }
        let s = symbol - 257;
        if s >= LBASE.len() {
            return Err(Error::Inflate("invalid length code"));
        }
        let len = LBASE[s] as usize + br.bits(LEXT[s] as u32)? as usize;
        let d = dist.decode(br)? as usize;
        if d >= DBASE.len() {
            return Err(Error::Inflate("invalid distance code"));
        }
        let distance = DBASE[d] as usize + br.bits(DEXT[d] as u32)? as usize;
        window.copy(distance, len, out)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut src = data;
        let mut br = BitReader::new(&mut src);
        let mut out = Vec::new();
        inflate(&mut br, &mut |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(out)
    }

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|p| crate::sha256::nibble(p[0]).unwrap() << 4 | crate::sha256::nibble(p[1]).unwrap())
            .collect()
    }

    #[test]
    fn zlib_streams() {
        // zlib.compressobj(9, DEFLATED, -15) output for these inputs.
        assert_eq!(decode(&unhex("0300")).unwrap(), b"");
        assert_eq!(decode(&unhex("4b0400")).unwrap(), b"a");
        assert_eq!(decode(&unhex("cb48cdc9c957c8402701")).unwrap(), b"hello hello hello hello");
        // A stored block: BFINAL=1, BTYPE=00, LEN=3, NLEN=!3, "abc".
        assert_eq!(decode(&unhex("010300fcff616263")).unwrap(), b"abc");
    }

    #[test]
    fn rejects_bad_streams() {
        assert_eq!(decode(&unhex("07")), Err(Error::Inflate("invalid block type")));
        assert_eq!(decode(&unhex("0103000000")), Err(Error::Inflate("stored block length check")));
        assert_eq!(decode(&unhex("010300fcff6162")), Err(Error::Truncated));
        // A fixed block whose first symbol is a match: nothing to copy yet.
        assert_eq!(decode(&unhex("0302")), Err(Error::Inflate("distance too far back")));
        assert_eq!(decode(&[]), Err(Error::Truncated));
    }

    #[test]
    fn huffman_rules() {
        assert!(Huffman::<4>::new(&[1, 1, 1, 0], Fill::Any).is_err(), "over-subscribed");
        assert!(Huffman::<4>::new(&[1, 2, 0, 0], Fill::Usable).is_err(), "incomplete with two codes");
        assert!(Huffman::<4>::new(&[2, 0, 0, 0], Fill::Usable).is_err(), "a lone two-bit code");
        assert!(Huffman::<4>::new(&[1, 0, 0, 0], Fill::Usable).is_ok(), "a lone one-bit code");
        assert!(Huffman::<4>::new(&[0, 0, 0, 0], Fill::Usable).is_ok(), "no codes");
        assert!(Huffman::<4>::new(&[1, 0, 0, 0], Fill::Complete).is_err(), "incomplete code length code");
        assert!(Huffman::<4>::new(&[1, 2, 2, 0], Fill::Complete).is_ok(), "complete");
        assert!(Huffman::<30>::new(&[5; 30], Fill::Any).is_ok(), "the fixed distance code");
    }
}
