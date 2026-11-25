//! gzip (RFC 1952) framing for modem images.

use crate::crc32::Crc32;
use crate::deflate::Deflater;
use crate::inflate::{BitReader, inflate};
use crate::{Error, Sink, Source};

/// The header tkpatch.py writes: deflate, no flags, mtime 0, XFL 2 (level 9),
/// OS 3 (Unix).
pub const HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 3];

/// Largest image the boot hook stages (`max_bytes` in
/// overlay/etc/init.d/witcher-tk-stage).
pub const LOADER_MAX_BYTES: u64 = 7_864_320;
/// Smallest image the boot hook stages.
pub const LOADER_MIN_BYTES: u64 = 1024;

/// The boot hook's `header` rule, which is also what the modem's own reader
/// (lib/inflate.c in modem.ko) accepts: magic 1f 8b, method 8, and none of
/// the continuation (0x02), encrypted (0x20) or reserved (0xc0) flag bits.
pub fn modem_reads(header: &[u8]) -> bool {
    matches!(header, [0x1f, 0x8b, 8, flags, ..] if flags & 0xe2 == 0)
}

/// Decompress the first gzip member of `src` into `out`, checking the
/// trailer's CRC-32 and length. Whatever follows the member (NAND padding)
/// is not read beyond the reader's buffer. Returns the decompressed size.
pub fn decompress(src: &mut dyn Source, out: &mut dyn FnMut(&[u8]) -> Result<(), Error>) -> Result<u64, Error> {
    let mut br = BitReader::new(src);
    let mut head = [0u8; 10];
    for b in &mut head {
        *b = br.byte()?;
    }
    if head[..3] != [0x1f, 0x8b, 8] {
        return Err(Error::Gzip("not a gzip deflate stream"));
    }
    let flags = head[3];
    if flags & 0xe0 != 0 {
        return Err(Error::Gzip("reserved header flags"));
    }
    if flags & 0x04 != 0 {
        let len = br.byte()? as usize | (br.byte()? as usize) << 8;
        for _ in 0..len {
            br.byte()?;
        }
    }
    for field in [0x08, 0x10] {
        if flags & field != 0 {
            while br.byte()? != 0 {}
        }
    }
    if flags & 0x02 != 0 {
        br.byte()?;
        br.byte()?;
    }
    let mut crc = Crc32::new();
    let mut size = 0u64;
    inflate(&mut br, &mut |chunk| {
        crc.update(chunk);
        size += chunk.len() as u64;
        out(chunk)
    })?;
    br.align();
    let mut trailer = [0u8; 8];
    for b in &mut trailer {
        *b = br.byte()?;
    }
    if u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]) != crc.value() {
        return Err(Error::Gzip("CRC-32 differs from the trailer"));
    }
    if u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]) != size as u32 {
        return Err(Error::Gzip("length differs from the trailer"));
    }
    Ok(size)
}

/// Writes one gzip member: [`HEADER`], zlib-exact level 9 data, trailer.
pub struct Writer {
    deflater: Deflater,
    crc: Crc32,
    size: u32,
}

impl Writer {
    pub fn new(sink: &mut dyn Sink) -> Result<Self, Error> {
        sink.write(&HEADER)?;
        Ok(Writer { deflater: Deflater::new(), crc: Crc32::new(), size: 0 })
    }

    pub fn write(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        self.crc.update(data);
        self.size = self.size.wrapping_add(data.len() as u32);
        self.deflater.write(data, sink)
    }

    pub fn finish(self, sink: &mut dyn Sink) -> Result<(), Error> {
        self.deflater.finish(sink)?;
        sink.write(&self.crc.value().to_le_bytes())?;
        sink.write(&self.size.to_le_bytes())
    }
}

/// gzip of `data` in one call, as `gzip.compress(data, 9, mtime=0)` with OS 3.
pub fn compress(data: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    // Vec sinks cannot fail.
    if let Ok(mut w) = Writer::new(&mut out) {
        let _ = w.write(data, &mut out);
        let _ = w.finish(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata;
    use alloc::vec;
    use alloc::vec::Vec;

    fn gunzip(data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut src = data;
        let mut out = Vec::new();
        decompress(&mut src, &mut |c| {
            out.extend_from_slice(c);
            Ok(())
        })?;
        Ok(out)
    }

    #[test]
    fn header_is_one_the_modem_reads() {
        assert!(modem_reads(&HEADER));
        assert!(modem_reads(&[0x1f, 0x8b, 8, 0x08]), "FNAME is fine");
        assert!(!modem_reads(&[0x1f, 0x8b, 8, 0x02]), "continuation / FHCRC");
        assert!(!modem_reads(&[0x1f, 0x8b, 8, 0x20]), "encrypted");
        assert!(!modem_reads(&[0x1f, 0x8b, 8, 0x40]), "reserved");
        assert!(!modem_reads(&[0x1f, 0x8b, 9, 0]), "method");
        assert!(!modem_reads(&[0xfd, 0x37, 0x7a, 0x58]), "xz");
        assert!(!modem_reads(&[0x1f, 0x8b]), "short");
    }

    #[test]
    fn round_trip_with_padding_after_the_member() {
        let data = testdata::mixed(5, 300);
        let mut packed = compress(&data);
        assert_eq!(packed[..10], HEADER);
        packed.extend_from_slice(&[0xff; 5000]);
        assert!(gunzip(&packed).unwrap() == data);
    }

    #[test]
    fn python_gzip_with_optional_fields() {
        // gzip.GzipFile(filename='tk', mtime=0) adds FNAME; this one also has
        // FEXTRA and FCOMMENT, built by hand around the raw deflate of "abc".
        let mut packed = vec![0x1f, 0x8b, 8, 0x1c, 0, 0, 0, 0, 2, 3];
        packed.extend_from_slice(&[2, 0, b'x', b'y']);
        packed.extend_from_slice(b"tk\0");
        packed.extend_from_slice(b"note\0");
        packed.extend_from_slice(&crate::deflate::deflate(b"abc"));
        packed.extend_from_slice(&0x3524_41c2u32.to_le_bytes());
        packed.extend_from_slice(&3u32.to_le_bytes());
        assert_eq!(gunzip(&packed).unwrap(), b"abc");
    }

    #[test]
    fn rejects_damaged_members() {
        let packed = compress(b"hello hello hello");
        let mut crc = packed.clone();
        let n = crc.len();
        crc[n - 8] ^= 1;
        assert_eq!(gunzip(&crc), Err(Error::Gzip("CRC-32 differs from the trailer")));
        let mut len = packed.clone();
        len[n - 1] ^= 1;
        assert_eq!(gunzip(&len), Err(Error::Gzip("length differs from the trailer")));
        assert_eq!(gunzip(&packed[..n - 3]), Err(Error::Truncated));
        assert_eq!(gunzip(b"\x1f\x8b\x09\0\0\0\0\0\0\x03"), Err(Error::Gzip("not a gzip deflate stream")));
        assert_eq!(gunzip(b"\x1f\x8b\x08\x80\0\0\0\0\0\x03"), Err(Error::Gzip("reserved header flags")));
    }
}
