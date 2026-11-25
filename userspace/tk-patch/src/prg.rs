//! The vendor .prg container, as far as finding its tk section
//! (scripts/prg-unpack.py has the full layout): an 84-byte big-endian
//! header, then kernel, UBI rootfs and the tk gzip stream.

const MAGIC: [u8; 4] = [0, 0, 0x72, 0x43];
const HEADER_LEN: usize = 0x54;

/// The tk gzip stream inside a .prg, or `None` if `data` is not one.
pub fn tk_section(data: &[u8]) -> Option<&[u8]> {
    if data.len() < HEADER_LEN || data[..4] != MAGIC {
        return None;
    }
    let be32 = |at: usize| u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) as usize;
    let start = HEADER_LEN.checked_add(be32(0x24))?.checked_add(be32(0x28))?;
    data.get(start..start.checked_add(be32(0x2c))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_tk_section() {
        let mut prg = alloc::vec![0u8; HEADER_LEN];
        prg[..4].copy_from_slice(&MAGIC);
        prg[0x24..0x28].copy_from_slice(&3u32.to_be_bytes());
        prg[0x28..0x2c].copy_from_slice(&2u32.to_be_bytes());
        prg[0x2c..0x30].copy_from_slice(&4u32.to_be_bytes());
        prg.extend_from_slice(b"KKKUUtk!!");
        assert_eq!(tk_section(&prg), Some(&b"tk!!"[..]));
        prg.pop();
        assert_eq!(tk_section(&prg), None, "truncated");
        assert_eq!(tk_section(b"\x1f\x8b\x08"), None);
    }
}
