//! Stock image in, patched gzip image out, in one pass and about 400 KiB of
//! memory. Every size and hash must match the manifest; on any error the
//! caller must throw away what the sink received.

use alloc::vec::Vec;

use crate::gzip;
use crate::manifest::Manifest;
use crate::patch::Patcher;
use crate::sha256::{Digest, Sha256};
use crate::{Error, Sink, Source};

/// What a build produced, all checked against the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Built {
    pub stock: Digest,
    pub image: Digest,
    pub gzip: Digest,
    pub gzip_size: u64,
}

/// Counts and hashes what passes to the real sink.
struct Counted<'s> {
    sink: &'s mut dyn Sink,
    sha: Sha256,
    size: u64,
}

impl Sink for Counted<'_> {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.sha.update(data);
        self.size += data.len() as u64;
        self.sink.write(data)
    }
}

struct Build<'m, 's> {
    manifest: &'m Manifest<'m>,
    patcher: Patcher<'m>,
    writer: gzip::Writer,
    out: Counted<'s>,
    scratch: Vec<u8>,
}

impl<'m, 's> Build<'m, 's> {
    fn new(manifest: &'m Manifest<'m>, sink: &'s mut dyn Sink) -> Result<Self, Error> {
        let mut out = Counted { sink, sha: Sha256::new(), size: 0 };
        let writer = gzip::Writer::new(&mut out)?;
        Ok(Build { manifest, patcher: Patcher::new(manifest), writer, out, scratch: Vec::new() })
    }

    fn feed(&mut self, stock: &[u8]) -> Result<(), Error> {
        self.scratch.clear();
        self.scratch.extend_from_slice(stock);
        self.patcher.apply(&mut self.scratch)?;
        self.writer.write(&self.scratch, &mut self.out)
    }

    fn finish(self) -> Result<Built, Error> {
        let Build { manifest, patcher, writer, mut out, .. } = self;
        let (stock, image) = patcher.finish()?;
        writer.finish(&mut out)?;
        let gzip = out.sha.finish();
        if out.size != manifest.gzip.size || gzip != manifest.gzip.sha256 {
            return Err(Error::Output("the gzip image"));
        }
        Ok(Built { stock, image, gzip, gzip_size: out.size })
    }
}

/// Build from the stock gzip stream (a NAND tk bank, or 03_tk.gzip).
pub fn from_gzip(manifest: &Manifest, src: &mut dyn Source, sink: &mut dyn Sink) -> Result<Built, Error> {
    let mut build = Build::new(manifest, sink)?;
    gzip::decompress(src, &mut |chunk| build.feed(chunk))?;
    build.finish()
}

/// Build from the decompressed stock image.
pub fn from_raw(manifest: &Manifest, src: &mut dyn Source, sink: &mut dyn Sink) -> Result<Built, Error> {
    let mut build = Build::new(manifest, sink)?;
    let mut buf = alloc::vec![0u8; 32 * 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            return build.finish();
        }
        build.feed(&buf[..n])?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::tests::fixture;
    use crate::sha256::digest;
    use alloc::format;

    #[test]
    fn builds_the_pinned_gzip_from_either_input() {
        let f = fixture();
        let m = Manifest::parse(&f.text).unwrap();
        let want = gzip::compress(&f.image);
        let packed = gzip::compress(&f.stock);
        let mut out = Vec::new();
        let built = from_gzip(&m, &mut &packed[..], &mut out).unwrap();
        assert!(out == want);
        assert_eq!(built, Built { stock: digest(&f.stock), image: digest(&f.image), gzip: digest(&want), gzip_size: want.len() as u64 });
        let mut raw_out = Vec::new();
        assert_eq!(from_raw(&m, &mut &f.stock[..], &mut raw_out), Ok(built));
        assert!(raw_out == want);
    }

    #[test]
    fn stops_on_the_first_problem() {
        let f = fixture();
        let m = Manifest::parse(&f.text).unwrap();
        let mut damaged = gzip::compress(&f.stock);
        let n = damaged.len();
        damaged[n - 6] ^= 1;
        assert_eq!(from_gzip(&m, &mut &damaged[..], &mut crate::Discard), Err(Error::Gzip("CRC-32 differs from the trailer")));
        let other = gzip::compress(&f.image);
        assert!(matches!(from_gzip(&m, &mut &other[..], &mut crate::Discard), Err(Error::Site(_))));
        let wrong = f.text.replace(&format!("{}", digest(&gzip::compress(&f.image))), &"2".repeat(64));
        let m = Manifest::parse(&wrong).unwrap();
        assert_eq!(from_raw(&m, &mut &f.stock[..], &mut crate::Discard), Err(Error::Output("the gzip image")));
    }

    #[test]
    fn carried_manifests_pin_loadable_images() {
        for text in crate::manifests::ALL {
            let m = Manifest::parse(text).unwrap();
            assert!(m.gzip.size < gzip::LOADER_MAX_BYTES);
        }
        assert!(gzip::modem_reads(&gzip::HEADER));
    }
}
