//! Apply a manifest to the stock image as it streams past.

use alloc::vec::Vec;

use crate::Error;
use crate::manifest::{Manifest, Part};
use crate::sha256::{Digest, Sha256};

/// Stock bytes a reference copies, collected as they stream past.
struct Capture {
    from: u64,
    len: usize,
    bytes: Vec<u8>,
}

pub struct Patcher<'m> {
    manifest: &'m Manifest<'m>,
    /// One per reference, in manifest order.
    captures: Vec<Capture>,
    /// The first site not finished yet.
    next: usize,
    /// Site `next`'s replacement, built when the stream reaches the site.
    replacement: Vec<u8>,
    /// Site `next`'s stock bytes so far.
    original: Sha256,
    /// Stream offset of the next byte.
    offset: u64,
    stock: Sha256,
    image: Sha256,
}

impl<'m> Patcher<'m> {
    pub fn new(manifest: &'m Manifest<'m>) -> Self {
        let captures = manifest
            .sites
            .iter()
            .flat_map(|s| &s.parts)
            .filter_map(|p| match *p {
                Part::Stock { va, len } => {
                    Some(Capture { from: (va - manifest.base) as u64, len: len as usize, bytes: Vec::new() })
                }
                Part::Bytes(_) => None,
            })
            .collect();
        Patcher {
            manifest,
            captures,
            next: 0,
            replacement: Vec::new(),
            original: Sha256::new(),
            offset: 0,
            stock: Sha256::new(),
            image: Sha256::new(),
        }
    }

    /// Patch the next stock bytes of the stream in place.
    pub fn apply(&mut self, chunk: &mut [u8]) -> Result<(), Error> {
        let manifest = self.manifest;
        let start = self.offset;
        let end = start + chunk.len() as u64;
        if end > manifest.stock.size {
            return Err(Error::Stock("longer than the stock image"));
        }
        self.stock.update(chunk);
        for c in &mut self.captures {
            let (a, b) = ((c.from + c.bytes.len() as u64).max(start), (c.from + c.len as u64).min(end));
            if a < b {
                c.bytes.extend_from_slice(&chunk[(a - start) as usize..(b - start) as usize]);
            }
        }
        while let Some(site) = manifest.sites.get(self.next) {
            let from = manifest.offset(site);
            let to = from + site.len as u64;
            if from >= end {
                break;
            }
            if self.replacement.is_empty() {
                self.replacement = self.resolve(self.next)?;
            }
            let (a, b) = (from.max(start), to.min(end));
            let here = &mut chunk[(a - start) as usize..(b - start) as usize];
            self.original.update(here);
            here.copy_from_slice(&self.replacement[(a - from) as usize..(b - from) as usize]);
            if to > end {
                break;
            }
            if core::mem::take(&mut self.original).finish() != site.original {
                return Err(Error::Site(self.next));
            }
            self.replacement.clear();
            self.next += 1;
        }
        self.image.update(chunk);
        self.offset = end;
        Ok(())
    }

    /// Site `index`'s replacement. The manifest puts every reference before
    /// its site, so the stream has already passed (and captured) its bytes.
    fn resolve(&self, index: usize) -> Result<Vec<u8>, Error> {
        let site = &self.manifest.sites[index];
        let mut out = Vec::with_capacity(site.len as usize);
        for part in &site.parts {
            match *part {
                Part::Bytes(ref b) => out.extend_from_slice(b),
                Part::Stock { va, len } => {
                    let from = (va - self.manifest.base) as u64;
                    let c = self
                        .captures
                        .iter()
                        .find(|c| c.from == from && c.len == len as usize && c.bytes.len() == c.len)
                        .ok_or(Error::Output("a reference was not captured"))?;
                    out.extend_from_slice(&c.bytes);
                }
            }
        }
        Ok(out)
    }

    /// End of the stream: the stock and patched images must be the pinned ones.
    pub fn finish(self) -> Result<(Digest, Digest), Error> {
        if self.offset != self.manifest.stock.size {
            return Err(Error::Stock("shorter than the stock image"));
        }
        let stock = self.stock.finish();
        if stock != self.manifest.stock.sha256 {
            return Err(Error::Stock("its SHA-256 differs"));
        }
        let image = self.image.finish();
        if image != self.manifest.image.sha256 {
            return Err(Error::Output("the patched image's SHA-256"));
        }
        Ok((stock, image))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sha256::digest;
    use crate::testdata;
    use alloc::format;
    use alloc::string::String;

    pub(crate) struct Fixture {
        pub stock: Vec<u8>,
        pub image: Vec<u8>,
        pub text: String,
    }

    /// A small stock image and a manifest over it: one site of Witcher
    /// bytes, one that also copies stock bytes from earlier in the image.
    pub(crate) fn fixture() -> Fixture {
        let stock = testdata::random_bytes(9, 4096);
        let mut image = stock.clone();
        image[0x100..0x108].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        image[0x200..0x202].copy_from_slice(&[9, 9]);
        image[0x202..0x20a].copy_from_slice(&stock[0x40..0x48]);
        let gz = crate::gzip::compress(&image);
        let text = format!(
            "witcher-tk-manifest 1\nname fixture\nbase 0x84100000\nstock 4096 {}\nimage 4096 {}\ngzip {} {}\n\
             site 0x84100100 8 lit {} 0102030405060708\nsite 0x84100200 10 refs {} 0909 @0x84100040:8\n",
            digest(&stock),
            digest(&image),
            gz.len(),
            digest(&gz),
            digest(&stock[0x100..0x108]),
            digest(&stock[0x200..0x20a]),
        );
        Fixture { stock, image, text }
    }

    fn run(m: &Manifest, stock: &[u8], chunk: usize) -> Result<Vec<u8>, Error> {
        let mut p = Patcher::new(m);
        let mut out = Vec::new();
        for piece in stock.chunks(chunk) {
            let mut piece = piece.to_vec();
            p.apply(&mut piece)?;
            out.extend_from_slice(&piece);
        }
        p.finish()?;
        Ok(out)
    }

    #[test]
    fn patches_in_any_chunking() {
        let f = fixture();
        let m = Manifest::parse(&f.text).unwrap();
        for chunk in [1, 3, 7, 64, 255, 4096] {
            assert!(run(&m, &f.stock, chunk).unwrap() == f.image, "chunks of {chunk}");
        }
    }

    #[test]
    fn refuses_anything_but_the_pinned_stock() {
        let f = fixture();
        let m = Manifest::parse(&f.text).unwrap();
        let flipped = |at: usize| {
            let mut s = f.stock.clone();
            s[at] ^= 1;
            s
        };
        assert_eq!(run(&m, &flipped(0x203), 100), Err(Error::Site(1)));
        assert_eq!(run(&m, &flipped(0x800), 100), Err(Error::Stock("its SHA-256 differs")));
        // A changed reference source changes the image, so the stock hash catches it.
        assert_eq!(run(&m, &flipped(0x41), 100), Err(Error::Stock("its SHA-256 differs")));
        assert_eq!(run(&m, &f.stock[..4000], 100), Err(Error::Stock("shorter than the stock image")));
        let mut longer = f.stock.clone();
        longer.push(0);
        assert_eq!(run(&m, &longer, 100), Err(Error::Stock("longer than the stock image")));
    }

    #[test]
    fn refuses_a_wrong_image_pin() {
        let f = fixture();
        let wrong = f.text.replace(&format!("{}", digest(&f.image)), &"1".repeat(64));
        let m = Manifest::parse(&wrong).unwrap();
        assert_eq!(run(&m, &f.stock, 512), Err(Error::Output("the patched image's SHA-256")));
    }
}
