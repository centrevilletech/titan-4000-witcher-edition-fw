//! Build a patched Titan modem firmware image (`tk`) from the stock image.
//!
//! Witcher ships no modem firmware bytes. A unit reads its own stock image
//! from a NAND `tk` bank, applies a manifest that holds only Witcher's bytes
//! and hashes, and writes the gzip image the boot loader stages. See
//! docs/tk-patch.md and docs/tk-boot-loader.md.
//!
//! - [`manifest`]: the text format. Each site has a VA, a length, the
//!   SHA-256 of the stock bytes it replaces, and the replacement: Witcher's
//!   bytes, or references to bytes elsewhere in the unit's own stock image.
//! - [`patch`]: applies the sites to the stream, refusing on any mismatch.
//! - [`pipeline`]: stock gzip in, patched gzip out, every size and hash
//!   checked against the manifest.
//! - [`gzip`], [`inflate`], [`deflate`]: the codec. [`deflate`] is zlib
//!   1.3's level-9 path, so the output is byte for byte what Python's
//!   `gzip.compress(data, 9, mtime=0)` writes: the file the bench tested.
//! - [`sha256`], [`crc32`].
//!
//! `no_std` with `alloc`: the codec keeps about 300 KiB of state on the heap.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod crc32;
pub mod deflate;
pub mod gzip;
pub mod inflate;
pub mod manifest;
pub mod manifests;
pub mod patch;
pub mod pipeline;
pub mod prg;
pub mod sha256;
mod trees;

#[cfg(test)]
mod testdata;

pub use manifest::Manifest;

/// Why a build stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The byte source failed. The caller keeps the cause.
    Read,
    /// The byte sink failed. The caller keeps the cause.
    Write,
    /// The input ended inside a gzip member.
    Truncated,
    /// Not a gzip stream, or a gzip trailer that does not match its data.
    Gzip(&'static str),
    /// Corrupt DEFLATE data.
    Inflate(&'static str),
    /// A manifest line breaks a rule (1-based line number).
    Manifest(usize, &'static str),
    /// The input is not the stock image the manifest pins.
    Stock(&'static str),
    /// The stock bytes at this site (index into the sites) do not hash to the
    /// manifest's value.
    Site(usize),
    /// The output differs from what the manifest pins.
    Output(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Read => f.write_str("reading the stock image failed"),
            Error::Write => f.write_str("writing the image failed"),
            Error::Truncated => f.write_str("the gzip stream ends early"),
            Error::Gzip(why) => write!(f, "gzip: {why}"),
            Error::Inflate(why) => write!(f, "deflate data: {why}"),
            Error::Manifest(line, why) => write!(f, "manifest line {line}: {why}"),
            Error::Stock(why) => write!(f, "not the pinned stock image: {why}"),
            Error::Site(index) => write!(f, "site {index}: the stock bytes there differ from the manifest"),
            Error::Output(why) => write!(f, "output differs from the manifest: {why}"),
        }
    }
}

/// Where stock bytes come from: a NAND bank, a file, a slice.
pub trait Source {
    /// Fill the front of `buf`; `Ok(0)` at the end.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error>;
}

/// Where image bytes go.
pub trait Sink {
    fn write(&mut self, data: &[u8]) -> Result<(), Error>;
}

impl Source for &[u8] {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let n = buf.len().min(self.len());
        let (head, rest) = self.split_at(n);
        buf[..n].copy_from_slice(head);
        *self = rest;
        Ok(n)
    }
}

impl Sink for alloc::vec::Vec<u8> {
    fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.extend_from_slice(data);
        Ok(())
    }
}

/// A sink that keeps nothing, for a build that only checks hashes.
pub struct Discard;

impl Sink for Discard {
    fn write(&mut self, _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}
