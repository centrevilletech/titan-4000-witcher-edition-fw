//! A raw NAND partition, read as the vendor kernel's gdm_flash_read reads a
//! tk bank for modem.ko: erase block by erase block in order, skipping the
//! blocks the bad block table marks bad (the image was written around them).
//! Opened read-only; the only ioctl asks whether a block is bad
//! (`titan_sys::mtd::is_bad_block`).

use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::path::Path;

use titan_pd_model::tk_build::Mtd;
use titan_sys::mtd::is_bad_block;
use witcher_tk_patch::{Error, Source};

pub struct GoodBlocks {
    file: File,
    /// False for a plain file standing in for a bank in tests: no bad block table.
    has_bbt: bool,
    size: u64,
    erasesize: u64,
    /// The next flash offset to read.
    pos: u64,
    /// Bad blocks skipped so far.
    pub skipped: u32,
    /// Why the last read failed.
    pub error: Option<io::Error>,
}

impl GoodBlocks {
    /// Open `dev` (a `/dev/mtdN`) read-only. `has_bbt` is false only for a
    /// plain file standing in for the bank in tests.
    pub fn open(dev: &Path, part: &Mtd, has_bbt: bool) -> io::Result<Self> {
        let file = File::open(dev)?;
        Ok(GoodBlocks { file, has_bbt, size: part.size, erasesize: part.erasesize as u64, pos: 0, skipped: 0, error: None })
    }

    fn fail(&mut self, err: io::Error) -> Error {
        self.error = Some(err);
        Error::Read
    }
}

impl Source for GoodBlocks {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        loop {
            if self.pos >= self.size {
                return Ok(0);
            }
            let in_block = self.pos % self.erasesize;
            if in_block == 0 && self.has_bbt {
                match is_bad_block(self.file.as_fd(), self.pos) {
                    Ok(true) => {
                        self.skipped += 1;
                        self.pos += self.erasesize;
                        continue;
                    }
                    Ok(false) => {}
                    Err(e) => return Err(self.fail(e)),
                }
            }
            let want = buf.len().min((self.erasesize - in_block) as usize);
            match self.file.read_at(&mut buf[..want], self.pos) {
                Ok(0) => return Err(self.fail(io::ErrorKind::UnexpectedEof.into())),
                Ok(n) => {
                    self.pos += n as u64;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(self.fail(e)),
            }
        }
    }
}
