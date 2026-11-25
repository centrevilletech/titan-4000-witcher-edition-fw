//! tk-patch: the host side of the on-unit modem image builder.
//!
//! - `manifest STOCK SPEC NAME -o OUT [--image TK.BIN] [--gzip TK.GZ]`:
//!   turn a tkpatch.py spec into a manifest. `--image` and `--gzip` check
//!   the result against the Python-built image byte for byte.
//! - `build STOCK MANIFEST [-o DIR]`: build as the unit does and print the
//!   hashes; with `-o`, write DIR/tk.gz and DIR/tk.bin (DIR must not exist).
//! - `show MANIFEST`: the sites, their sizes and stock references.
//! - `gzip`, `gunzip`: stdin to stdout with the builder's codec (zlib level
//!   9 exactly, and the strict decoder), for cross-checks against zlib.
//!
//! STOCK is the stock .prg, its tk gzip stream (03_tk.gzip or a NAND bank
//! dump), or the decompressed tk.bin.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::{env, fs, process};

use witcher_tk_patch::manifest::{Manifest, Part};
use witcher_tk_patch::sha256::digest;
use witcher_tk_patch::{Error, gzip, pipeline, prg};

mod spec;

const USAGE: &str = "usage: tk-patch manifest STOCK SPEC NAME -o OUT [--image TK.BIN] [--gzip TK.GZ]
       tk-patch build STOCK MANIFEST [-o DIR]
       tk-patch show MANIFEST
       tk-patch gzip|gunzip < IN > OUT";

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    let result = match args.first().map(String::as_str) {
        Some("manifest") => manifest(rest),
        Some("build") => build(rest),
        Some("show") => show(rest),
        Some("gzip") => filter(true),
        Some("gunzip") => filter(false),
        _ => Err(USAGE.into()),
    };
    if let Err(err) = result {
        eprintln!("tk-patch: {err}");
        process::exit(1);
    }
}

/// Positional arguments, and `--option VALUE` pairs from `known`.
fn split<'a>(args: &'a [String], known: &[&str]) -> Result<(Vec<&'a str>, HashMap<&'a str, &'a str>), String> {
    let (mut pos, mut opts) = (Vec::new(), HashMap::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if known.contains(&a.as_str()) {
            let v = it.next().ok_or(format!("{a} needs a value"))?;
            opts.insert(a.as_str(), v.as_str());
        } else if a.starts_with('-') {
            return Err(format!("unknown option {a}\n{USAGE}"));
        } else {
            pos.push(a.as_str());
        }
    }
    Ok((pos, opts))
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("{path}: {e}"))
}

/// The stock tk image's gzip stream, or `None` and the raw image.
fn stock(path: &str) -> Result<(Option<Vec<u8>>, Vec<u8>), String> {
    let data = read(path)?;
    let data = match prg::tk_section(&data).map(<[u8]>::to_vec) {
        Some(tk) => tk,
        None => data,
    };
    if !data.starts_with(&[0x1f, 0x8b]) {
        return Ok((None, data));
    }
    let mut raw = Vec::new();
    gzip::decompress(&mut &data[..], &mut |c| {
        raw.extend_from_slice(c);
        Ok(())
    })
    .map_err(|e| format!("{path}: {e}"))?;
    Ok((Some(data), raw))
}

/// An error, with the site's name when it is about one.
fn explain(m: &Manifest, err: Error) -> String {
    match err {
        Error::Site(i) => format!("site {} at {:#010x}: the stock bytes there differ from the manifest", m.sites[i].name, m.sites[i].va),
        other => other.to_string(),
    }
}

fn manifest(args: &[String]) -> Result<(), String> {
    let (pos, opts) = split(args, &["-o", "--image", "--gzip"])?;
    let (&[stock_path, spec_path, name], Some(out)) = (&pos[..], opts.get("-o")) else {
        return Err(USAGE.into());
    };
    let (_, raw) = stock(stock_path)?;
    if raw.len() != spec::STOCK_SIZE || digest(&raw).to_string() != spec::STOCK_SHA256 {
        return Err("unknown stock image".into());
    }
    let spec = spec::parse(&fs::read_to_string(spec_path).map_err(|e| format!("{spec_path}: {e}"))?)?;
    let (text, image) = spec::manifest(&raw, &spec, name)?;
    let m = Manifest::parse(&text).map_err(|e| e.to_string())?;
    // Build it back the way the unit will, and compare with Python's images.
    let mut packed = Vec::new();
    pipeline::from_raw(&m, &mut &raw[..], &mut packed).map_err(|e| explain(&m, e))?;
    if let Some(path) = opts.get("--image") {
        if read(path)? != image {
            return Err(format!("the patched image differs from {path}"));
        }
    }
    if let Some(path) = opts.get("--gzip") {
        if read(path)? != packed {
            return Err(format!("the gzip image differs from {path}"));
        }
    }
    fs::write(out, &text).map_err(|e| format!("{out}: {e}"))?;
    let refs: usize = m.sites.iter().flat_map(|s| &s.parts).filter(|p| matches!(p, Part::Stock { .. })).count();
    println!("{out}: {} sites, {} bytes, {refs} stock references", m.sites.len(), image.len());
    println!("image {} {}\ngzip {} {}", m.image.size, m.image.sha256, m.gzip.size, m.gzip.sha256);
    Ok(())
}

fn build(args: &[String]) -> Result<(), String> {
    let (pos, opts) = split(args, &["-o"])?;
    let &[stock_path, manifest_path] = &pos[..] else {
        return Err(USAGE.into());
    };
    let text = fs::read_to_string(manifest_path).map_err(|e| format!("{manifest_path}: {e}"))?;
    let m = Manifest::parse(&text).map_err(|e| e.to_string())?;
    let (packed, raw) = stock(stock_path)?;
    let mut out = Vec::new();
    let built = match &packed {
        Some(gz) => pipeline::from_gzip(&m, &mut &gz[..], &mut out),
        None => pipeline::from_raw(&m, &mut &raw[..], &mut out),
    }
    .map_err(|e| explain(&m, e))?;
    println!("{}: stock {} image {} gzip {} ({} bytes)", m.name, built.stock, built.image, built.gzip, built.gzip_size);
    if let Some(dir) = opts.get("-o") {
        // A fresh directory, like tkpatch.py: never overwrite a candidate.
        fs::create_dir(dir).map_err(|e| format!("{dir}: {e}"))?;
        let mut image = Vec::new();
        gzip::decompress(&mut &out[..], &mut |c| {
            image.extend_from_slice(c);
            Ok(())
        })
        .map_err(|e| e.to_string())?;
        fs::write(Path::new(dir).join("tk.gz"), &out).map_err(|e| e.to_string())?;
        fs::write(Path::new(dir).join("tk.bin"), &image).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn show(args: &[String]) -> Result<(), String> {
    let [path] = args else {
        return Err(USAGE.into());
    };
    let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let m = Manifest::parse(&text).map_err(|e| e.to_string())?;
    println!("{} (base {:#010x})", m.name, m.base);
    for (key, pin) in [("stock", m.stock), ("image", m.image), ("gzip", m.gzip)] {
        println!("  {key:5} {:>8} {}", pin.size, pin.sha256);
    }
    let mut witcher = 0;
    for s in &m.sites {
        let mut parts = Vec::new();
        for p in &s.parts {
            match p {
                Part::Bytes(b) => {
                    witcher += b.len();
                    parts.push(format!("{} B", b.len()));
                }
                Part::Stock { va, len } => parts.push(format!("{len} B from stock {va:#010x}")),
            }
        }
        println!("  {:#010x} {:>5} {:40} {}", s.va, s.len, s.name, parts.join(" + "));
    }
    println!("{} sites, {witcher} bytes of Witcher's own", m.sites.len());
    Ok(())
}

fn filter(compress: bool) -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).map_err(|e| e.to_string())?;
    let output = if compress {
        gzip::compress(&input)
    } else {
        let mut out = Vec::new();
        gzip::decompress(&mut &input[..], &mut |c| {
            out.extend_from_slice(c);
            Ok(())
        })
        .map_err(|e| e.to_string())?;
        out
    };
    std::io::stdout().write_all(&output).map_err(|e| e.to_string())
}
