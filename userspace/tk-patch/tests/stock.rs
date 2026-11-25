//! The carried manifests rebuild the bench images from the stock firmware.
//!
//! Needs the stock .prg in WITCHER_STOCK_PRG (CI downloads it; this tree
//! carries no modem firmware). Without it the test passes with a note,
//! unless WITCHER_REQUIRE_STOCK=1.

use witcher_tk_patch::manifest::Manifest;
use witcher_tk_patch::{Discard, manifests, pipeline, prg};

/// The Python-built bench images (tkpatch.py), from the lanes' SHA256SUMS:
/// manifest, tk.bin SHA-256, tk.gz SHA-256.
const BENCH: [(&str, &str, &str); 6] = [
    (
        manifests::N6H,
        "a2fc899439b938ec4e16ee2c8519587c4e2fffedee52b8a3bb5cdf33daff8168",
        "a1fc066af1cae2848fee47abb67e501fd76977298ab4b77fd1d81e1174fe5cbe",
    ),
    (
        manifests::M1,
        "cd7effdd3c45dced9d434fdb3c4283b14e7c7b7a70fadc457c091a1edab70c6b",
        "e47b04354db5d8280a4fb15e4f9937ca8d94ad18a969ccd11d4c21c72ce1001d",
    ),
    (
        manifests::R1,
        "f434277dfd1aa2db6a3ebc458c339ad90c4b311480558f96952753e5817f82b4",
        "186697f32b8831a35e96ca90745c2f7c20bd6d664d4de51da7bdaf61b9abdd1c",
    ),
    (
        manifests::R4,
        "60ab8fe7d50f6b44d2ece1d08b50bcc72f2b3e45195f71b0a2378369386ce376",
        "4ced9782d5e0143f5c0426ac24b08dabfc90c2afb9d823d022fe98bcae6c9831",
    ),
    (
        manifests::N6H_R4_R1,
        "f1aa8add6a4e4e00c17c3cfe90f51e8b31d75c39751c48cf6ffa5c9f159d1f42",
        "3348aa361c4689c4ff18b647a03bfa55cea36bc6675059cd9995e591592e40bb",
    ),
    (
        manifests::N6H_R4_Q1,
        "832c601a75f3000c9ae62c3dfdf9842bafcbc699136ec826393a6f2c3578bbf6",
        "98a79d3296fa87e95a4fc12d527181db9c3171e637a724986cb45a333f6a986f",
    ),
];

fn stock_prg() -> Option<Vec<u8>> {
    match std::env::var_os("WITCHER_STOCK_PRG") {
        Some(path) => Some(std::fs::read(path).expect("read WITCHER_STOCK_PRG")),
        None => {
            assert!(
                std::env::var("WITCHER_REQUIRE_STOCK").as_deref() != Ok("1"),
                "WITCHER_REQUIRE_STOCK=1 but WITCHER_STOCK_PRG is not set"
            );
            eprintln!("skipped: set WITCHER_STOCK_PRG to the stock .prg");
            None
        }
    }
}

#[test]
fn manifests_rebuild_the_bench_images() {
    let Some(prg) = stock_prg() else { return };
    let tk = prg::tk_section(&prg).expect("a .prg with a tk section");
    for (text, image, gzip) in BENCH {
        let m = Manifest::parse(text).unwrap();
        assert_eq!((m.image.sha256.to_string(), m.gzip.sha256.to_string()), (image.into(), gzip.into()), "{}", m.name);
        // The unit's path: the stock gzip stream in, the gzip image out.
        let built = pipeline::from_gzip(&m, &mut &tk[..], &mut Discard).unwrap();
        assert_eq!((built.image.to_string(), built.gzip.to_string()), (image.into(), gzip.into()), "{}", m.name);
        assert_eq!(built.gzip_size, m.gzip.size);
    }
}

#[test]
fn the_release_is_a_bench_image() {
    assert!(BENCH.iter().any(|(text, _, _)| *text == manifests::RELEASE));
}

/// A manifest without its bench hashes here would skip the byte-for-byte proof.
#[test]
fn every_carried_manifest_has_bench_hashes() {
    for text in manifests::ALL {
        let name = Manifest::parse(text).unwrap().name;
        assert!(BENCH.iter().any(|(t, _, _)| *t == text), "{name}: add its bench hashes to BENCH");
    }
}
