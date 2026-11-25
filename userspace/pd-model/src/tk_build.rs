//! Decisions for `titan-pd-keeper tk-build`, which builds the patched modem
//! image on the unit from its own stock firmware (docs/tk-patch.md).
//!
//! The builder writes exactly two files on the Witcher volume: `tk/active.gz`
//! and `tk/config`. Strikes, quarantine and the load itself stay with the
//! boot hook and the boot confirm (docs/tk-boot-loader.md); this module only
//! reads them to say why the next boot would still keep stock firmware.

/// The NAND banks the vendor kernel loads tk from, in the order the builder
/// tries them. Either one serves if it holds the exact stock image.
pub const BANKS: [&str; 2] = ["tk", "tk2"];

/// The boot hook's strike limit (`limit` in witcher-tk-stage).
const STRIKE_LIMIT: u32 = crate::tk_boot::STRIKE_LIMIT;

/// One raw flash partition from /proc/mtd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mtd {
    pub index: u32,
    pub size: u64,
    pub erasesize: u32,
}

/// The partition named `name` in /proc/mtd (`mtd17: 00800000 00020000 "tk"`).
/// `None` unless its size is a whole number of erase blocks.
pub fn find_mtd(proc_mtd: &str, name: &str) -> Option<Mtd> {
    let quoted = format!("\"{name}\"");
    proc_mtd.lines().find_map(|line| {
        let (dev, rest) = line.split_once(':')?;
        let index = dev.strip_prefix("mtd")?.parse().ok()?;
        let mut fields = rest.split_whitespace();
        let size = u64::from_str_radix(fields.next()?, 16).ok()?;
        let erasesize = u32::from_str_radix(fields.next()?, 16).ok()?;
        let named = fields.next()? == quoted && fields.next().is_none();
        let whole = erasesize > 0 && size > 0 && size % erasesize as u64 == 0;
        (named && whole).then_some(Mtd { index, size, erasesize })
    })
}

/// The bank this boot runs, from `/proc/cmdline`: the boot loader names the
/// active kernel, rootfs and tk partitions (`active=linux2,rootfs2,tk2`).
/// `None` when it names no bank in `BANKS`.
pub fn active_bank(cmdline: &str) -> Option<&'static str> {
    let list = cmdline.split_whitespace().find_map(|word| word.strip_prefix("active="))?;
    list.split(',').find_map(|part| BANKS.into_iter().find(|bank| *bank == part))
}

/// tk/config with the built image staged: `enabled=1` and one `sha256=` line
/// for it, then every other line of the old config in order (`target=`,
/// `wm=`, `manage=`, `hold_ack=`, comments). The lines the hook reads as
/// its switch and allow-list (`enabled=...`, `sha256=...`) are replaced, and
/// a default config's marker is dropped: an operator staged this one.
pub fn staged_config(old: &str, sha: &str) -> String {
    let mut out = format!("enabled=1\nsha256={sha}\n");
    for line in old.lines() {
        if !line.starts_with("enabled=")
            && !line.starts_with("sha256=")
            && !line.starts_with(crate::tk_default::MARKER)
        {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// A value as the hook's `value` reads it: comment and blanks removed.
fn cleaned(raw: &str) -> String {
    let raw = raw.split('#').next().unwrap_or_default();
    raw.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Why the boot hook would still load stock firmware with `sha` staged:
/// the strike count or the quarantine list. The builder only reports these.
pub fn loader_refusals(sha: &str, strikes: Option<&str>, quarantine: Option<&str>) -> Vec<String> {
    let mut why = Vec::new();
    if let Some(text) = strikes {
        let value = text.lines().filter_map(|l| l.strip_prefix("strikes=")).last().map(cleaned).unwrap_or_default();
        // The hook's rule: one to three digits.
        let digits = (1..=3).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit());
        match value.parse::<u32>() {
            Ok(n) if digits && n >= STRIKE_LIMIT => why.push(format!(
                "tk/strikes is {n}: the hook keeps stock firmware until it reads strikes=0 (write it to try again)"
            )),
            Ok(_) if digits => {}
            _ => why.push("tk/strikes holds no count: the hook keeps stock firmware".to_owned()),
        }
    }
    if let Some(text) = quarantine {
        if text.lines().any(|l| cleaned(l).eq_ignore_ascii_case(sha)) {
            why.push(format!("{sha} is in tk/quarantine: the keeper rolled it back before (remove the line to try again)"));
        }
    }
    why
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_MTD: &str = "dev:    size   erasesize  name\n\
        mtd16: 03c00000 00020000 \"rootfs2\"\n\
        mtd17: 00800000 00020000 \"tk\"\n\
        mtd18: 00800000 00020000 \"tk2\"\n\
        mtd20: 04000000 00020000 \"user\"\n";

    #[test]
    fn finds_the_tk_banks_by_name() {
        assert_eq!(find_mtd(PROC_MTD, "tk"), Some(Mtd { index: 17, size: 0x80_0000, erasesize: 0x2_0000 }));
        assert_eq!(find_mtd(PROC_MTD, "tk2").map(|m| m.index), Some(18));
        assert_eq!(find_mtd(PROC_MTD, "t"), None);
        assert_eq!(find_mtd(PROC_MTD, "misc"), None);
        assert_eq!(find_mtd("mtd17: 00800001 00020000 \"tk\"\n", "tk"), None, "not whole erase blocks");
        assert_eq!(find_mtd("mtd17: 00800000 00000000 \"tk\"\n", "tk"), None);
    }

    #[test]
    fn the_active_bank_comes_from_the_boot_loaders_command_line() {
        let line = "root=ubi0:rootfs ro rootfstype=ubifs ubi.mtd=16,2048 console=ttyS0 active=linux2,rootfs2,tk2\n";
        assert_eq!(active_bank(line), Some("tk2"));
        assert_eq!(active_bank("ubi.mtd=15 active=linux,rootfs,tk"), Some("tk"));
        assert_eq!(active_bank("ubi.mtd=15 active=linux,rootfs"), None);
        assert_eq!(active_bank("ubi.mtd=15 active=linux,rootfs,tk3"), None);
        assert_eq!(active_bank("inactive=tk2 bank=tk"), None);
        assert_eq!(active_bank(""), None);
    }

    #[test]
    fn staging_over_a_default_config_makes_it_the_operators() {
        let default = crate::tk_default::config_text("n6h-r4-r1", &"ab".repeat(32));
        let staged = staged_config(&default, "cccc");
        assert!(staged.starts_with("enabled=1\nsha256=cccc\n# Built at boot"), "{staged}");
        assert!(!staged.contains("witcher-default"));
        assert_eq!(crate::tk_default::default_sha(&staged), None);
        assert_eq!(staged.lines().filter(|l| l.starts_with("wm=")).count(), crate::tk_default::WORDS.len());
    }

    #[test]
    fn staging_replaces_only_the_switch_and_allow_list() {
        let old = "# bench\nenabled=0\nsha256=aaaa\ntarget=192.0.2.1\nsha256=bbbb # old\nwm=0x847ed604:0x15\nmanage=off\n";
        assert_eq!(
            staged_config(old, "cccc"),
            "enabled=1\nsha256=cccc\n# bench\ntarget=192.0.2.1\nwm=0x847ed604:0x15\nmanage=off\n"
        );
        assert_eq!(staged_config("", "cccc"), "enabled=1\nsha256=cccc\n");
        assert_eq!(staged_config("wm=0x1:0x2", "cccc"), "enabled=1\nsha256=cccc\nwm=0x1:0x2\n");
    }

    #[test]
    fn reports_what_would_keep_stock_firmware() {
        let sha = "ab".repeat(32);
        assert!(loader_refusals(&sha, None, None).is_empty());
        assert!(loader_refusals(&sha, Some("strikes=1\n"), Some("# none\n")).is_empty());
        assert_eq!(loader_refusals(&sha, Some("strikes=2\n"), None).len(), 1);
        assert_eq!(loader_refusals(&sha, Some("strikes=0\nstrikes= 2 # rollback\n"), None).len(), 1);
        assert_eq!(loader_refusals(&sha, Some("strikes=x\n"), None).len(), 1);
        assert_eq!(loader_refusals(&sha, Some("strikes=+1\n"), None).len(), 1, "the hook wants digits only");
        assert_eq!(loader_refusals(&sha, Some("# empty\n"), None).len(), 1);
        assert_eq!(loader_refusals(&sha, Some("strikes=0\n"), Some(&format!("{}\n", sha.to_uppercase()))).len(), 1);
    }
}
