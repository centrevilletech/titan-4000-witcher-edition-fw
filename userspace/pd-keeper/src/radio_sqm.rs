//! CAKE occupies the customer bearer root and the keeper's ordinary-traffic
//! Ethernet band. Reserve explicit handles so cleanup can recognize each slot.
//!
//! Both directions run `diffserv4`. Hosts are told apart by the far end:
//! `dual-dsthost` on upload and `dual-srchost` on download, with `nonat`. In
//! IP passthrough every IPv4 device in the home shares the router's one WAN
//! address, so the default `triple-isolate` counted all of the home's bulk
//! flows against that one host and shrank a new game or call flow's first
//! quantum (300 bytes at 9 Mbit/s, divided by the number of bulk flows) until
//! it fell out of the sparse queue. Grouping by the remote host keeps it.
//! With `classify` on, the Stage 1 filters in `titan_pd_model::sqm_classes`
//! sit on each CAKE qdisc and are checked after every apply.
//!
//! The rootfs has no room for the tools, so they are not in the image. An
//! operator stages `tc` and `sch_cake.ko` from the repository's
//! `device/sqm/payload` in `/mnt/titan-api/sqm`. Only bytes matching the
//! digests built into the keeper are copied into the keeper's private runtime
//! directory and used from there.
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
};
use titan_pd_model::{sha256, sqm_classes};

const STAGED: &str = "/mnt/titan-api/sqm";
const DIR: &str = "/tmp/titan-pd-keeper/sqm";
const MANIFEST: &str = include_str!("../../../device/sqm/SHA256SUMS");
const UP: &str = "lte0pdn2";
const DOWN: &str = "eth0";

/// Copy the staged tools into the private runtime directory once their bytes
/// match the pinned digests. A copy already there is checked again first.
fn stage() -> io::Result<()> {
    let dir = Path::new(DIR);
    if !dir.is_dir() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .or_else(|e| if dir.is_dir() { Ok(()) } else { Err(e) })?;
    }
    for (name, mode) in [("tc", 0o700), ("sch_cake.ko", 0o600)] {
        let want = sha256::pinned(MANIFEST, name)
            .ok_or_else(|| io::Error::other("SQM manifest incomplete"))?;
        let dest = dir.join(name);
        if fs::read(&dest).is_ok_and(|b| sha256::hex(&sha256::digest(&b)) == want) {
            continue;
        }
        let bytes = fs::read(Path::new(STAGED).join(name)).map_err(|_| {
            io::Error::other(format!("SQM payload {name} is not staged in {STAGED}"))
        })?;
        if sha256::hex(&sha256::digest(&bytes)) != want {
            return Err(io::Error::other(format!("SQM payload {name} digest mismatch")));
        }
        let tmp = dir.join(format!(".{name}.{}", std::process::id()));
        let _ = fs::remove_file(&tmp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, &dest)?;
    }
    Ok(())
}

fn tc(args: &[&str]) -> io::Result<Vec<u8>> {
    let out = Command::new(format!("{DIR}/tc")).args(args).output()?;
    if !out.status.success() {
        return Err(io::Error::other("tc failed"));
    }
    Ok(out.stdout)
}
/// One `tc` process for many commands. Without `force` it stops at the first
/// failure and reports it; with `force` it runs every line.
fn tc_batch(lines: &[String], force: bool) -> io::Result<()> {
    let mut args = vec!["-batch", "-"];
    if force {
        args.insert(0, "-force");
    }
    let mut child = Command::new(format!("{DIR}/tc"))
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut text = lines.join("\n");
    text.push('\n');
    let wrote = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("tc stdin unavailable"))?
        .write_all(text.as_bytes());
    let status = child.wait()?;
    wrote?;
    if !force && !status.success() {
        return Err(io::Error::other("tc batch failed"));
    }
    Ok(())
}
/// Install, keep or remove the traffic classes on one of our CAKE qdiscs,
/// then count them again. Anything else attached there is a mismatch.
fn classes(dev: &str, handle: &str, want: bool) -> io::Result<()> {
    let parent = format!("{handle}:");
    let count = || -> io::Result<usize> {
        let listing = tc(&["filter", "show", "dev", dev, "parent", &parent])?;
        Ok(sqm_classes::installed(&String::from_utf8_lossy(&listing)))
    };
    let lines = if want {
        sqm_classes::batch(dev, handle)
    } else {
        Vec::new()
    };
    let have = count()?;
    if have == lines.len() {
        return Ok(());
    }
    if have > 0 {
        tc_batch(&sqm_classes::removal(dev, handle), true)?;
    }
    if !lines.is_empty() {
        if let Err(e) = tc_batch(&lines, false) {
            // Leave no half list behind; the caller reverts the profile.
            let _ = tc_batch(&sqm_classes::removal(dev, handle), true);
            return Err(e);
        }
    }
    if count()? != lines.len() {
        return Err(io::Error::other("SQM classes read-back mismatch"));
    }
    Ok(())
}
fn rows(dev: &str) -> io::Result<Vec<Value>> {
    Ok(serde_json::from_slice(&tc(&[
        "-j", "-s", "qdisc", "show", "dev", dev,
    ])?)?)
}
fn owned(row: &Value, dev: &str) -> bool {
    row["kind"] == "cake"
        && if dev == UP {
            row["handle"] == "ca01:" && row["root"] == true
        } else {
            row["handle"] == "ca02:" && row["parent"] == "1:2"
        }
}
fn plan(dev: &str, q: &[Value], rate: Option<u32>) -> io::Result<Option<Vec<String>>> {
    let up = dev == UP;
    let slot = q.iter().find(|row| {
        if up {
            row["root"] == true
        } else {
            row["parent"] == "1:2"
        }
    });
    let ours = slot.is_some_and(|r| owned(r, dev));
    let keeper_root = q
        .iter()
        .any(|r| r["kind"] == "prio" && r["handle"] == "1:" && r["root"] == true);
    let drop_band = q
        .iter()
        .any(|r| r["kind"] == "blackhole" && r["handle"] == "30:" && r["parent"] == "1:3");
    let str_args = |words: &[&str]| words.iter().map(|w| (*w).to_string()).collect();
    let Some(rate) = rate else {
        if !ours {
            return Ok(None);
        }
        if up {
            return Ok(Some(str_args(&[
                "qdisc", "del", "dev", UP, "root", "handle", "ca01:",
            ])));
        }
        if !keeper_root {
            return Err(io::Error::other("unexpected SQM parent"));
        }
        // Linux 3.10 prio_graft(NULL) installs noop_qdisc, which discards
        // every normal packet. Graft a real FIFO using the device queue limit.
        return Ok(Some(str_args(&[
            "qdisc", "replace", "dev", DOWN, "parent", "1:2", "handle", "ca03:", "pfifo",
        ])));
    };
    if !up && !(keeper_root && drop_band) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "keeper Ethernet filter unavailable",
        ));
    }
    let fifo = slot.is_some_and(|r| !up && r["kind"] == "pfifo" && r["handle"] == "ca03:");
    if let Some(s) = slot {
        let implicit = s["handle"] == "0:" && (s["kind"] == "pfifo_fast" || s["kind"] == "pfifo");
        if !ours && !implicit && !fifo {
            return Err(io::Error::other("qdisc slot occupied"));
        }
        // iproute2 emits the rate in bytes/s in JSON mode. An older CAKE of
        // ours with other modes is changed in place.
        let o = &s["options"];
        let flowmode = if up { "dual-dsthost" } else { "dual-srchost" };
        if ours
            && o["bandwidth"].as_u64() == Some(u64::from(rate) * 125)
            && o["diffserv"] == "diffserv4"
            && o["flowmode"] == flowmode
            && o["nat"] == false
        {
            return Ok(None);
        }
    }
    let op = if ours {
        "change"
    } else if fifo {
        "replace"
    } else {
        "add"
    };
    let mut args = vec!["qdisc", op, "dev", dev];
    if up {
        args.extend(["root", "handle", "ca01:"]);
    } else {
        args.extend(["parent", "1:2", "handle", "ca02:"]);
    }
    let rate = format!("{rate}kbit");
    args.extend(["cake", "bandwidth", &rate, "diffserv4"]);
    if up {
        args.extend(["dual-dsthost", "nonat", "ack-filter"]);
    } else {
        args.extend(["dual-srchost", "nonat", "ingress", "wash"]);
    }
    args.extend(["rtt", "100ms", "raw", "overhead", "14", "memlimit", "4m"]);
    Ok(Some(str_args(&args)))
}
/// `rates` is (upload kbit/s, download kbit/s, traffic classes on), or `None`
/// to remove CAKE.
pub fn reconcile(rates: Option<(u32, u32, bool)>) -> io::Result<()> {
    if rates.is_some() {
        stage()?;
    } else if !Path::new(DIR).join("tc").exists() {
        // The tools were never staged on this boot, so no CAKE of ours exists.
        return Ok(());
    }
    if rates.is_some()
        && !Path::new("/sys/module/sch_cake").exists()
        && !Command::new("insmod")
            .arg(format!("{DIR}/sch_cake.ko"))
            .status()?
            .success()
    {
        return Err(io::Error::other("CAKE unavailable"));
    }
    let mut error = None;
    for (dev, rate) in [(DOWN, rates.map(|r| r.1)), (UP, rates.map(|r| r.0))] {
        let classify = rates.is_some_and(|r| r.2);
        if rates.is_none() && !Path::new("/sys/class/net").join(dev).exists() {
            continue;
        }
        let result = (|| {
            let mut next = plan(dev, &rows(dev)?, rate);
            // The PD keeper rebuilds the root and its filters in separate
            // netlink requests. Wait briefly for that transaction to finish.
            for _ in 0..3 {
                if !next
                    .as_ref()
                    .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock)
                {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
                next = plan(dev, &rows(dev)?, rate);
            }
            if let Some(args) = next? {
                tc(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
                if plan(dev, &rows(dev)?, rate)?.is_some() {
                    return Err(io::Error::other("SQM read-back mismatch"));
                }
            }
            // Removing CAKE removes its filters with it.
            if rate.is_some() {
                classes(dev, if dev == UP { "ca01" } else { "ca02" }, classify)?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            if rates.is_some() {
                return Err(e);
            }
            error = Some(e); // Always try to undo the other direction too.
        }
    }
    error.map_or(Ok(()), Err)
}
pub fn stats() -> io::Result<Value> {
    let mut stats = json!({});
    for dev in [UP, DOWN] {
        let r = rows(dev)?
            .into_iter()
            .find(|r| owned(r, dev))
            .ok_or_else(|| io::Error::other("SQM handle missing"))?;
        // diffserv4 tins in order: Bulk, Best Effort, Video, Voice.
        let tins: Vec<Value> = r["tins"]
            .as_array()
            .map(|tins| {
                tins.iter()
                    .map(|t| json!({"packets":t["sent_packets"],"drops":t["drops"],"ack_drops":t["ack_drops"],"peak_delay_us":t["peak_delay_us"],"avg_delay_us":t["avg_delay_us"]}))
                    .collect()
            })
            .unwrap_or_default();
        stats[dev] = json!({"bytes":r["bytes"],"packets":r["packets"],"drops":r["drops"],"overlimits":r["overlimits"],"tins":tins});
    }
    Ok(stats)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_restores_a_forwarding_leaf_and_preserves_foreign_handles() {
        let root = json!({"kind":"prio","root":true,"handle":"1:"});
        let leaf = json!({"kind":"cake","parent":"1:2","handle":"ca02:"});
        let args = plan(DOWN, &[root.clone(), leaf], None).unwrap().unwrap();
        assert!(args.ends_with(&["ca03:".into(), "pfifo".into()]));
        assert!(!args.iter().any(|s| s == "root" || s == "del"));
        let other = json!({"kind":"cake","parent":"1:2","handle":"222:"});
        assert!(plan(DOWN, &[root, other], None).unwrap().is_none());
    }
    #[test]
    fn require_keeper_filter_and_verify_exact_rate() {
        assert!(plan(DOWN, &[], Some(1000)).is_err());
        let r = json!({"kind":"cake","root":true,"handle":"ca01:","options":{"bandwidth":125000,"diffserv":"diffserv4","flowmode":"dual-dsthost","nat":false}});
        assert!(plan(UP, &[r.clone()], Some(1000)).unwrap().is_none());
        assert_eq!(plan(UP, &[r], Some(2000)).unwrap().unwrap()[1], "change");
        assert!(
            plan(
                UP,
                &[json!({"kind":"htb","root":true,"handle":"1:"})],
                Some(1000)
            )
            .is_err()
        );
    }
    #[test]
    fn stage_one_modes_are_set_and_an_older_cake_of_ours_is_changed() {
        let root = json!({"kind":"prio","root":true,"handle":"1:"});
        let drop = json!({"kind":"blackhole","parent":"1:3","handle":"30:"});
        let fifo = json!({"kind":"pfifo","parent":"1:2","handle":"0:"});
        let add = plan(DOWN, &[root.clone(), drop.clone(), fifo], Some(90000)).unwrap().unwrap();
        assert_eq!(
            add.join(" "),
            "qdisc add dev eth0 parent 1:2 handle ca02: cake bandwidth 90000kbit diffserv4 dual-srchost nonat ingress wash rtt 100ms raw overhead 14 memlimit 4m"
        );
        let up = plan(UP, &[], Some(9000)).unwrap().unwrap();
        assert_eq!(
            up.join(" "),
            "qdisc add dev lte0pdn2 root handle ca01: cake bandwidth 9000kbit diffserv4 dual-dsthost nonat ack-filter rtt 100ms raw overhead 14 memlimit 4m"
        );
        // v1.0.11 ran besteffort with triple-isolate on download.
        let old = json!({"kind":"cake","parent":"1:2","handle":"ca02:","options":{"bandwidth":90000u64*125,"diffserv":"besteffort","flowmode":"triple-isolate","nat":false}});
        let change = plan(DOWN, &[root.clone(), drop.clone(), old], Some(90000)).unwrap().unwrap();
        assert_eq!(change[1], "change");
        assert!(change.join(" ").contains("diffserv4 dual-srchost nonat"));
        let current = json!({"kind":"cake","parent":"1:2","handle":"ca02:","options":{"bandwidth":90000u64*125,"diffserv":"diffserv4","flowmode":"dual-srchost","nat":false}});
        assert!(plan(DOWN, &[root.clone(), drop.clone(), current], Some(90000)).unwrap().is_none());
        let nat = json!({"kind":"cake","parent":"1:2","handle":"ca02:","options":{"bandwidth":90000u64*125,"diffserv":"diffserv4","flowmode":"dual-srchost","nat":true}});
        assert_eq!(plan(DOWN, &[root, drop, nat], Some(90000)).unwrap().unwrap()[1], "change");
    }
}
