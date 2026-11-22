//! CAKE occupies the customer bearer root and the keeper's ordinary-traffic
//! Ethernet band. Reserve explicit handles so cleanup can recognize each slot.
use serde_json::{Value, json};
use std::{io, path::Path, process::Command};

const DIR: &str = "/usr/lib/witcher-sqm";
const UP: &str = "lte0pdn2";
const DOWN: &str = "eth0";
fn tc(args: &[&str]) -> io::Result<Vec<u8>> {
    let out = Command::new(format!("{DIR}/tc")).args(args).output()?;
    if !out.status.success() {
        return Err(io::Error::other("tc failed"));
    }
    Ok(out.stdout)
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
        // iproute2 emits this field in bytes/s in JSON mode.
        if ours && s["options"]["bandwidth"].as_u64() == Some(u64::from(rate) * 125) {
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
    args.extend(["cake", "bandwidth", &rate]);
    if up {
        args.extend(["diffserv4", "ack-filter"]);
    } else {
        args.extend(["besteffort", "ingress", "wash"]);
    }
    args.extend(["rtt", "100ms", "raw", "overhead", "14", "memlimit", "4m"]);
    Ok(Some(str_args(&args)))
}
pub fn reconcile(rates: Option<(u32, u32)>) -> io::Result<()> {
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
        stats[dev] = json!({"bytes":r["bytes"],"packets":r["packets"],"drops":r["drops"],"overlimits":r["overlimits"]});
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
        let r = json!({"kind":"cake","root":true,"handle":"ca01:","options":{"bandwidth":125000}});
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
}
