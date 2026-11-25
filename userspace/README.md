# Witcher userspace

The normal firmware build compiles the first-boot service and network keeper
from this Rust workspace. It also builds the vendored entropy collector.

```bash
cargo test --locked --workspace --manifest-path userspace/Cargo.toml
scripts/build-firstboot.sh /tmp/witcher-firstboot
scripts/build-keeper.sh /tmp/titan-pd-keeper
```

Both Rust programs target `armv7-unknown-linux-musleabi` with Rust 1.99.0 and
its bundled linker. Image verification compares them with the source build.

## Layout

- `pd-model`: the keeper's decisions, with no I/O, tested on the host.
- `pd-keeper`: the keeper. `run.rs` holds its state and loop; each part
  (prefix delegation, the IPv4 repair, the watchdogs, the staged modules and
  so on) is a module under `run/`. Shared I/O helpers (`netdev`, `nvram`,
  `paths`, `files`, `command`, `staged`, `status_file`) sit beside it.
- `firstboot`: the first-boot service.
- `sys` (`titan-sys`): the only crate allowed `unsafe`. It wraps the Linux
  calls std does not offer (packet sockets, `getifaddrs`, `poll`, signals,
  the `fork`-to-`exec` hooks, the kernel log ring) in typed safe functions,
  and every `unsafe` block carries a `// SAFETY:` comment that CI's clippy
  checks. The other crates are `#![forbid(unsafe_code)]`.

CI's `sizes` job prints the stripped armv7 size of both programs on every
pull request; the rootfs has little room to spare.

Other native services, including the web API and key-only SSH server, currently
ship as pinned overlay binaries. Their source remains in the private ops
repository; this tree does not yet rebuild every bundled service.

See [building](../docs/building.md), [IPv4 recovery](../docs/ipv4-recovery.md)
and [first-boot HTTPS](../docs/first-boot-https.md).
