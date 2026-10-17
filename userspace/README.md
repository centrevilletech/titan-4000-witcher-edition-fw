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

Other native services, including the web API and key-only SSH server, currently
ship as pinned overlay binaries. Their source remains in the private ops
repository; this tree does not yet rebuild every bundled service.

See [building](../docs/building.md), [IPv4 recovery](../docs/ipv4-recovery.md)
and [first-boot HTTPS](../docs/first-boot-https.md).
