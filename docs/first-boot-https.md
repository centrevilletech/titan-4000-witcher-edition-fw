# HTTPS before the first password

Witcher can initialize itself and serve its normal HTTPS login on a unit
with no previous Witcher seed or TLS identity. The administrator enters the
existing device password on that login page. No separate setup submission is
needed on the successful path.

## Startup

1. Mount/create the existing guarded persistent state volume. Do not format,
   resize or overwrite vendor storage, credentials, APNs or calibration.
2. If no seed exists, run the bundled Jitterentropy 3.7.0 collector. Use OSR 3,
   forced startup/continuous health tests, no internal timer fallback, and a
   90-second process deadline. Accept exactly 64 bytes only after a successful exit, rejecting an all-zero
   block. Publish the private seed atomically without replacement.
3. The native launcher's existing entropy initialization consumes that seed,
   credits the kernel RNG and durably writes a new next-boot seed.
4. Preserve existing certificate/key pairs. For a fresh identity, use the
   image's bundled OpenSSL to generate a unique P-256 key and self-signed
   SHA-256 certificate, then publish the pair atomically. Fixed validity from
   1970 through 2099 avoids dependence on RTC, NTP or an attached APN. The browser
   still displays the expected self-signed trust warning; arbitrary LTE IPs
   may also differ from the certificate's local-address names.
5. Start the existing native HTTP/HTTPS panel, including its MAC/version login
   display. Existing management-access rules cover NAT, passthrough and remote
   IPv4. HTTP is retained for compatibility; it is not forcibly redirected.

First setup no longer needs a browser seed on the successful path. If the local
collector fails, no autonomous seed or new TLS key is published. The existing
password-authenticated HTTP bootstrap is retained for a trusted LAN/protected
management network. Independent HTTP recovery on 8081 remains available. Failed
storage, invalid existing seeds or incomplete existing TLS identities are not
silently overwritten.

## Source and qualification

The collector source is vendored unchanged from
[Jitterentropy v3.7.0](https://github.com/smuellerDD/jitterentropy-library/tree/e783cf1c450bce4d72f95c9f9c84546a6094976a),
with the BSD license included in the firmware. It is compiled at `-O0`, without
LTO, using Zig 0.14.1/musl for ARMv7. Its own tests reject unsuitable runtime
noise; passing them does not constitute a cryptographic certification or a
full SP800-90B entropy assessment.

Bench testing has exercised fresh entropy and TLS state through a warm reboot,
with HTTPS available before any browser password submission, over direct
Ethernet and an assigned LTE IPv4 address in NAT mode. This does not establish
cold-power-cycle, full factory-reset, no-APN hardware behavior, or compatibility
with every starting firmware version.

The image carries its own collector, OpenSSL, kernel and rootfs; it does not
rely on TLS tooling from the previous installation. OpenSSL is explicitly
instructed to use named P-256 parameters for native-server compatibility.
CI runs the image's ARM OpenSSL under QEMU and checks named-curve encoding,
key/certificate agreement, validity dates and identity reuse. These are tool
compatibility checks, not a full Titan boot test.
