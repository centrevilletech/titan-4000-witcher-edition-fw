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
management network. Independent HTTP recovery on 8081 remains available.

## When something fails

Nothing that fails here keeps the Witcher web interface off once the cause is
gone. Every fallback retries by itself, and nothing an operator saved is deleted.

- **The web service.** If it does not start, or stops later, the factory
  interface serves while `/etc/init.d/titan-api` tries Witcher again: after a
  minute, then doubling to half an hour, for as long as it takes. A service
  that ran for an hour before it stopped starts again at once. One slow health
  answer is not a failure: three in a row are, and a missing process is.
  Only an operator's choice ends the retries: the factory interface chosen on
  the recovery page (or `titan-api vendor`) for this boot, or
  `/mnt/titan-api/use-vendor-ui` across reboots.
- **The persistent volume.** A mount that fails is retried with the web
  service. Anything found in the bare `/mnt/titan-api` while the volume is not
  mounted moves to `/mnt/titan-api.stray-N` and the volume mounts as usual;
  before, one such file kept the volume unmounted on every boot. The recovery
  page writes its marker only while the volume is mounted; otherwise its choice
  holds for that boot only.
- **The boot seed.** A seed is published with a rename, so a power cut leaves
  either no seed or a complete one. A seed that fails its checks (for example,
  one an older build left with two names after a power cut) is never credited:
  titan-api moves it to `/mnt/titan-api/.invalid-seed` and a new one is made
  before the next start. An unused `seed.next` from a power cut is kept in
  `.interrupted-seed`, one slot.
- **The browser setup page.** When there is no seed and the collector fails,
  the setup page takes port 80, and the collector is tried again underneath it
  (after a minute, doubling to half an hour). When it succeeds, the page
  closes and the HTTPS login starts; no operator has to come.
- **The TLS identity.** One that fails a check (a file missing or empty,
  unreadable, or a key that is not the certificate's) moves to
  `/mnt/titan-api/tls/broken`, which keeps the last one, and a new identity is
  made. Browsers then ask once to accept the unit's new certificate. A good
  identity is kept, with its file modes put right.
- **Sign-in limits.** Attempts are counted per source address (an IPv6 host by
  its /64): 10 a minute on the web service and 5 on the recovery page.
  Addresses on the open Internet also share one budget (30 and 15 a minute),
  so a crowd guesses no faster than a few. Private, CGNAT, link-local and
  loopback sources never count against the shared budget, so nothing on the
  Internet can lock out the LAN or the management APN. Nothing is kept on
  flash.
- **Sessions.** At 16 sessions, a new sign-in replaces the least recently used
  one instead of being refused. With Automatic logout off, sessions never
  expire, so closed browsers used to fill the table and lock out every sign-in.

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
