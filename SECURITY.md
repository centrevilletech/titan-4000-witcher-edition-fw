# Security and credential handling

## Device access

Witcher locks both factory Unix root-account writers. It does not install a
shared root password. Native SSH accepts operator-enrolled public keys; the
browser uses the device's existing administrator password, which is separate
from Unix root login. Configure a unique administrator password before exposing
the unit. A vendor default or MAC-derived password is not a strong secret.

Browser management is enabled on every assigned IPv4 address by default,
including customer/public APNs. HTTP setup and recovery remain available;
password authentication does not encrypt an HTTP connection. Use HTTPS for
normal access and restrict recovery access to trusted networks.

TLS and native SSH host keys are generated per unit and kept with operator
keys and entropy state in persistent storage. Builds remove factory shared TLS
files and embedded vendor SSH private-key constants. A self-signed certificate
requires an independent identity check; accepting a browser warning alone does
not authenticate the unit.

## Source and build hygiene

Never commit credentials, session cookies, packet captures, live customer
exports or private keys. Use synthetic addresses and telemetry for examples
and screenshots. Preserve third-party licenses and record the source revision
for imported components.

Run these checks before submitting changes:

```bash
python3 scripts/audit-secrets.py
python3 scripts/audit-secrets.py --history
```

CI scans the tracked tree and full branch/tag history. Official packaging also
requires the `LEGACY_CREDENTIAL_DENYLIST` Actions secret, a JSON array passed as
`WITCHER_CREDENTIAL_DENYLIST_JSON` to check that known credentials are absent.
It is never installed as a device password. Generic root-hash/private-key
checks run without it; Gitleaks adds checks for common provider tokens.
Reports identify files without printing matched credentials.

Embedding a shared password from GitHub Secrets in downloadable firmware would
still expose it to anyone who extracts that firmware. A clean scan is evidence
within its scope, not a guarantee that binaries or deployments contain no secrets.

## CI trust boundary

CI runs every job on disposable GitHub-hosted runners. This repository has no
self-hosted runner, so a pull request cannot reach one by editing workflow YAML.
Packaging and its private denylist run only for trusted pushes and tags, never
for pull requests, and outside contributors' workflows wait for maintainer
approval. Never pass packaging secrets to untrusted code. Review workflow
changes as executable code.

## Reporting a vulnerability

Use GitHub private vulnerability reporting if it is enabled, or contact a
maintainer privately through the project's listed author site. Send a minimal
reproduction and firmware version, with customer information, keys, passwords
and cookies removed. Do not put working credentials in a public issue.

If sensitive data was committed, removing the current file is insufficient.
Rotate or disable the credential and assess history, tags, releases, artifacts,
logs, caches, forks and clones. GitHub-managed cached references may require
Support removal before publication. Keep incident evidence in a private archive.
