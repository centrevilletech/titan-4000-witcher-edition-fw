# Local CBRS/SAS enforcement changes

Witcher changes vendor enforcement behavior. These patches are not a regulatory
compliance mechanism. Successful SAS registration or visible grant state does
not establish that a radio is operating with valid authorization. Blocking
IP traffic upstream is not evidence that RF transmissions have stopped.

For U.S. deployments, review [47 CFR Part 96](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-D/part-96),
including the requirements applicable to the equipment's role as an End User
Device or CBSD. This repository does not establish equipment authorization or
compliance of a modified device. An educational purpose does not exempt radio
operation from those requirements.

## Default build

[`build-firmware.sh`](../scripts/build-firmware.sh) applies
[`patch-cbrs_fsm.py`](../scripts/patch-cbrs_fsm.py) to the pinned vendor binary:

- At file offsets `0x4fcc` and `0x4fd0`, the Block Channel routine is replaced
  with `mov r0,#0; bx lr`. It returns before its grant-state update and signal
  to `rcinit`, bypassing that local channel-teardown path.
- Five `iptables`/`ebtables` command prefixes are replaced with same-length
  `true` commands, making those command strings no-ops.
- Registration and heartbeat code are not changed by this patch. That is a
  statement about patched bytes, not proof that registration always succeeds.

The normal builder does not apply the separate grant-state patch to `rcinit`.
Do not describe all of its remaining behavior as unconditionally grant-free.

The same-length patches and byte guards check compatibility with the known
input. They do not demonstrate regulatory or operational safety, and this
project supplies no tested replacement for spectrum enforcement.
