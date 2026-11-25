# Latency features: on by default

Since v1.0.17 a unit that is only flashed gets every latency and upload
improvement Witcher has. Nothing needs SSH, staging or flags. Each feature
can be turned off on its own, live.

| Feature | What it does | Bench result | Details |
| --- | --- | --- | --- |
| Upload latency and AQM (the modem words) | A patched modem image the unit builds from its own stock firmware. Its words turn on the uplink queue control, the grant hold, the sparse-flow lane and the Rust PIE uplink AQM. | Ping during an upload about 100 ms to 38 ms; 4-stream CUBIC upload on two carriers 7.4 to 14.9 Mbps | [Boot-time loader](tk-boot-loader.md), [building the image](tk-patch.md) |
| Download clamp (`titan_qctrl`) | Keeps the tower's download queue short, mode 3 (window clamp plus ACK thinning). It acts in IP passthrough. | Ping during a full download about 310 ms to 50 ms in mode 2, for about 8 % less peak speed; mode 3 took about 6 ms more off with no speed cost | [Download clamp](download-clamp.md) |
| Fast path (`titan_k1fp`) | Forwards steady IP passthrough flows past the full bridge path, mode 2 (downlink). | About 20 points of CPU back at 170 to 200 Mbps, +7 to 10 % download | [Fast path](fast-path.md) |

## The first boot of v1.0.17

1. **Modem image.** Right before the boot's one `modprobe modem`, the boot
   hook asks the keeper whether `tk/` holds anything an operator made. When
   it does not, the keeper builds the release image from the active modem
   bank and writes it with a default `tk/config`. The image loads for that
   same `modprobe`. This makes that one boot about 20 s slower (17.5 s on the
   bench), and later boots reuse the file. After the boot confirm (an answer
   through the core within 300 s) the keeper writes the modem words.
2. **Clamp and fast path.** The keeper loads both from the image about 30 s
   after the customer port and LTE are up: the clamp first, then the fast
   path, which needs IP passthrough.

A unit flashed from stock firmware has no Witcher volume on its first boot,
so it builds the modem image on its next boot. The clamp and the fast path
start on the first boot.

Nothing is built, and stock modem firmware loads, when any of these hold:

- an operator's own `tk/config` exists, or `enabled=0`;
- the active modem bank is not the exact stock image the release image is
  built from;
- an image was rolled back (anything in `tk/quarantine`, or `tk/strikes` at 2).

`/var/run/witcher-tk.status` says why (`reason=`), and `build=` says what the
default image did this boot.

## Turning a feature off

Use the web interface, **Network → Latency**, or edit one file:
`/mnt/titan-api/latency/config`. Each line turns one feature off; a missing
file or line means on.

```text
modem=off      # the modem words go back to their stock values
clamp=off      # the download clamp passes everything (mode 0)
fastpath=off   # the fast path forwards everything the stock way (mode 0)
```

The keeper reads the file every 5 s and acts at once: no reboot, and nothing
is unloaded. `on`, `1`, `yes` and `true` mean on; `off`, `0`, `no` and
`false` mean off. Any other value also means off, and `keeper.log` says so.
The web screen and the keeper read and write the same file.

| To... | Do this | Result |
| --- | --- | --- |
| Turn the modem words off now | `modem=off` | Within seconds the keeper writes every word back to its documented off value and reads each one back. The patched image then behaves as stock firmware. |
| Run stock modem firmware | `printf 'enabled=0\n' > /mnt/titan-api/tk/config` | The words go off at once, and the next boot loads stock firmware. Keep the file: with no `tk/config` the default applies again. |
| Turn the download clamp off | `clamp=off`, or `mode=0` in `qctrl/config` | Mode 0 within seconds. The module stays loaded and passes everything. |
| Turn the fast path off | `fastpath=off`, or `mode=0` in `fastpath/config` | Mode 0 within seconds; the SAS grant lease is revoked. |
| Go back to the default | Delete the lines (or the file); for the modem image delete `tk/config` and `tk/active.gz` | The default applies again: live for the switches, at the next boot for the image. |

## Your own settings still win

The switch is the master off. While it is on, an operator's own file
replaces the default for that feature:

| Feature | Operator file | Instead of the default |
| --- | --- | --- |
| Modem | `tk/config` without the `# witcher-default` first line (or with any line edited) | Your image, your `sha256=` allow-list and your `wm=` words. The firmware never rewrites it. |
| Clamp | `qctrl/config` | Your `mode=` and knobs. |
| Fast path | `fastpath/config` | Your `mode=`. |

`scripts/stage-latency.sh` still writes these files from a workstation.

The default clamp stands aside (mode 0) while `sch_cake` is loaded. Only a
radio profile's `sqm` action loads it, and CAKE download shaping and the clamp
have not been tested together. An operator's `qctrl/config` overrides that.

## Status

| File | Shows |
| --- | --- |
| `/var/run/witcher-tk.status` | The modem image this boot: `state`, `reason`, `build`, `build_secs` |
| `/var/run/witcher-tk.flags` | The modem words |
| `/var/run/witcher-qctrl.status` | The clamp; `detail` says where its mode came from |
| `/var/run/witcher-fastpath.status` | The fast path; `detail` says where its mode came from |

`keeper.log` lines start with `latency switches`, `tk boot`, `tk flags`,
`download clamp` or `fast path`.
