#!/usr/bin/env bash
# Stage the latency fixes on one Titan over the enrolled operator SSH login
# (port 2222). Run it from a checkout on a workstation.
#
#   scripts/stage-latency.sh [options] <unit> <tk.gz> <titan_qctrl.ko>
#   scripts/stage-latency.sh [options] --fastpath <titan_k1fp.ko> <unit>
#
# It copies the modem firmware image to /mnt/titan-api/tk/active.gz and writes
# tk/config (enabled=1, its sha256, target= lines, wm= flag lines). It copies
# the download clamp module to /mnt/titan-api/qctrl/ and writes qctrl/config.
# With --fastpath it copies titan_k1fp.ko to /mnt/titan-api/fastpath/ and
# writes fastpath/config. When --fastpath is given without <tk.gz>, only the
# fast path is staged. Every copy is checked by SHA-256 on the unit before it
# replaces anything. It never reboots the unit. See docs/tk-boot-loader.md,
# docs/download-clamp.md, and docs/fast-path.md.
#
# Options:
#   --target ADDR        Ping responder for the boot confirm (up to 4). Without
#                        one the keeper uses the deaf watchdog's targets.
#   --profile NAME       Modem switch profile: latency (inspects tk.gz magics
#                        for N4 / IMG4 / N5 / N6 and writes the proven set) or
#                        stock (writes no wm= lines).
#   --flags HEX          0x847ed604 value (default 0x15: AQM v2 + grant hold;
#                        overrides profile)
#   --hold HEX           0x84f93008 grant-hold size in bytes (default 0x140;
#                        cap 0x200, or 0x800 with --hold-ack prb-tax; overrides
#                        profile)
#   --hold-ack TOKEN     Write hold_ack=prb-tax to allow --hold up to 0x800
#                        (adds padding uplink grants on the tower while active)
#   --no-flags           Write no wm= lines (the image runs with every flag 0)
#   --mode N             Clamp mode: 0, 2, 3 or 6 (default 2)
#   --trough-ms N        Clamp knob, 0..40 (default: module default 4)
#   --clamp-target-ms N  Clamp knob, 4..80 (default: module default 40)
#   --ack-adapt N        Clamp knob, 0 or 1 (default: module default 0)
#   --ctrl-v3 N          Clamp knob, 0 or 1 (default: module default 0)
#   --ack-ms N           Clamp knob, 1..10 (default: module default 6)
#   --ack-segs N         Clamp knob, 2..32 (default: module default 18)
#   --ack-min-kbps N     Clamp knob, 0..100000 (default: module default 2000)
#   --no-clamp           Skip the clamp; the .ko argument may be left out
#   --fastpath PATH      Stage titan_k1fp.ko and fastpath/config
#   --fastpath-mode N    Fast path mode: 0, 1, 2 or 3 (default 2)
#   --reset-strikes      strikes=0 and take this image out of quarantine
#   --port N             SSH port (default 2222)
#   --user NAME          SSH user (default root)
#   --status             Only print the unit's current status
#   --dry-run            Check inputs and print the files; change nothing
#
# Extra ssh options can go in SSH_OPTS, for example SSH_OPTS="-i ~/.ssh/key".
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
PORT=2222
SSH_USER=root
PROFILE=
FLAGS=0x15
HOLD=0x140
HOLD_ACK=
WRITE_FLAGS=1
MODE=2
TROUGH=
CLAMP_TARGET=
ACK_ADAPT=
CTRL_V3=
ACK_MS=
ACK_SEGS=
ACK_MIN_KBPS=
CLAMP=1
FASTPATH=
FASTPATH_MODE=2
RESET=0
STATUS_ONLY=0
DRY=0
TARGETS=()
ARGS=()

die() { echo "stage-latency: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGETS+=("${2:?--target needs an address}"); shift 2 ;;
    --profile) PROFILE=${2:?--profile needs latency or stock}; shift 2 ;;
    --flags) FLAGS=${2:?}; shift 2 ;;
    --hold) HOLD=${2:?}; shift 2 ;;
    --hold-ack) HOLD_ACK=${2:?--hold-ack needs prb-tax}; shift 2 ;;
    --no-flags) WRITE_FLAGS=0; shift ;;
    --mode) MODE=${2:?}; shift 2 ;;
    --trough-ms) TROUGH=${2:?}; shift 2 ;;
    --clamp-target-ms) CLAMP_TARGET=${2:?}; shift 2 ;;
    --ack-adapt) ACK_ADAPT=${2:?}; shift 2 ;;
    --ctrl-v3) CTRL_V3=${2:?}; shift 2 ;;
    --ack-ms) ACK_MS=${2:?}; shift 2 ;;
    --ack-segs) ACK_SEGS=${2:?}; shift 2 ;;
    --ack-min-kbps) ACK_MIN_KBPS=${2:?}; shift 2 ;;
    --no-clamp) CLAMP=0; shift ;;
    --fastpath) FASTPATH=${2:?--fastpath needs a path}; shift 2 ;;
    --fastpath-mode) FASTPATH_MODE=${2:?}; shift 2 ;;
    --reset-strikes) RESET=1; shift ;;
    --port) PORT=${2:?}; shift 2 ;;
    --user) SSH_USER=${2:?}; shift 2 ;;
    --status) STATUS_ONLY=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,48p' "$0"; exit 0 ;;
    --) shift; ARGS+=("$@"); break ;;
    -*) die "unknown option $1" ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

UNIT=${ARGS[0]:-}
[ -n "$UNIT" ] || die "usage: $0 [options] <unit> <tk.gz> <titan_qctrl.ko>"
# shellcheck disable=SC2086 # SSH_OPTS holds several words on purpose.
remote() { ssh -p "$PORT" -o BatchMode=yes ${SSH_OPTS:-} "$SSH_USER@$UNIT" "$@"; }

status() {
  remote 'sh -s' <<'EOS'
show() { echo "== $1"; if [ -e "$1" ]; then cat "$1"; else echo "(none)"; fi; }
echo "== /etc/witcher-release"; cat /etc/witcher-release 2>/dev/null || echo "(none)"
for f in /var/run/witcher-tk.status /var/run/witcher-tk.result /var/run/witcher-tk.flags \
         /var/run/witcher-tk.hands-off \
         /var/run/witcher-qctrl.status /var/run/witcher-fastpath.status \
         /mnt/titan-api/tk/config /mnt/titan-api/tk/strikes \
         /mnt/titan-api/tk/quarantine /mnt/titan-api/tk/confirmed \
         /mnt/titan-api/qctrl/config /mnt/titan-api/fastpath/config; do
  show "$f"
done
echo "== staged files"
for f in /mnt/titan-api/tk/active.gz /mnt/titan-api/qctrl/titan_qctrl.ko /mnt/titan-api/fastpath/titan_k1fp.ko; do
  [ -f "$f" ] && sha256sum "$f" || echo "(no $f)"
done
echo "== /proc/titan_qctrl"
if [ -r /proc/titan_qctrl ]; then head -n 4 /proc/titan_qctrl; else echo "(not loaded)"; fi
echo "== /proc/k1fp"
if [ -r /proc/k1fp ]; then head -n 9 /proc/k1fp; else echo "(not loaded)"; fi
echo "== keeper.log (tk, flags, clamp, fast path)"
{ grep -h -E 'tk boot|tk flags|download clamp|fast path' /tmp/titan-pd-keeper/keeper.log.1 /tmp/titan-pd-keeper/keeper.log 2>/dev/null ||
  grep -h -E 'tk boot|tk flags|download clamp|fast path' /mnt/titan-api/pd/keeper.log 2>/dev/null; } | tail -n 15 || true
EOS
}

if [ "$STATUS_ONLY" = 1 ]; then
  status
  exit 0
fi

TK=${ARGS[1]:-}
KO=${ARGS[2]:-}
STAGE_TK=1
STAGE_FP=0
if [ -n "$FASTPATH" ]; then
  STAGE_FP=1
  if [ -z "$TK" ]; then
    STAGE_TK=0
    CLAMP=0
  fi
fi

if [ "$STAGE_TK" = 1 ]; then
  [ -n "$TK" ] || die "usage: $0 [options] <unit> <tk.gz> <titan_qctrl.ko>"
  [ -f "$TK" ] || die "no file $TK"
fi
if [ "$CLAMP" = 1 ]; then
  [ -n "$KO" ] || die "give the titan_qctrl.ko path, or --no-clamp"
  [ -f "$KO" ] || die "no file $KO"
fi
if [ "$STAGE_FP" = 1 ]; then
  [ -f "$FASTPATH" ] || die "no file $FASTPATH"
fi
[ "${#TARGETS[@]}" -le 4 ] || die "at most 4 --target addresses"

# ---- Local checks, before anything touches the unit ----
case "$PROFILE" in
  ""|latency) ;;
  stock) WRITE_FLAGS=0 ;;
  *) die "--profile must be latency or stock" ;;
esac
case "$HOLD_ACK" in
  ""|prb-tax) ;;
  *) die "--hold-ack must be prb-tax" ;;
esac

num() { # hex (0x) or decimal to decimal, or fail
  case "$1" in
    0x*|0X*) [[ "${1:2}" =~ ^[0-9A-Fa-f]{1,8}$ ]] || return 1; echo $((16#${1:2})) ;;
    *) [[ "$1" =~ ^[0-9]{1,10}$ ]] || return 1; echo $((10#$1)) ;;
  esac
}
flags=$(num "$FLAGS") || die "--flags $FLAGS is not a number"
hold=$(num "$HOLD") || die "--hold $HOLD is not a number"
[ $((flags & ~0x15)) -eq 0 ] || die "--flags $FLAGS sets bits outside 0x15"
hold_cap=$((0x200))
if [ "$HOLD_ACK" = "prb-tax" ]; then
  hold_cap=$((0x800))
fi
if [ "$hold" -gt "$hold_cap" ]; then
  if [ -z "$HOLD_ACK" ] && [ "$hold" -le $((0x800)) ]; then
    die "--hold $HOLD is over 0x200; pass --hold-ack prb-tax to allow up to 0x800"
  fi
  die "--hold $HOLD is over $(printf '0x%x' "$hold_cap")"
fi
case "$MODE" in 0|2|3|6) ;; *) die "--mode must be 0, 2, 3 or 6" ;; esac
case "$FASTPATH_MODE" in 0|1|2|3) ;; *) die "--fastpath-mode must be 0, 1, 2 or 3" ;; esac
if [ -n "$TROUGH" ]; then [[ "$TROUGH" =~ ^[0-9]+$ ]] && [ "$TROUGH" -le 40 ] || die "--trough-ms must be 0..40"; fi
if [ -n "$CLAMP_TARGET" ]; then [[ "$CLAMP_TARGET" =~ ^[0-9]+$ ]] && [ "$CLAMP_TARGET" -ge 4 ] && [ "$CLAMP_TARGET" -le 80 ] || die "--clamp-target-ms must be 4..80"; fi
if [ -n "$ACK_ADAPT" ]; then [[ "$ACK_ADAPT" =~ ^[0-9]+$ ]] && [ "$ACK_ADAPT" -le 1 ] || die "--ack-adapt must be 0 or 1"; fi
if [ -n "$CTRL_V3" ]; then [[ "$CTRL_V3" =~ ^[0-9]+$ ]] && [ "$CTRL_V3" -le 1 ] || die "--ctrl-v3 must be 0 or 1"; fi
if [ -n "$ACK_MS" ]; then [[ "$ACK_MS" =~ ^[0-9]+$ ]] && [ "$ACK_MS" -ge 1 ] && [ "$ACK_MS" -le 10 ] || die "--ack-ms must be 1..10"; fi
if [ -n "$ACK_SEGS" ]; then [[ "$ACK_SEGS" =~ ^[0-9]+$ ]] && [ "$ACK_SEGS" -ge 2 ] && [ "$ACK_SEGS" -le 32 ] || die "--ack-segs must be 2..32"; fi
if [ -n "$ACK_MIN_KBPS" ]; then [[ "$ACK_MIN_KBPS" =~ ^[0-9]+$ ]] && [ "$ACK_MIN_KBPS" -le 100000 ] || die "--ack-min-kbps must be 0..100000"; fi
for t in "${TARGETS[@]}"; do
  [[ "$t" =~ ^[0-9A-Fa-f.:]+$ ]] || die "--target $t is not an IP address"
done

DETECTED_TIER=""
HAS_IMG4=0
HAS_N5=0
HAS_N6=0
IS_N6H=0

inspect_tk_magics() {
  python3 - "$1" <<'PY'
import gzip, struct, sys

BASE = 0x84100000
CHECKS = [
    ("img4", 0x847ecfe8, 0x494d4734),
    ("n5",   0x84489a64, 0x4e35464c),
    ("n6",   0x8418ff00, 0x55324846),
    ("n6h",  0x8418ff04, 0x4e364803),
]
with gzip.open(sys.argv[1], "rb") as fh:
    data = fh.read()

found = {}
for name, va, want in CHECKS:
    off = va - BASE
    if 0 <= off <= len(data) - 4:
        val = struct.unpack_from("<I", data, off)[0]
        found[name] = (val == want)
    else:
        found[name] = False

print(
    int(found["img4"]),
    int(found["n5"]),
    int(found["n6"]),
    int(found["n6"] and found["n6h"]),
)
PY
}

if [ "$STAGE_TK" = 1 ]; then
  size=$(wc -c < "$TK")
  [ "$size" -ge 1024 ] && [ "$size" -le $((7680 * 1024)) ] || die "$TK is $size bytes; the boot hook takes 1 KiB to 7.5 MiB"
  read -r m1 m2 m3 flg < <(od -An -tx1 -N4 "$TK")
  [ "$m1$m2$m3" = 1f8b08 ] || die "$TK is not a gzip (deflate) file"
  [ $((16#$flg & 0xe2)) -eq 0 ] || die "$TK has gzip header flags 0x$flg; the modem reader takes only FTEXT/FNAME"
  TK_SHA=$(sha256sum "$TK" | cut -d' ' -f1)
  if [ "$PROFILE" = "latency" ]; then
    read -r HAS_IMG4 HAS_N5 HAS_N6 IS_N6H < <(inspect_tk_magics "$TK") || die "could not decompress $TK to read patch magics"
    if [ "$HAS_N6" = 1 ]; then
      if [ "$IS_N6H" = 1 ]; then DETECTED_TIER="N6H"; else DETECTED_TIER="N6"; fi
    elif [ "$HAS_N5" = 1 ]; then
      DETECTED_TIER="N5"
    elif [ "$HAS_IMG4" = 1 ]; then
      DETECTED_TIER="IMG4"
    else
      DETECTED_TIER="N4"
    fi
  fi
fi

if [ "$CLAMP" = 1 ]; then
  KO_SHA=$(sha256sum "$KO" | cut -d' ' -f1)
  PINNED=$(awk '$2 == "titan_qctrl.ko" { print $1 }' "$REPO/device/qctrl/SHA256SUMS")
  [ -n "$PINNED" ] || die "no titan_qctrl.ko line in device/qctrl/SHA256SUMS"
  [ "$KO_SHA" = "$PINNED" ] || die "$KO has SHA-256 $KO_SHA; the keeper accepts only $PINNED (device/qctrl/SHA256SUMS)"
fi

if [ "$STAGE_FP" = 1 ]; then
  FP_SHA=$(sha256sum "$FASTPATH" | cut -d' ' -f1)
  FP_PINNED=$(awk '$2 == "titan_k1fp.ko" { print $1 }' "$REPO/device/fastpath/SHA256SUMS")
  [ -n "$FP_PINNED" ] || die "no titan_k1fp.ko line in device/fastpath/SHA256SUMS"
  [ "$FP_SHA" = "$FP_PINNED" ] || die "$FASTPATH has SHA-256 $FP_SHA; the keeper accepts only $FP_PINNED (device/fastpath/SHA256SUMS)"
fi

stamp=$(date -u +%Y-%m-%dT%H:%MZ)
if [ "$STAGE_TK" = 1 ]; then
  TK_CONFIG="# Written by scripts/stage-latency.sh at $stamp
enabled=1
sha256=$TK_SHA"
  for t in "${TARGETS[@]}"; do TK_CONFIG="$TK_CONFIG
target=$t"; done
  if [ "$WRITE_FLAGS" = 1 ]; then
    if [ "$HOLD_ACK" = "prb-tax" ]; then
      TK_CONFIG="$TK_CONFIG
hold_ack=prb-tax"
    fi
    TK_CONFIG="$TK_CONFIG
wm=0x84f93008:$(printf '0x%x' "$hold")
wm=0x847ed604:$(printf '0x%x' "$flags")"
    if [ "$PROFILE" = "latency" ]; then
      if [ "$HAS_IMG4" = 1 ]; then
        TK_CONFIG="$TK_CONFIG
wm=0x847ed548:0x1
wm=0x847ed54c:0x1
wm=0x847ed550:0x1
wm=0x847ecf08:0x1"
      fi
      if [ "$HAS_N5" = 1 ]; then
        if [ $((flags & 0x1)) -ne 0 ]; then
          TK_CONFIG="$TK_CONFIG
wm=0x84489a84:0x2000
wm=0x84489a88:0x3000
wm=0x84489a6c:0x3"
        else
          TK_CONFIG="$TK_CONFIG
wm=0x84489a6c:0x1"
        fi
      fi
      if [ "$HAS_N6" = 1 ]; then
        TK_CONFIG="$TK_CONFIG
wm=0x8418ff08:0x1"
      fi
    fi
  fi
fi
QCTRL_CONFIG="# Written by scripts/stage-latency.sh at $stamp
mode=$MODE"
[ -n "$TROUGH" ] && QCTRL_CONFIG="$QCTRL_CONFIG
trough_ms=$TROUGH"
[ -n "$CLAMP_TARGET" ] && QCTRL_CONFIG="$QCTRL_CONFIG
target_ms=$CLAMP_TARGET"
[ -n "$ACK_ADAPT" ] && QCTRL_CONFIG="$QCTRL_CONFIG
ack_adapt=$ACK_ADAPT"
[ -n "$CTRL_V3" ] && QCTRL_CONFIG="$QCTRL_CONFIG
ctrl_v3=$CTRL_V3"
[ -n "$ACK_MS" ] && QCTRL_CONFIG="$QCTRL_CONFIG
ack_ms=$ACK_MS"
[ -n "$ACK_SEGS" ] && QCTRL_CONFIG="$QCTRL_CONFIG
ack_segs=$ACK_SEGS"
[ -n "$ACK_MIN_KBPS" ] && QCTRL_CONFIG="$QCTRL_CONFIG
ack_min_kbps=$ACK_MIN_KBPS"
FASTPATH_CONFIG="# Written by scripts/stage-latency.sh at $stamp
mode=$FASTPATH_MODE"

echo "unit:        $SSH_USER@$UNIT port $PORT"
[ "$STAGE_TK" = 1 ] && echo "tk image:    $TK ($size bytes) sha256 $TK_SHA"
if [ "$STAGE_TK" = 1 ] && [ -n "$PROFILE" ]; then
  if [ "$PROFILE" = "latency" ]; then
    echo "tk profile:  latency (detected $DETECTED_TIER)"
  else
    echo "tk profile:  $PROFILE"
  fi
fi
[ "$CLAMP" = 1 ] && echo "clamp:       $KO sha256 $KO_SHA"
[ "$STAGE_FP" = 1 ] && echo "fast path:   $FASTPATH sha256 $FP_SHA"
[ "$STAGE_TK" = 1 ] && { echo "--- tk/config"; echo "$TK_CONFIG"; }
[ "$CLAMP" = 1 ] && { echo "--- qctrl/config"; echo "$QCTRL_CONFIG"; }
[ "$STAGE_FP" = 1 ] && { echo "--- fastpath/config"; echo "$FASTPATH_CONFIG"; }
if [ "$STAGE_TK" = 1 ] && [ "${#TARGETS[@]}" -eq 0 ]; then
  echo "note: no --target; the boot confirm uses the deaf watchdog's targets"
fi
if [ "$DRY" = 1 ]; then
  echo "dry run: nothing changed"
  exit 0
fi

# ---- The unit ----
release=$(remote 'cat /etc/witcher-release' 2>/dev/null) || die "cannot reach $UNIT over SSH port $PORT"
version=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' <<<"$release")
echo "unit runs Witcher ${version:-unknown}"
if [ -z "$version" ] || [ "$(printf '%s\n%s\n' 1.0.15 "$version" | sort -V | head -n 1)" != 1.0.15 ]; then
  echo "WARNING: this unit runs ${version:-an unknown version}. Before 1.0.15 the keeper loads no clamp and writes no flags." >&2
fi
remote 'grep -q " /mnt/titan-api " /proc/mounts' || die "/mnt/titan-api is not mounted on the unit"

# Copy to a temporary name, check the copy's SHA-256 on the unit, then rename.
put() { # local remote-final sha
  local tmp
  tmp="$(dirname "$2")/.$(basename "$2").new"
  remote "umask 077; mkdir -p '$(dirname "$2")' && chmod 700 '$(dirname "$2")' && cat > '$tmp'" < "$1"
  local got
  got=$(remote "sha256sum '$tmp'" | cut -d' ' -f1)
  if [ "$got" != "$3" ]; then
    remote "rm -f '$tmp'"
    die "copy of $1 arrived with SHA-256 $got, not $3"
  fi
  remote "mv -f '$tmp' '$2' && sync"
}
write_text() { # remote-final text
  local tmp
  tmp="$(dirname "$1")/.$(basename "$1").new"
  printf '%s\n' "$2" | remote "umask 077; mkdir -p '$(dirname "$1")' && chmod 700 '$(dirname "$1")' && cat > '$tmp' && sync && if [ -f '$1' ]; then cp -f '$1' '$1.prev'; fi && mv -f '$tmp' '$1' && sync"
  local back
  back=$(remote "cat '$1'")
  [ "$back" = "$2" ] || die "$1 did not read back as written"
}

if [ "$STAGE_TK" = 1 ]; then
  # The boot hook refuses a quarantined image and stops after 2 strikes.
  quarantined=$(remote "grep -ci '$TK_SHA' /mnt/titan-api/tk/quarantine 2>/dev/null || true")
  strikes=$(remote "sed -n 's/^strikes=\([0-9]*\).*/\1/p' /mnt/titan-api/tk/strikes 2>/dev/null | tail -n 1")
  if [ "$RESET" = 1 ]; then
    remote "if [ -f /mnt/titan-api/tk/quarantine ]; then grep -vi '$TK_SHA' /mnt/titan-api/tk/quarantine > /mnt/titan-api/tk/.quarantine.new; mv -f /mnt/titan-api/tk/.quarantine.new /mnt/titan-api/tk/quarantine; fi"
    write_text /mnt/titan-api/tk/strikes "strikes=0"
    echo "strikes reset to 0; image taken out of quarantine"
  else
    [ "${quarantined:-0}" = 0 ] || echo "WARNING: this image is in tk/quarantine; the hook will refuse it. Run again with --reset-strikes." >&2
    [ "${strikes:-0}" -lt 2 ] || echo "WARNING: tk/strikes is ${strikes}; the hook will refuse to load. Run again with --reset-strikes." >&2
  fi

  put "$TK" /mnt/titan-api/tk/active.gz "$TK_SHA"
  write_text /mnt/titan-api/tk/config "$TK_CONFIG"
  echo "staged the tk image and tk/config"
fi
if [ "$CLAMP" = 1 ]; then
  put "$KO" /mnt/titan-api/qctrl/titan_qctrl.ko "$KO_SHA"
  write_text /mnt/titan-api/qctrl/config "$QCTRL_CONFIG"
  echo "staged titan_qctrl.ko and qctrl/config"
fi
if [ "$STAGE_FP" = 1 ]; then
  put "$FASTPATH" /mnt/titan-api/fastpath/titan_k1fp.ko "$FP_SHA"
  write_text /mnt/titan-api/fastpath/config "$FASTPATH_CONFIG"
  echo "staged titan_k1fp.ko and fastpath/config"
fi

echo
status
if [ "$STAGE_TK" = 1 ]; then
  cat <<EOF

Next: reboot the unit OUTSIDE 07:00 to 10:00 UTC (the SAS grants nothing then):
  ssh -p $PORT ${SSH_OPTS:-}${SSH_OPTS:+ }$SSH_USER@$UNIT reboot
After the boot, run this script with --status. Expect:
  witcher-tk.status  state=staged source=fs firmware=clean
  witcher-tk.result  confirmed=$TK_SHA
  witcher-tk.flags   state=applied (within 1 to 3 minutes of the confirm)
  witcher-qctrl.status state=applied (about 30 s after LTE comes up)
EOF
  if [ "$STAGE_FP" = 1 ]; then
    echo "  witcher-fastpath.status state=applied (about 30 s after eth0 and lte0pdn2 are up in IP passthrough)"
  fi
else
  cat <<EOF

Next: no reboot is needed for the fast path. Within about 45 s (once eth0 and
lte0pdn2 are up in IP passthrough and any configured clamp is loaded), run this
script with --status. Expect:
  witcher-fastpath.status state=applied
  /proc/k1fp              mode=$FASTPATH_MODE ... ports_ok=1 ... gate=open
EOF
fi
