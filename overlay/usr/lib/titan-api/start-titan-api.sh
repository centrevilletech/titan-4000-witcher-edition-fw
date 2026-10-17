#!/bin/sh
# shellcheck disable=SC2046,SC2015
# Root-owned service launcher. Never modifies NVRAM, firmware banks or boot hooks.
# start stage ADDRESS | start production | stop | status | identity
set -eu
# Native BusyBox lacks stat: intentional splitting of ls numeric mode/owner fields.
umask 077
[ "$(id -u)" = 0 ] || { echo 'Service control requires root.' >&2; exit 77; }
bundle=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
runtime=/tmp/witcher-api
private_file() {
 [ -f "$1" ] && [ ! -L "$1" ] || return 1
 set -- $(ls -ldn "$1")
 # 500 is the owner of every file shipped in this firmware image.
 [ "$3" = 0 ] || [ "$3" = 500 ] || return 1
 case "$1" in -rw-------|-rwx------|-rw-r-----|-rwxr-x---|-rw-r--r--|-rwxr-xr-x) ;; *) return 1;; esac
}
secure_dir() {
 [ -d "$1" ] && [ ! -L "$1" ] || return 1
 set -- $(ls -ldn "$1")
 [ "$3" = 0 ] || [ "$3" = 500 ] || return 1
 case "$1" in drwx------|drwxr-x---|drwxr-xr-x) ;; *) return 1;; esac
}
# Config is executable shell syntax, therefore must be trusted and private.
conf=/etc/titan-api.conf
if [ ! -e "$conf" ] && [ -f /mnt/titan-api/titan-api.conf ]; then
 conf=/mnt/titan-api/titan-api.conf
fi
if [ -e "$conf" ]; then
 private_file "$conf" || exit 77
 config_mode=$(ls -ldn "$conf")
 case "$config_mode" in -rw-------\ *) ;; *) exit 77;; esac
 # shellcheck source=/dev/null
 . "$conf"
fi
secure_dir "$bundle" || { echo 'Untrusted bundle directory.' >&2; exit 77; }
if [ ! -e "$runtime" ]; then mkdir "$runtime"; chmod 755 "$runtime"; fi
secure_dir "$runtime" || exit 77
# Collectors require a traversable directory, but private logs/PIDs remain 0600.
chmod 755 "$runtime"
process_owned() {
 service=$1
 pid=$2
 case "$pid" in ''|*[!0-9]*) return 1;; esac
 [ "$pid" -gt 1 ] && [ -r "/proc/$pid/cmdline" ] || return 1
 case "$service" in
  api) expected="$runtime/titan-api";;
  broker) expected="$runtime/titan-api --device-broker";;
  collector) expected="$runtime/collect.sh";;
  routes) expected="$runtime/start-titan-api.sh restore-routes-loop";;
  *) return 1;;
 esac
 command=$(tr '\000' ' ' < "/proc/$pid/cmdline")
 case "$command" in "$expected "*|"/bin/sh $expected "*|"/bin/sh $expected") return 0;; *) return 1;; esac
}
process_alive() {
 # The process can exit between these checks; the caller simply polls again.
 kill -0 "$1" 2>/dev/null && [ -r "/proc/$1/status" ] && ! grep -q '^State:.*Z' "/proc/$1/status" 2>/dev/null
}
stop_all() {
 for service in api broker collector routes; do
  file=$runtime/$service.pid
  [ -e "$file" ] || continue
  private_file "$file" || return 77
  pid=$(cat "$file")
  if process_alive "$pid"; then
   # A recycled PID belongs to someone else: never signal it, only forget it.
   process_owned "$service" "$pid" || { echo "Ignoring stale $service PID file; PID $pid is not this service." >&2; rm -f "$file"; continue; }
   kill "$pid"
   attempts=0
   while process_alive "$pid" && [ "$attempts" -lt 5 ]; do sleep 1; attempts=$((attempts + 1)); done
   if process_alive "$pid"; then
    process_owned "$service" "$pid" || return 77
    kill -9 "$pid"
   fi
  fi
  rm -f "$file"
 done
}
# Ethernet identity is available without an APN. An explicitly configured
# expected serial still has to match; an unconfigured unit may report it later.
check_identity() {
 actual_mac=$(cat /sys/class/net/eth0/address)
 private_file "$bundle/titan-nvram" && [ -x "$bundle/titan-nvram" ] || { echo 'Missing or untrusted titan-nvram.' >&2; exit 77; }
 identity=$("$bundle/titan-nvram" read 0 sqns_identity_serialNumber)
 # A firmware image has no per-unit file. An explicit conf still has to match
 # this chassis; a missing one adopts the serial and MAC of the unit it is on.
 if [ -z "${TITAN_EXPECTED_MAC:-}" ]; then TITAN_EXPECTED_MAC=$actual_mac; fi
 if [ -z "${TITAN_EXPECTED_SERIAL:-}" ]; then
  TITAN_EXPECTED_SERIAL=$(printf '%s' "$identity" | sed -n 's/.*"sqns_identity_serialNumber":"\([^"]*\)".*/\1/p')
 fi
 : "${TITAN_EXPECTED_MAC:?Set TITAN_EXPECTED_MAC for this physical unit}"
 case "$TITAN_EXPECTED_SERIAL" in *[!A-Za-z0-9_-]*) exit 64;; esac
 expected_mac=$(printf '%s' "$TITAN_EXPECTED_MAC" | tr 'A-F' 'a-f')
 [ "$actual_mac" = "$expected_mac" ] || { echo 'Device MAC mismatch.' >&2; exit 77; }
 if [ -n "$TITAN_EXPECTED_SERIAL" ]; then
  printf '%s' "$identity" | grep -Fq "\"sqns_identity_serialNumber\":\"$TITAN_EXPECTED_SERIAL\"" || { echo 'Device serial mismatch.' >&2; exit 77; }
 fi
}
command_name=${1:-}
case "$command_name" in
 identity) [ "$#" = 1 ] || exit 64; check_identity; exit 0;;
 restore-routes-loop)
  [ "$#" = 1 ] || exit 64
  route_attempt=0
  # Routes need the bearer; registration and grant can take several minutes.
  while [ "$route_attempt" -lt 40 ]; do
   "$runtime/titan-api" --restore-routes && exit 0
   route_attempt=$((route_attempt + 1))
   sleep 15
  done
  echo 'Configured routes could not be restored after 40 attempts.' >&2
  exit 1;;
 stop) [ "$#" = 1 ] || exit 64; stop_all; exit;;
 status)
  [ "$#" = 1 ] || exit 64
  result=0
  for service in api broker collector; do
   if [ -f "$runtime/$service.pid" ] && process_owned "$service" "$(cat "$runtime/$service.pid")"; then
    echo "$service running"
   else echo "$service stopped"; result=1; fi
  done
  exit "$result";;
 start) ;;
 *) echo 'Usage: start-titan-api.sh start stage ADDRESS | start production | stop | status | identity' >&2; exit 64;;
esac
profile=${2:-}
case "$profile" in
 stage)
  [ "$#" = 3 ] || exit 64
  address=$3
  case "$address" in ''|*[!0-9.]*) echo 'Stage address must be an IPv4 address.' >&2; exit 64;; esac
  TITAN_LISTEN=$address:${TITAN_HTTP_PORT:-8088}
  TITAN_TLS_LISTEN=$address:${TITAN_HTTPS_PORT:-8448}
  ;;
 production)
  [ "$#" = 2 ] || exit 64
  TITAN_LISTEN=0.0.0.0:80
  TITAN_TLS_LISTEN=0.0.0.0:443
  ;;
 *) exit 64;;
esac
for name in titan-api titan-device-helper titan-nvram titan-maintenance titan-seed-rng collect.sh start-titan-api.sh; do
 private_file "$bundle/$name" && [ -x "$bundle/$name" ] || { echo "Missing or untrusted $name." >&2; exit 77; }
done
check_identity
secure_dir "$bundle/ui" && private_file "$bundle/ui/index.html" || { echo 'Missing UI bundle.' >&2; exit 77; }
# The web worker drops to an unprivileged UID and serves the UI from the bundle.
for directory in "$bundle" "$bundle/ui"; do
 set -- $(ls -ldn "$directory")
 [ "$1" = drwxr-xr-x ] || { echo 'UI bundle is not readable by the web service.' >&2; exit 77; }
done
# Public chassis identity for the login page. Keep it in RAM, outside private
# state and the firmware bank. The UI contains a link to this one regular file.
temporary=$runtime/.device-mac.$$.new
(set -C; printf '%s\n' "$actual_mac" | tr 'a-f' 'A-F' > "$temporary")
chmod 644 "$temporary"
mv -f "$temporary" "$runtime/device-mac.txt"
if [ "$profile" = production ]; then
 flags=$("$bundle/titan-nvram" read 0 http_enable https_enable)
 printf '%s' "$flags" | grep -Fq '"http_enable":"0"' && printf '%s' "$flags" | grep -Fq '"https_enable":"0"' || {
  echo 'Production requires a separately qualified legacy-server cutover.' >&2; exit 78;
 }
 # The binary consumes and durably replaces a private per-unit seed; never ship one in a bundle.
 # A power loss before publication can leave an unused replacement file.
 # Preserve it privately for diagnosis; never credit that uncommitted seed.
 if [ -e /mnt/titan-api/seed.next ]; then
  [ -f /mnt/titan-api/seed.next ] && [ ! -L /mnt/titan-api/seed.next ] || exit 77
  mv /mnt/titan-api/seed.next "/mnt/titan-api/.interrupted-seed-$$"
  sync
 fi
 "$bundle/titan-api" --prepare-boot-entropy
fi
# Every key is generated only after the per-unit seed has initialized the kernel.
if [ "$profile" = production ]; then
 /bin/sh "$bundle/prepare-tls.sh"
fi
if [ -e /mnt/titan-api/tls/cert.pem ] || [ -e /mnt/titan-api/tls/key.pem ]; then
 tls=/mnt/titan-api/tls
else
 tls=/mnt/titan-api/tls/current
fi
TITAN_TLS_CERT=${TITAN_TLS_CERT:-$tls/cert.pem}
TITAN_TLS_KEY=${TITAN_TLS_KEY:-$tls/key.pem}
private_file "$TITAN_TLS_CERT" && private_file "$TITAN_TLS_KEY" || { echo 'Missing or untrusted TLS files; existing identity was preserved.' >&2; exit 77; }
set -- $(ls -ldn "$TITAN_TLS_KEY")
[ "$1" = -rw------- ] || { echo 'TLS key must have mode 0600.' >&2; exit 77; }
stop_all
# Copy through fresh files so a failed transfer cannot truncate a running executable.
for name in titan-api titan-device-helper titan-nvram titan-maintenance titan-seed-rng collect.sh start-titan-api.sh; do
 temporary=$runtime/.$name.$$.new
 (set -C; cat "$bundle/$name" > "$temporary")
 chmod 700 "$temporary"
 [ "$name" != titan-api ] || chmod 755 "$temporary"
 mv -f "$temporary" "$runtime/$name"
done
TITAN_BROKER=$runtime/device.sock
TITAN_NVRAM_HELPER=$runtime/titan-nvram
TITAN_HELPER=$runtime/titan-device-helper
TITAN_SNAPSHOT=$runtime/telemetry.json
TITAN_WEBROOT=$bundle/ui
TITAN_UID=65534
# Firmware 4172 answers SAS status only on the web IPC source (4). Production owns
# it because the vendor server is off; staging beside that server must not claim it.
if [ "$profile" = production ]; then TITAN_CBRS_SOURCE=${TITAN_CBRS_SOURCE:-4}; else TITAN_CBRS_SOURCE=${TITAN_CBRS_SOURCE:-5}; fi
TITAN_AUTO_UPDATES=${TITAN_AUTO_UPDATES:-0}
export TITAN_LISTEN TITAN_TLS_LISTEN TITAN_TLS_CERT TITAN_TLS_KEY TITAN_BROKER TITAN_NVRAM_HELPER TITAN_HELPER TITAN_SNAPSHOT TITAN_WEBROOT TITAN_UID TITAN_CBRS_SOURCE TITAN_AUTO_UPDATES
# The shell service runs on its own; the web interface shows and edits its keys.
[ -z "${TITAN_SSH_PORT:-}" ] || export TITAN_SSH_PORT
# Never force Secure globally: HTTP-only LAN clients still need functional sessions.
unset TITAN_SECURE_COOKIE
for service in api broker collector routes; do
 logfile=$runtime/$service.log
 if [ -e "$logfile" ]; then private_file "$logfile" || exit 77; fi
 : > "$logfile"
 chmod 600 "$logfile"
done
started=0
trap '[ "$started" = 1 ] || stop_all' EXIT
trap 'exit 1' HUP INT TERM
# This kernel has no binfmt_script: a bare script path is interpreted inside the
# forked shell and keeps the launcher's command line. Name the interpreter so
# /proc/PID/cmdline identifies each service.
/bin/sh "$runtime/collect.sh" "$TITAN_HELPER" > "$runtime/collector.log" 2>&1 < /dev/null &
echo $! > "$runtime/collector.pid"
"$runtime/titan-api" --device-broker > "$runtime/broker.log" 2>&1 < /dev/null &
echo $! > "$runtime/broker.pid"
attempts=0
while [ ! -S "$TITAN_BROKER" ]; do
 process_owned broker "$(cat "$runtime/broker.pid")" || { echo 'Broker failed; inspect private broker.log.' >&2; exit 1; }
 [ "$attempts" -lt 10 ] || { echo 'Broker readiness timeout.' >&2; exit 1; }
 sleep 1; attempts=$((attempts + 1))
done
if [ "$profile" = production ]; then
 # Networking must be ready before the boot hook invokes this launcher.
 /bin/sh "$runtime/start-titan-api.sh" restore-routes-loop > "$runtime/routes.log" 2>&1 < /dev/null &
 echo $! > "$runtime/routes.pid"
fi
"$runtime/titan-api" > "$runtime/api.log" 2>&1 < /dev/null &
echo $! > "$runtime/api.pid"
sleep 1
for service in api broker collector; do process_owned "$service" "$(cat "$runtime/$service.pid")" || { echo "$service failed; inspect its private log." >&2; exit 1; }; done
started=1
trap - EXIT HUP INT TERM
echo "Titan native service running: HTTP $TITAN_LISTEN; TLS $TITAN_TLS_LISTEN"
