#!/bin/sh
# shellcheck disable=SC2046
# Privileged collector for the unprivileged HTTP process. No network listener.
# Usage: collect.sh [/tmp/titan-device-helper|/tmp/witcher-api/titan-device-helper|/usr/libexec/titan-device-helper]
set -eu
# Native BusyBox lacks stat; mode/owner field splitting is intentional.
[ "$(id -u)" = 0 ] || { echo 'collector must run as root' >&2; exit 77; }
[ "$#" -le 1 ] || exit 64
collector_helper=${1:-/tmp/titan-device-helper}
case "$collector_helper" in
  /tmp/titan-device-helper|/tmp/witcher-api/titan-device-helper|/usr/libexec/titan-device-helper) ;;
  *) echo 'unapproved helper path' >&2; exit 64 ;;
esac
# Native busybox has no stat or mktemp; inspect exact owner/mode using ls -n.
[ -f "$collector_helper" ] && [ ! -L "$collector_helper" ] || exit 77
set -- $(ls -ldn "$collector_helper")
[ "$3" = 0 ] || exit 77
case "$1" in -rwx------|-rwxr-xr-x|-rwxr-x---) ;; *) exit 77 ;; esac
collector_dir=/tmp/witcher-api
if [ ! -e "$collector_dir" ]; then
  (umask 022; mkdir "$collector_dir")
fi
[ -d "$collector_dir" ] && [ ! -L "$collector_dir" ] || exit 77
set -- $(ls -ldn "$collector_dir")
[ "$1" = drwxr-xr-x ] && [ "$3" = 0 ] || exit 77
# Atomic creation without following a pre-existing file or symlink.
collector_tmp=$collector_dir/.telemetry.$$.tmp
(umask 022; set -C; : > "$collector_tmp") || exit 73
trap 'rm -f "$collector_tmp"' EXIT
trap 'exit 0' HUP INT TERM
while :; do
  if "$collector_helper" --snapshot > "$collector_tmp"; then
    chmod 644 "$collector_tmp"
    mv -f "$collector_tmp" "$collector_dir/telemetry.json"
    (umask 022; set -C; : > "$collector_tmp") || exit 73
  fi
  # Fixed cadence prevents failure loops. Last good snapshot ages on failure.
  sleep 1
done
