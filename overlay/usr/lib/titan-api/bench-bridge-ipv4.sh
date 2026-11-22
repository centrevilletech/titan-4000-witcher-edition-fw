#!/bin/sh
# Foreground, opt-in trial on an isolated passthrough bench. No boot hook.
set -eu
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
[ "${WITCHER_BENCH_BRIDGE_IPV4:-0}" = 1 ] && [ "$#" = 2 ] || exit 64
keeper=/usr/lib/titan-api/titan-pd-keeper
knob=/proc/sys/net/bridge/bridge-nf-call-iptables
sas=$1
# A verified SAS reply port (or reserved range), in on-wire coordinates
# after SNAT. Never redirect all customer TLS sessions to the same host.
reply_ports=$2
printf '%s\n' "$reply_ports" | awk -F: '
 NF > 2 || $1 !~ /^[0-9]+$/ || $1 < 1 || $1 > 65535 { exit 1 }
 NF == 2 && ($2 !~ /^[0-9]+$/ || $2+0 < $1+0 || $2 > 65535) { exit 1 }
' || exit 64
endpoints=$("$keeper" bench-bridge-endpoints "$sas") || exit 1
# The keeper emits an interface name and two parsed IPv4 addresses.
set -- $endpoints
[ "$#" = 3 ] || exit 1
port=$1
client=$2
host=$3
read -r original < "$knob"
[ "$original" = 1 ] || exit 1
for flag in /sys/class/net/*/bridge/nf_call_iptables; do
 read -r per_bridge < "$flag"
 case "$flag" in */br0/bridge/*) [ "$per_bridge" = 0 ];; *) [ "$per_bridge" = 1 ];; esac || exit 1
done
lock=/tmp/witcher-bridge-trial
umask 077
mkdir "$lock" || exit 1
ebt() { /usr/bin/ebtables -t nat "$@"; }
jump() {
 ebt "$@" -i "$port" -p IPv4 --ip-src "$host" --ip-dst "$client" \
  --ip-proto tcp --ip-sport 443 --ip-dport "$reply_ports" -j WITCHER_SAS_TEST
}
# One cleanup owner. Restore L3 processing before removing the reply path.
finish() {
 echo 1 > "$knob" || return 1
 jump -D PREROUTING 2>/dev/null || :
 ebt -F WITCHER_SAS_TEST && ebt -X WITCHER_SAS_TEST || return 1
 rmdir "$lock"
}
if ! ebt -N WITCHER_SAS_TEST; then rmdir "$lock"; exit 1; fi
trap finish EXIT
trap 'exit 1' HUP INT TERM
ebt -A WITCHER_SAS_TEST -j redirect --redirect-target ACCEPT
jump -I PREROUTING 1
# Compare the complete listing on each check so a vendor flush or displaced
# jump ends the trial. Never fight a vendor reset by writing zero again.
listing() {
 ebt -L PREROUTING --Lx && ebt -L WITCHER_SAS_TEST --Lx
}
expected=$(listing)
printf '%s\n' "$expected" | awk '
 /-A PREROUTING / && !first++ { jump = ($NF == "WITCHER_SAS_TEST") }
 /-A WITCHER_SAS_TEST / && /-j redirect/ { redirect = 1 }
 END { exit !(jump && redirect) }
' || exit 1
[ "$("$keeper" bench-bridge-endpoints "$sas")" = "$endpoints" ] || exit 1
# Independent rollback if the foreground monitor is killed or a tool hangs.
# The deadline owns cleanup after its parent dies. The lock excludes a new trial.
parent=$$
(
 trap - EXIT HUP INT TERM
 elapsed=0
 while [ "$elapsed" -lt 120 ] && kill -0 "$parent" 2>/dev/null; do
  sleep 1
  elapsed=$((elapsed + 1))
 done
 echo 1 > "$knob" || exit 1
 if ! kill -0 "$parent" 2>/dev/null; then finish; fi
) </dev/null >/dev/null 2>&1 &
deadline=$!
trap 'echo 1 > "$knob"; kill "$deadline" 2>/dev/null || :; wait "$deadline" 2>/dev/null || :; finish' EXIT
echo 0 > "$knob"
while :; do
 sleep 1
 read -r active < "$knob"
 [ "$active" = 0 ] && [ "$(listing)" = "$expected" ] &&
  [ "$("$keeper" bench-bridge-endpoints "$sas")" = "$endpoints" ] || exit 1
done
