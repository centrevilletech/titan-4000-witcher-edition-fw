#!/bin/sh
# Titan 4000 IP-passthrough repair overlay.
#
# Intended to run on the device (telnet/SSH, remount rw, copy to
# /etc/sysconfig/script/passthru-fix.sh) and also to be baked into a
# rebuilt rootfs. Does not touch modem.ko, tk.gz, CBRS/SAS, or RF NVM.
#
# What the stock rcinit does in passthrough, from the unpacked image:
#   - L2-bridges eth0 + lte0pdn1 on br0
#   - runs busybox udhcpd with max_leases 1 on alias br0:9
#   - lease file /tmp/udhcpd.leases, remaining yes
#   - tries to start ndppd, but ndppd is not in the rootfs
#
# Failure mode this script targets:
#   After WAN re-dial or LAN client reboot, udhcpd still holds the one
#   lease (or is bound to a dead br0:9). DISCOVER is then flooded out
#   lte0pdn1 onto the bearer. IPv6 NS for fe80::1 is likewise flooded
#   because ND proxy never actually runs.
#
# Userspace (busybox 1.21.0-uc0 / uClibc): /bin/sh, ifconfig, brctl,
# udhcpd, syslogd, tail, killall, /usr/bin/ebtables, /bin/ip (iproute2).
# No nc, logger, ndppd. lted may not source /etc/profile.

set -eu

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH

INTF=br0
DATA_IF=lte0pdn1
MGMT_IF=lte0pdn0
UDHCPD_CONF=/tmp/udhcpd.conf
UDHCPD_LEASES=/tmp/udhcpd.leases
LOG_TAG=passthru-fix
DROPBEAR=/usr/sbin/dropbear
TELNETD=/usr/sbin/telnetd
EBTABLES=/usr/bin/ebtables
SYSLOG_FWD=/usr/sbin/syslog-fwd
UDHCPD=/usr/sbin/udhcpd

# Remote syslog target on the MANAGEMENT APN only. Override via:
#   ucfg set config syslog remote_host 172.16.0.10
# Empty means local /var/log/messages only (stock).
REMOTE_HOST=""
REMOTE_PORT=514

log() {
    echo "$LOG_TAG: $*"
    # This busybox has no logger applet. Append so local syslogd still
    # picks the line up if /var/log/messages is its dest.
    echo "$LOG_TAG: $*" >> /var/log/messages 2>/dev/null || true
}

# The prefix keeper owns DHCP, flood scoping and neighbour discovery when its
# binary is installed. Running both would rewrite udhcpd twice and could answer
# fe80::1 twice. This firmware reports passthru=0 while eth0 is bridged to the
# customer bearer, so the bridge (or router_disable) is the check when the
# keeper is absent.
passthru_enabled() {
    if [ -x /usr/lib/titan-api/titan-pd-keeper ]; then
        return 1
    fi
    val=$(ucfg get config lan br passthru 2>/dev/null | awk '{print $1}') || val=""
    val=${val#passthru=}
    if [ "$val" = "1" ]; then
        return 0
    fi
    proto=$(nvram_get 0 router_disable 2>/dev/null) || proto=""
    proto=${proto##*: }
    proto=$(printf '%s' "$proto" | tr -d '[:space:]')
    if [ "$proto" = "1" ]; then
        return 0
    fi
    [ -d /sys/class/net/br0/brif/lte0pdn1 ]
}

# ip -4 -o is present on this iproute2; ifconfig is the reliable fallback.
ipv4_of() {
    out=$(ip -4 -o addr show dev "$1" 2>/dev/null | awk '{print $4}' | cut -d/ -f1) || out=""
    if [ -z "$out" ]; then
        out=$(ifconfig "$1" 2>/dev/null | awk '/inet addr:/ { print $2 }' | cut -d: -f2) || out=""
    fi
    echo "$out"
}

ipv4_first() {
    ipv4_of "$1" | awk 'NF { print; exit }'
}

mgmt_addrs() {
    ipv4_of "$MGMT_IF"
}

# Rewrite udhcpd so a re-DISCOVER gets the current bearer address.
# max_leases is raised from 1 so a MAC change does not wedge the server.
# The alias br0:9 is left at 10.1.1.1. The lease file is unlinked on PDN-up
# so a stale binding cannot occupy the only slot.
restart_passthru_dhcp() {
    # The bearer address is a host route on br0. br0:9 stays 10.1.1.1; udhcpd
    # offers the bearer address from that alias. Never offer 10.1.1.1 itself,
    # and never move the alias onto the bearer address.
    data_ip=$(ip route show dev "$INTF" 2>/dev/null | awk '
        $2 == "dev" && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            ip = $1
            split(ip, o, ".")
            if (o[1] == 10 || o[1] == 127) next
            if (o[1] == 192 && o[2] == 168) next
            if (ip == "172.20.0.152") next
            print ip
            exit
        }') || data_ip=""
    router=$(ip route show dev "$DATA_IF" 2>/dev/null | awk '/default/ { print $3; exit }') || router=""
    if [ -z "$router" ]; then
        router=$(ip route show dev "$INTF" 2>/dev/null | awk '/default/ { print $3; exit }') || router=""
    fi
    if [ -z "$data_ip" ] || [ -z "$router" ]; then
        log "no customer bearer route yet; skip dhcp restart"
        return 0
    fi
    dns=$(awk '/^option dns / { print $3; exit }' "$UDHCPD_CONF" 2>/dev/null) || dns=""

    cat > "$UDHCPD_CONF" <<EOF
pidfile /var/run/udhcpd.pid
start $data_ip
end $data_ip
max_leases 8
interface ${INTF}:9
remaining yes
auto_time 5
lease_file $UDHCPD_LEASES
option subnet 255.255.255.240
option router $router
option lease 120
EOF
    if [ -n "$dns" ]; then
        echo "option dns $dns" >> "$UDHCPD_CONF"
    fi
    rm -f "$UDHCPD_LEASES"
    touch "$UDHCPD_LEASES"
    killall -q udhcpd 2>/dev/null || true
    sleep 1
    $UDHCPD -f "$UDHCPD_CONF" &
    log "udhcpd restarted ip=$data_ip router=$router max_leases=8 remaining=yes"
}

# Stop DHCP and IPv6 link-local/multicast from flooding up the LTE bearer.
# Allow RS (ICMPv6 type 133), NS to the gateway, and DHCPv6 (udp/547) through.
# GUA in the PDN /64 and the delegated prefix are not source-filtered here.
scope_lan_flood() {
    if [ ! -x "$EBTABLES" ]; then
        log "ebtables missing"
        return 0
    fi
    # This ebtables build rejects "--ip-protocol udp". UDP is protocol 17.
    $EBTABLES -D FORWARD -o "$DATA_IF" -p IPv4 --ip-proto 17 --ip-dport 67 -j DROP 2>/dev/null || true
    $EBTABLES -A FORWARD -o "$DATA_IF" -p IPv4 --ip-proto 17 --ip-dport 67 -j DROP || true
    $EBTABLES -D FORWARD -o "$DATA_IF" -p IPv4 --ip-proto 17 --ip-dport 68 -j DROP 2>/dev/null || true
    $EBTABLES -A FORWARD -o "$DATA_IF" -p IPv4 --ip-proto 17 --ip-dport 68 -j DROP || true

    # IPv6 multicast dest MAC 33:33:* is RS/RA/NS/NA/MLD/DHCPv6-all-relays.
    # Drop MLD and unknown link-local multicast toward the bearer; keep
    # DHCPv6-all-relays (33:33:00:01:00:02) and all-routers (33:33:00:00:00:02).
    $EBTABLES -D FORWARD -o "$DATA_IF" -d 33:33:00:00:00:16 -j DROP 2>/dev/null || true
    $EBTABLES -A FORWARD -o "$DATA_IF" -d 33:33:00:00:00:16 -j DROP || true
    log "ebtables flood-scope installed on $DATA_IF"
}

# Not called. The core's SMF already answers neighbour solicitations for
# fe80::1. A proxy on the bridge would send a second answer. ndppd is also
# not shipped on this firmware.
nd_proxy_gateway() {
    echo 1 > /proc/sys/net/ipv6/conf/all/proxy_ndp 2>/dev/null || true
    echo 1 > /proc/sys/net/ipv6/conf/$INTF/proxy_ndp 2>/dev/null || true
    echo 1 > /proc/sys/net/ipv6/conf/$DATA_IF/proxy_ndp 2>/dev/null || true
    # fe80::1 is the observed SMF RA source on this EPC.
    ip -6 neigh add proxy fe80::1 dev "$INTF" 2>/dev/null || \
        ip -6 neigh replace proxy fe80::1 dev "$INTF" 2>/dev/null || true
    log "proxy_ndp enabled for fe80::1 on $INTF"
}

# BusyBox v1.21.0-uc0 syslogd has no -R and no nc/logger applets.
# scripts/syslog-fwd.c is the UDP sender; it must be cross-compiled for
# ARM/uClibc and installed as /usr/sbin/syslog-fwd.
start_remote_syslog() {
    host=$REMOTE_HOST
    if [ -z "$host" ]; then
        host=$(ucfg get config syslog remote_host 2>/dev/null | awk '{print $1}') || host=""
        host=${host#remote_host=}
    fi
    [ -n "$host" ] && [ "$host" != "remote_host=" ] || return 0
    if [ ! -x "$SYSLOG_FWD" ]; then
        log "syslog-fwd missing; remote syslog not started (need ARM build of scripts/syslog-fwd.c)"
        return 0
    fi
    mgmt=$(ipv4_first "$MGMT_IF") || mgmt=""
    [ -n "$mgmt" ] || return 0
    killall -q syslog-fwd 2>/dev/null || true
    $SYSLOG_FWD -s "$mgmt" -d "$host" -p "$REMOTE_PORT" -f /var/log/messages &
    log "remote syslog $mgmt -> $host:$REMOTE_PORT"
}

# Operator shell access. Dropbear listens on the LAN and the management APN,
# never the customer PDN (lte0pdn1). This script does not set a root password.
# Telnet is stopped; authenticated desktop recovery replaces the old shell fallback.
#
# ip -4 -o addr lists every address; $2 is the interface. We exclude lo, the
# customer PDN, and 169.254 link-local.
lan_and_mgmt_addrs() {
    ip -4 -o addr show 2>/dev/null \
        | awk -v skip="$DATA_IF" '$2!=skip && $2!="lo" {print $4}' \
        | cut -d/ -f1 | grep -vE '^169\.254\.' | sort -u
}
lan_only_addrs() {
    ip -4 -o addr show 2>/dev/null \
        | awk -v s1="$DATA_IF" -v s2="$MGMT_IF" '$2!=s1 && $2!=s2 && $2!="lo" {print $4}' \
        | cut -d/ -f1 | grep -vE '^169\.254\.' | sort -u
}

start_shell_access() {
    keys=/etc/dropbear

    # ---- SSH: dropbear, LAN + mgmt, not customer PDN ----
    ssh_addrs=$(lan_and_mgmt_addrs)
    [ -n "$ssh_addrs" ] || ssh_addrs="10.1.1.1 192.168.0.1"
    if [ -x "$DROPBEAR" ] && [ -f "$keys/dropbear_rsa_host_key" ]; then
        killall -q dropbear 2>/dev/null || true
        sleep 1
        pflags=""
        for a in $ssh_addrs; do pflags="$pflags -p $a:22"; done
        if [ -f "$keys/dropbear_dss_host_key" ]; then
            # shellcheck disable=SC2086 # pflags is a list of -p address:port pairs
            $DROPBEAR -r "$keys/dropbear_rsa_host_key" -r "$keys/dropbear_dss_host_key" $pflags 2>/dev/null \
              || $DROPBEAR -r "$keys/dropbear_rsa_host_key" $pflags 2>/dev/null || true
        else
            # shellcheck disable=SC2086
            $DROPBEAR -r "$keys/dropbear_rsa_host_key" $pflags 2>/dev/null || true
        fi
        log "sshd on:$pflags"
    else
        log "dropbear or host key missing; ssh not started"
    fi

    # Recovery is password-authenticated in the browser. Never launch an
    # unauthenticated root shell, even on a LAN address shared by a bridge.
    killall -q telnetd 2>/dev/null || true

}
on_pdn_up() {
    log "PDN up $*"
    if passthru_enabled; then
        restart_passthru_dhcp
        scope_lan_flood
    fi
    start_remote_syslog
    start_shell_access
}

on_pdn_down() {
    log "PDN down $*"
    if passthru_enabled; then
        killall -q udhcpd 2>/dev/null || true
        rm -f "$UDHCPD_LEASES"
    fi
}

# libltesdk.so invokes "pdn_interface_ready.sh <if> READY|RELEASE".
# Stock script (and older overlay) looked for RESET; accept both.
case "${1:-}" in
    READY|up)
        on_pdn_up "$@"
        ;;
    RESET|RELEASE|down)
        on_pdn_down "$@"
        ;;
    start|"")
        if passthru_enabled; then
            restart_passthru_dhcp
            scope_lan_flood
        fi
        start_remote_syslog
        start_shell_access
        ;;
    *)
        echo "usage: $0 [start|READY|RESET|RELEASE]" >&2
        exit 1
        ;;
esac
