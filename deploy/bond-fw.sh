#!/bin/sh
# Idempotent firewall/NAT setup for bond-server. Oracle's Ubuntu image ends the
# INPUT and FORWARD chains with REJECT, so our ACCEPTs are inserted above them.
set -e
TUN=${TUN:-bond0}
NET=${NET:-10.77.0.0/24}
WAN=${WAN:-$(ip -4 route show default | awk '{print $5; exit}')}

add() { # add <table> <chain> <position|A> <rule...>
	t=$1 c=$2 p=$3; shift 3
	iptables -t "$t" -C "$c" "$@" 2>/dev/null && return 0
	if [ "$p" = A ]; then iptables -t "$t" -A "$c" "$@"; else iptables -t "$t" -I "$c" "$p" "$@"; fi
}

add filter INPUT   1 -p udp --dport 51820 -j ACCEPT
add filter INPUT   1 -i "$TUN" -j ACCEPT
add filter FORWARD 1 -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
add filter FORWARD 1 -i "$TUN" -s "$NET" -j ACCEPT
add nat    POSTROUTING A -s "$NET" -o "$WAN" -j MASQUERADE
add mangle FORWARD A -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
