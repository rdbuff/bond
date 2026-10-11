#!/bin/sh
# Installs or updates the Bond relay on a Debian/Ubuntu server. Run as root
# from a folder holding bond-server-{amd64,arm64}, bond-fw.sh,
# bond-server.service and 90-bond.conf (an optional "key" file reuses an
# existing pre-shared key). Prints the key to paste into the Bond app.
set -e
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root (sudo sh install.sh)" >&2; exit 1; }

case "$(uname -m)" in
	aarch64|arm64) bin=bond-server-arm64 ;;
	x86_64|amd64)  bin=bond-server-amd64 ;;
	*) echo "unsupported CPU $(uname -m)" >&2; exit 1 ;;
esac
[ -f "$bin" ] || bin=bond-server
command -v iptables >/dev/null || { apt-get update -qq && apt-get install -y -qq iptables; }

install -m 755 "$bin" /usr/local/bin/bond-server
install -m 755 bond-fw.sh /usr/local/sbin/bond-fw.sh
install -d -m 700 /etc/bond
if [ ! -s /etc/bond/key ]; then
	if [ -s key ]; then
		install -m 600 key /etc/bond/key
	else
		umask 077
		head -c 32 /dev/urandom | base64 > /etc/bond/key
	fi
fi
install -m 644 90-bond.conf /etc/sysctl.d/90-bond.conf
sysctl -q -p /etc/sysctl.d/90-bond.conf
install -m 644 bond-server.service /etc/systemd/system/bond-server.service
systemctl daemon-reload
systemctl enable bond-server >/dev/null 2>&1
systemctl restart bond-server
sleep 1
/usr/local/sbin/bond-fw.sh
command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
systemctl is-active --quiet bond-server || { journalctl -u bond-server -n 20 --no-pager; exit 1; }

ip=$(curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
cat <<MSG

Bond relay is running on UDP port 51820.
Make sure your provider's firewall / security group allows inbound UDP 51820.

In the Bond app, open Settings and enter:
  Relay server: ${ip}
  Server key:   $(cat /etc/bond/key)
MSG
