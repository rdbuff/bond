//go:build windows

package client

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const ipUnicastIf = 31 // IP_UNICAST_IF

// pinToInterface makes a socket send through the given interface regardless of
// the routing table, so the tunnel's own default route cannot capture it.
func pinToInterface(ifIndex int) func(network, address string, rc syscall.RawConn) error {
	return func(network, address string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			var be [4]byte
			binary.BigEndian.PutUint32(be[:], uint32(ifIndex)) // network byte order
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf,
				int(binary.NativeEndian.Uint32(be[:])))
		})
		if err != nil {
			return err
		}
		return serr
	}
}

func interfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
			return n.IP.To4(), nil
		}
	}
	return nil, fmt.Errorf("%s has no IPv4 address", iface.Name)
}

func defaultGateway(luid winipcfg.LUID) (netip.Addr, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return netip.Addr{}, err
	}
	for i := range rows {
		r := &rows[i]
		if r.InterfaceLUID == luid && r.DestinationPrefix.Prefix().Bits() == 0 {
			if gw := r.NextHop.Addr(); gw.IsValid() && !gw.IsUnspecified() {
				return gw, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("no default gateway")
}

type netConfig struct {
	MTU         int
	Addr        netip.Prefix
	Server      netip.Addr
	PhysIfIndex []int
}

// configureAdapter addresses the tunnel adapter and pins host routes to the
// relay on the physical interfaces so that unbonded traffic to it (e.g. SSH)
// keeps working. It returns a cleanup function that removes what it added
// outside the tunnel adapter.
func configureAdapter(dev tun.Device, c netConfig, logf func(string, ...any)) (func(), error) {
	luid := winipcfg.LUID(dev.(*tun.NativeTun).LUID())
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{c.Addr}); err != nil {
		return nil, fmt.Errorf("set address: %w", err)
	}
	ipif, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	ipif.NLMTU = uint32(c.MTU)
	ipif.UseAutomaticMetric = false
	ipif.Metric = 0
	ipif.DadTransmits = 0
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	if err := ipif.Set(); err != nil {
		return nil, fmt.Errorf("set interface: %w", err)
	}

	type hostRoute struct {
		luid winipcfg.LUID
		gw   netip.Addr
	}
	var added []hostRoute
	dst := netip.PrefixFrom(c.Server, 32)
	for i, idx := range c.PhysIfIndex {
		pl, err := winipcfg.LUIDFromIndex(uint32(idx))
		if err != nil {
			continue
		}
		gw, err := defaultGateway(pl)
		if err != nil {
			logf("interface %d: %v (no host route to relay)", idx, err)
			continue
		}
		if err := pl.AddRoute(dst, gw, uint32(i)); err != nil && err != windows.ERROR_OBJECT_ALREADY_EXISTS {
			logf("host route via %v: %v", gw, err)
			continue
		}
		added = append(added, hostRoute{pl, gw})
	}
	cleanup := func() {
		for _, r := range added {
			r.luid.DeleteRoute(dst, r.gw)
		}
	}

	return cleanup, nil
}

// routeAllTraffic points the IPv4 default route and DNS at the tunnel. The
// routes disappear with the adapter.
func routeAllTraffic(dev tun.Device, dns []netip.Addr) error {
	luid := winipcfg.LUID(dev.(*tun.NativeTun).LUID())
	for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		err := luid.AddRoute(netip.MustParsePrefix(p), netip.IPv4Unspecified(), 0)
		if err != nil && err != windows.ERROR_OBJECT_ALREADY_EXISTS {
			return fmt.Errorf("route %s: %w", p, err)
		}
	}
	if len(dns) > 0 {
		if err := luid.SetDNS(windows.AF_INET, dns, nil); err != nil {
			return fmt.Errorf("set DNS: %w", err)
		}
	}
	return nil
}
