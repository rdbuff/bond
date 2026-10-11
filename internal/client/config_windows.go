//go:build windows

package client

import (
	"net"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// ConfigDir is where bond.json and bond.key live. A copy that keeps either
// file next to its executable is "portable" and uses that folder; an
// installed copy uses %APPDATA%\Bond.
func ConfigDir() string {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	for _, f := range []string{"bond.key", "bond.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return dir
		}
	}
	return filepath.Join(os.Getenv("APPDATA"), "Bond")
}

// GatewayInterfaces lists the names of the interfaces that have an IPv4
// default route, i.e. the connections that can reach the internet. It is
// the default set of paths to bond.
func GatewayInterfaces() []string {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil
	}
	var names []string
	seen := map[uint32]bool{}
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.Prefix().Bits() != 0 || seen[r.InterfaceIndex] {
			continue
		}
		if gw := r.NextHop.Addr(); !gw.IsValid() || gw.IsUnspecified() {
			continue // on-link default routes belong to tunnels such as Bond itself
		}
		seen[r.InterfaceIndex] = true
		if ifc, err := net.InterfaceByIndex(int(r.InterfaceIndex)); err == nil && ifc.Name != "Bond" {
			names = append(names, ifc.Name)
		}
	}
	sort.Strings(names)
	return names
}
