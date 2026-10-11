//go:build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rdbuff/bond/internal/client"
)

// fileSettings is what bond.json stores; anything absent keeps its default.
type fileSettings struct {
	Server       string   `json:",omitempty"`
	Paths        []string `json:",omitempty"`
	DNS          []string `json:",omitempty"`
	AdBlock      bool     `json:",omitempty"`
	AdBlockAllow []string `json:",omitempty"`
	KillSwitch   bool     `json:",omitempty"`
	OnClose      string   `json:",omitempty"` // X button: ask (default), tray, quit
	OnMinimize   string   `json:",omitempty"` // minimize button: ask (default), tray, taskbar
	AutoConnect  bool     `json:",omitempty"` // turn bonding on when the app starts
}

func (fs fileSettings) apply(cfg *client.Config) {
	if fs.Server != "" {
		cfg.Server = fs.Server
	}
	if len(fs.Paths) > 0 {
		cfg.Paths = fs.Paths
	}
	if len(fs.DNS) > 0 {
		cfg.DNS = fs.DNS
	}
	cfg.KillSwitch = fs.KillSwitch
}

func (fs fileSettings) save() error {
	if err := os.MkdirAll(configDir(), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(fs, "", "  ")
	return os.WriteFile(settingsPath(), append(b, '\n'), 0o644)
}

type uiInterface struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type uiSettings struct {
	Server      string        `json:"server"`
	Paths       []string      `json:"paths"`
	DNS         string        `json:"dns"`
	HasKey      bool          `json:"hasKey"`
	Key         string        `json:"key"`   // only sent by the UI, when replacing the key
	Allow       string        `json:"allow"` // ad blocker allowlist, one domain per line
	KillSwitch  bool          `json:"killSwitch"`
	OnClose     string        `json:"onClose"`
	OnMinimize  string        `json:"onMinimize"`
	AutoStart   bool          `json:"autoStart"`
	AutoConnect bool          `json:"autoConnect"`
	Interfaces  []uiInterface `json:"interfaces"`
}

func configDir() string { return client.ConfigDir() }

func settingsPath() string { return filepath.Join(configDir(), "bond.json") }
func keyPath() string      { return filepath.Join(configDir(), "bond.key") }

// candidateInterfaces lists up interfaces with an IPv4 address that could
// carry a path, plus any configured ones that are currently missing.
func candidateInterfaces(configured []string) []uiInterface {
	var out []uiInterface
	seen := map[string]bool{}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Name == "Bond" ||
			strings.HasPrefix(ifc.Name, "vEthernet") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				out = append(out, uiInterface{ifc.Name, n.IP.String()})
				seen[ifc.Name] = true
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	for _, p := range configured {
		if !seen[p] {
			out = append(out, uiInterface{Name: p})
		}
	}
	return out
}

func (a *app) getSettings() uiSettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg := a.cfg
	_, err := os.Stat(keyPath())
	return uiSettings{
		Server:      cfg.Server,
		Paths:       cfg.Paths,
		DNS:         strings.Join(cfg.DNS, ", "),
		HasKey:      err == nil,
		Allow:       strings.Join(a.fs.AdBlockAllow, "\n"),
		KillSwitch:  a.fs.KillSwitch,
		OnClose:     orAsk(a.fs.OnClose),
		OnMinimize:  orAsk(a.fs.OnMinimize),
		AutoStart:   autoStartEnabled(),
		AutoConnect: a.fs.AutoConnect,
		Interfaces:  candidateInterfaces(cfg.Paths),
	}
}

// saveSettings validates and stores the settings, then reconnects if the
// tunnel is on. It returns a message for the user, or "" on success.
func (a *app) saveSettings(s uiSettings) string {
	s.OnClose, s.OnMinimize = orAsk(s.OnClose), orAsk(s.OnMinimize)
	if !validAction(s.OnClose, closeActions) || !validAction(s.OnMinimize, minimizeActions) {
		return "Unknown window button choice."
	}
	server := strings.TrimSpace(s.Server)
	if server == "" {
		return "Enter the relay server address."
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(strings.Trim(server, "[]"), "51820")
	}
	if _, err := net.ResolveUDPAddr("udp4", server); err != nil {
		return fmt.Sprintf("Can't resolve %s: %v", server, err)
	}
	if len(s.Paths) == 0 {
		return "Pick at least one connection to bond."
	}
	var dns []string
	for _, d := range strings.FieldsFunc(s.DNS, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if net.ParseIP(d).To4() == nil {
			return fmt.Sprintf("%q is not an IPv4 DNS server.", d)
		}
		dns = append(dns, d)
	}
	var key []byte
	if k := strings.TrimSpace(s.Key); k != "" {
		var err error
		if key, err = base64.StdEncoding.DecodeString(k); err != nil || len(key) < 32 {
			return "The key must be the base64 text from /etc/bond/key on your server."
		}
	} else if _, err := os.Stat(keyPath()); errors.Is(err, os.ErrNotExist) {
		return "Paste your server's key (printed by install.sh, or sudo cat /etc/bond/key)."
	}

	var allow []string
	for _, d := range strings.FieldsFunc(s.Allow, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' }) {
		d = strings.TrimSuffix(strings.ToLower(d), ".")
		if !strings.Contains(d, ".") {
			return fmt.Sprintf("%q in the allowed list is not a domain.", d)
		}
		allow = append(allow, d)
	}

	a.mu.Lock()
	fs := a.fs
	fs.Server, fs.Paths, fs.DNS, fs.AdBlockAllow, fs.KillSwitch = server, s.Paths, dns, allow, s.KillSwitch
	fs.OnClose, fs.OnMinimize, fs.AutoConnect = s.OnClose, s.OnMinimize, s.AutoConnect
	err := fs.save()
	if err == nil {
		a.fs = fs
	}
	a.mu.Unlock()
	if err != nil {
		return fmt.Sprintf("Can't save settings: %v", err)
	}
	if s.AutoStart != autoStartEnabled() {
		if err := setAutoStart(s.AutoStart); err != nil {
			return err.Error()
		}
	}
	a.filter.SetAllow(allow)
	flushDNSCache()
	if key != nil {
		os.MkdirAll(configDir(), 0o755)
		if err := os.WriteFile(keyPath(), []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
			return fmt.Sprintf("Can't save key: %v", err)
		}
	}

	a.mu.Lock()
	old := a.cfg
	a.cfg.Server, a.cfg.Paths, a.cfg.KillSwitch = server, s.Paths, s.KillSwitch
	if len(dns) > 0 {
		a.cfg.DNS = dns
	}
	dnsChanged := strings.Join(old.DNS, ",") != strings.Join(a.cfg.DNS, ",")
	reconnect := a.state == "on" && (old.Server != a.cfg.Server || old.KillSwitch != a.cfg.KillSwitch ||
		strings.Join(old.Paths, ",") != strings.Join(a.cfg.Paths, ",") || dnsChanged || key != nil)
	adBlockOn := a.fs.AdBlock
	a.mu.Unlock()
	if dnsChanged && adBlockOn {
		a.restartResolver()
	}
	if reconnect {
		a.restart()
	}
	return ""
}
