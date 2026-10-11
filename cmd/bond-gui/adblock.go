//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/rdbuff/bond/internal/adblock"
)

const (
	listMaxAge = 24 * time.Hour

	// The resolver listens on its own loopback address; 0.0.0.0:53 is often
	// taken by Internet Connection Sharing (Hyper-V's Default Switch).
	resolverIP = "127.0.0.53"
	nrptTag    = "Bond ad blocker"
)

type uiAdBlock struct {
	Enabled bool   `json:"enabled"`
	Loading bool   `json:"loading"`
	Domains int    `json:"domains"`
	Blocked uint64 `json:"blocked"`
	Error   string `json:"error"`
}

func listCachePath() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "Bond", "blocklist-hosts.txt")
}

func (a *app) adBlockStatus() uiAdBlock {
	n, _ := a.filter.Count()
	a.mu.Lock()
	defer a.mu.Unlock()
	st := uiAdBlock{
		Enabled: a.fs.AdBlock, Loading: a.listLoading, Domains: n,
		Blocked: a.filter.Blocked.Load(), Error: a.listErr,
	}
	if a.abErr != "" {
		st.Error = a.abErr
	}
	return st
}

// setAdBlock switches system-wide blocking on or off and remembers the
// choice. It works whether or not bonding is on. Returns a message for the
// user, or "".
func (a *app) setAdBlock(on bool) string {
	a.mu.Lock()
	a.fs.AdBlock = on
	err := a.fs.save()
	a.mu.Unlock()
	a.abApply()
	if err != nil {
		return "Couldn't save the setting: " + err.Error()
	}
	return ""
}

// abApply brings the resolver and the DNS policy in line with a.fs.AdBlock.
// Calls are serialized; slow steps (PowerShell, downloads) run off the UI
// thread.
func (a *app) abApply() {
	a.abMu.Lock()
	a.abGen++
	gen := a.abGen
	a.abMu.Unlock()
	go func() {
		a.abMu.Lock()
		defer a.abMu.Unlock()
		if gen != a.abGen {
			return // superseded by a newer toggle
		}
		a.mu.Lock()
		on, dns := a.fs.AdBlock, append([]string{}, a.cfg.DNS...)
		a.mu.Unlock()
		a.filter.SetEnabled(on)
		var errMsg string
		if on {
			if a.resolver == nil {
				srv, err := adblock.Serve(resolverIP+":53", dns, a.filter, func(string, ...any) {})
				if err != nil {
					errMsg = fmt.Sprintf("Can't start the ad blocker's DNS server: %v", err)
				}
				a.resolver = srv
			}
			if a.resolver != nil {
				if err := setDNSPolicy(true); err != nil {
					errMsg = err.Error()
				}
				go a.updateList()
			}
		} else {
			if err := setDNSPolicy(false); err != nil {
				errMsg = err.Error()
			}
			if a.resolver != nil {
				a.resolver.Close()
				a.resolver = nil
			}
		}
		flushDNSCache()
		a.mu.Lock()
		a.abErr = errMsg
		a.mu.Unlock()
	}()
}

// restartResolver picks up new upstream DNS servers.
func (a *app) restartResolver() {
	a.abMu.Lock()
	if a.resolver != nil {
		a.resolver.Close()
		a.resolver = nil
	}
	a.abMu.Unlock()
	a.abApply()
}

// abShutdown removes the DNS policy before the app exits.
func (a *app) abShutdown() {
	a.abMu.Lock()
	defer a.abMu.Unlock()
	if a.fs.AdBlock {
		setDNSPolicy(false)
		flushDNSCache()
	}
	if a.resolver != nil {
		a.resolver.Close()
		a.resolver = nil
	}
}

// setDNSPolicy adds or removes a Name Resolution Policy Table rule that sends
// every DNS query, on every adapter, to the ad blocker's resolver. 1.1.1.1 is
// listed second so that name resolution keeps working if Bond is killed
// without cleaning up; the next start removes the stale rule.
func setDNSPolicy(on bool) error {
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
Get-DnsClientNrptRule | Where-Object Comment -eq '%s' | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }`, nrptTag)
	if on {
		script += fmt.Sprintf(`
Add-DnsClientNrptRule -Namespace '.' -NameServers '%s','1.1.1.1' -Comment '%s' | Out-Null`, resolverIP, nrptTag)
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("DNS policy: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// updateList loads the blocklist from cache or downloads it if it is stale.
func (a *app) updateList() {
	a.mu.Lock()
	if a.listLoading {
		a.mu.Unlock()
		return
	}
	a.listLoading, a.listErr = true, ""
	a.mu.Unlock()
	_, err := a.filter.Update(context.Background(), adblock.DefaultListURL, listCachePath(), listMaxAge)
	a.mu.Lock()
	a.listLoading = false
	if err != nil {
		a.listErr = err.Error()
	}
	a.mu.Unlock()
	if err == nil {
		flushDNSCache()
	}
}

// refreshLists keeps the blocklist current while the app runs.
func (a *app) refreshLists() {
	for range time.Tick(6 * time.Hour) {
		if a.filter.Enabled() {
			a.updateList()
		}
	}
}

var procFlushDNS = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

func flushDNSCache() {
	if procFlushDNS.Find() == nil {
		procFlushDNS.Call()
	}
}
