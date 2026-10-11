//go:build windows

// bond-client bonds several local network interfaces into one Wintun tunnel
// to a bond-server relay. See also bond-gui for the windowed version.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rdbuff/bond/internal/bond"
	"github.com/rdbuff/bond/internal/client"
)

func main() {
	def := client.DefaultConfig()
	var (
		server   = flag.String("server", def.Server, "relay address")
		key      = flag.String("key", "", "file holding the base64 pre-shared key (default: bond.key in the config folder)")
		paths    = flag.String("paths", strings.Join(def.Paths, ","), "comma-separated interface names to bond")
		mtu      = flag.Int("mtu", def.MTU, "tunnel MTU")
		addr     = flag.String("addr", def.Addr, "tunnel address of this client")
		dns      = flag.String("dns", strings.Join(def.DNS, ","), "DNS servers to use through the tunnel")
		defRoute = flag.Bool("default-route", def.DefaultRoute, "send all IPv4 traffic through the tunnel")
		reorder  = flag.Duration("reorder", def.Reorder, "minimum reorder timeout (adapts upwards)")
		stats    = flag.Duration("stats", 2*time.Second, "stats interval (0 disables)")
		kill     = flag.Bool("killswitch", false, "block all traffic outside the tunnel while running")
	)
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfg := client.Config{
		Server: *server, KeyFile: *key, MTU: *mtu, Addr: *addr,
		DefaultRoute: *defRoute, Reorder: *reorder, KillSwitch: *kill, Logf: log.Printf,
	}
	for _, p := range strings.Split(*paths, ",") {
		cfg.Paths = append(cfg.Paths, strings.TrimSpace(p))
	}
	for _, d := range strings.Split(*dns, ",") {
		if d = strings.TrimSpace(d); d != "" {
			cfg.DNS = append(cfg.DNS, d)
		}
	}
	c, err := client.Start(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if *stats > 0 {
		go statsLoop(c, cfg.Paths, *stats)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Print("shutting down")
	c.Stop()
}

func statsLoop(c *client.Client, names []string, every time.Duration) {
	var mon bond.Monitor
	for range time.Tick(every) {
		e := c.Engine()
		if e == nil {
			continue
		}
		if mon.E != e {
			mon = bond.Monitor{E: e}
			copy(mon.Names[:], names)
		}
		if r := mon.Report(); r != "" {
			fmt.Print(time.Now().Format("15:04:05 "), r)
		}
	}
}
