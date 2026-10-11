//go:build windows

// Package client runs the Windows end of the bonding tunnel: one UDP socket
// pinned to each bonded interface, a Wintun adapter, and the session with the
// relay. It is used by both the command-line client and the GUI.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/rdbuff/bond/internal/bond"
	"github.com/rdbuff/bond/internal/firewall"
	"github.com/rdbuff/bond/internal/proto"
)

type Config struct {
	Server       string        // relay host:port
	KeyFile      string        // base64 pre-shared key; "" = bond.key in ConfigDir()
	Paths        []string      // interface names to bond, e.g. WiFi, Ethernet
	MTU          int           // tunnel MTU
	Addr         string        // tunnel address of this client
	DNS          []string      // DNS servers used through the tunnel
	DefaultRoute bool          // send all IPv4 traffic through the tunnel
	Reorder      time.Duration // minimum reorder timeout

	// KillSwitch blocks all traffic that does not go through the tunnel from
	// Start until Stop, including while connecting or reconnecting. Only this
	// process (relay sockets), loopback, DHCP and NDP are exempt.
	KillSwitch bool

	// Logf receives diagnostic messages; nil discards them.
	Logf func(format string, args ...any)
}

func DefaultConfig() Config {
	return Config{
		Paths:        []string{"WiFi", "Ethernet"},
		MTU:          1420,
		Addr:         "10.77.0.2/24",
		DNS:          []string{"1.1.1.1", "8.8.8.8"},
		DefaultRoute: true,
		Reorder:      100 * time.Millisecond,
	}
}

// pathSock is one bonded interface: a UDP socket pinned to it.
type pathSock struct {
	id   int
	name string
	conn atomic.Pointer[net.UDPConn]

	mu    sync.Mutex
	ip    net.IP
	index int
}

var errNoConn = errors.New("no socket")

func (s *pathSock) Send(b []byte) error {
	c := s.conn.Load()
	if c == nil {
		return errNoConn
	}
	_, err := c.Write(b)
	return err
}

func (s *pathSock) localIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ip == nil || s.conn.Load() == nil {
		return ""
	}
	return s.ip.String()
}

type Client struct {
	cfg    Config
	psk    []byte
	server *net.UDPAddr
	dns    []netip.Addr
	socks  []*pathSock
	dev    tun.Device
	mutex  windows.Handle

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	cur   atomic.Pointer[bond.Engine]
	hsAck chan []byte

	tunMu sync.Mutex
	wbufs [][]byte

	netMu      sync.Mutex
	netCleanup func()
	firewalled bool
	v6Blocked  bool // IPv6 outside the tunnel is blocked (Bond carries IPv4 only)
	routed     bool

	statusMu  sync.Mutex
	since     time.Time
	lastMsg   string
	prevAt    time.Time
	prevBytes []struct{ tx, rx uint64 }
	rates     []struct{ tx, rx float64 } // Mbit/s over the last measurement window
	prevEng   *bond.Engine
}

// ErrAlreadyRunning is returned when another bonding client holds the tunnel.
var ErrAlreadyRunning = errors.New("another Bond client is already running")

// Start brings the tunnel up and returns once the adapter exists; the session
// with the relay is established in the background (see Status). All IPv4
// traffic is switched to the tunnel only once the relay has answered, so an
// unreachable relay never cuts the machine off.
func Start(cfg Config) (*Client, error) {
	c := &Client{cfg: cfg, hsAck: make(chan []byte, 4)}
	if c.cfg.Logf == nil {
		c.cfg.Logf = func(string, ...any) {}
	}
	name, _ := windows.UTF16PtrFromString(`Global\BondTunnelClient`)
	m, err := windows.CreateMutex(nil, false, name)
	if err == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(m)
		return nil, ErrAlreadyRunning
	} else if err != nil {
		return nil, err
	}
	c.mutex = m
	ok := false
	defer func() {
		if !ok {
			c.Stop()
		}
	}()

	if strings.TrimSpace(cfg.Server) == "" {
		return nil, errors.New("no relay server configured")
	}
	keyPath := cfg.KeyFile
	if keyPath == "" {
		keyPath = filepath.Join(ConfigDir(), "bond.key")
	}
	if c.psk, err = loadKey(keyPath); err != nil {
		return nil, err
	}
	if c.server, err = net.ResolveUDPAddr("udp4", cfg.Server); err != nil {
		return nil, err
	}
	tunPrefix, err := netip.ParsePrefix(cfg.Addr)
	if err != nil {
		return nil, err
	}
	for _, d := range cfg.DNS {
		a, err := netip.ParseAddr(strings.TrimSpace(d))
		if err != nil {
			return nil, fmt.Errorf("DNS server %q: %w", d, err)
		}
		c.dns = append(c.dns, a)
	}
	if len(cfg.Paths) == 0 || len(cfg.Paths) > bond.MaxPaths {
		return nil, fmt.Errorf("need 1 to %d paths", bond.MaxPaths)
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())

	var physIdx []int
	bound := 0
	for i, n := range cfg.Paths {
		s := &pathSock{id: i, name: strings.TrimSpace(n)}
		c.socks = append(c.socks, s)
		if err := c.dial(s); err != nil {
			c.logf("path %s: %v (will keep trying)", s.name, err)
			continue
		}
		bound++
		physIdx = append(physIdx, s.index)
	}
	if bound == 0 {
		return nil, fmt.Errorf("none of %s is connected", strings.Join(cfg.Paths, ", "))
	}

	tun.WintunTunnelType = "Bond"
	if c.dev, err = tun.CreateTUN("Bond", cfg.MTU); err != nil {
		return nil, fmt.Errorf("create tunnel adapter (is wintun.dll next to the exe, and is it running as administrator?): %w", err)
	}
	c.netCleanup, err = configureAdapter(c.dev, netConfig{
		MTU: cfg.MTU, Addr: tunPrefix,
		Server: netip.AddrFrom4([4]byte(c.server.IP.To4())), PhysIfIndex: physIdx,
	}, c.logf)
	if err != nil {
		return nil, err
	}
	if cfg.KillSwitch {
		if err := firewall.EnableFirewall(c.dev.(*tun.NativeTun).LUID(), false, nil); err != nil {
			return nil, fmt.Errorf("kill switch: %w", err)
		}
		c.firewalled = true
	}

	for _, s := range c.socks {
		c.goLoop(func() { c.readLoop(s) })
	}
	c.goLoop(c.watchInterfaces)
	c.goLoop(c.tunLoop)
	c.goLoop(c.tickLoop)
	c.goLoop(c.sessionLoop)
	ok = true
	return c, nil
}

// Stop tears the tunnel down and undoes all network changes. It is safe to
// call more than once.
func (c *Client) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	for _, s := range c.socks {
		if uc := s.conn.Swap(nil); uc != nil {
			uc.Close()
		}
	}
	if c.dev != nil {
		c.dev.Close() // also removes the tunnel's routes and DNS
	}
	if c.firewalled {
		firewall.DisableFirewall()
		c.firewalled = false
	}
	c.wg.Wait()
	if c.v6Blocked {
		firewall.UnblockIPv6()
		c.v6Blocked = false
	}
	for _, s := range c.socks { // a re-bind may have raced with the first sweep
		if uc := s.conn.Swap(nil); uc != nil {
			uc.Close()
		}
	}
	c.netMu.Lock()
	if c.netCleanup != nil {
		c.netCleanup()
		c.netCleanup = nil
	}
	c.netMu.Unlock()
	if c.mutex != 0 {
		windows.CloseHandle(c.mutex)
		c.mutex = 0
	}
}

func (c *Client) goLoop(f func()) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		f()
	}()
}

func (c *Client) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	c.statusMu.Lock()
	c.lastMsg = msg
	c.statusMu.Unlock()
	c.cfg.Logf("%s", msg)
}

// sleep waits for d or until the client stops; it reports whether to go on.
func (c *Client) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-c.ctx.Done():
		return false
	}
}

func loadKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) < 32 {
		return nil, fmt.Errorf("%s must hold base64 of at least 32 bytes", path)
	}
	return k, nil
}

func (c *Client) dial(s *pathSock) error {
	iface, err := net.InterfaceByName(s.name)
	if err != nil {
		return err
	}
	ip, err := interfaceIPv4(iface)
	if err != nil {
		return err
	}
	d := net.Dialer{LocalAddr: &net.UDPAddr{IP: ip}, Control: pinToInterface(iface.Index)}
	nc, err := d.DialContext(c.ctx, "udp4", c.server.String())
	if err != nil {
		return err
	}
	uc := nc.(*net.UDPConn)
	uc.SetReadBuffer(8 << 20)
	uc.SetWriteBuffer(4 << 20)
	s.mu.Lock()
	s.ip, s.index = ip, iface.Index
	s.mu.Unlock()
	if old := s.conn.Swap(uc); old != nil {
		old.Close()
	}
	c.logf("path %s: %v -> %v", s.name, uc.LocalAddr(), c.server)
	return nil
}

// watchInterfaces binds paths whose interface appears and re-binds those whose
// address changes.
func (c *Client) watchInterfaces() {
	for c.sleep(3 * time.Second) {
		for _, s := range c.socks {
			iface, err := net.InterfaceByName(s.name)
			if err != nil {
				continue
			}
			ip, err := interfaceIPv4(iface)
			if err != nil {
				continue
			}
			s.mu.Lock()
			changed := !ip.Equal(s.ip) || s.conn.Load() == nil
			s.mu.Unlock()
			if changed && c.ctx.Err() == nil {
				c.logf("path %s now at %v, binding", s.name, ip)
				if err := c.dial(s); err != nil {
					c.logf("path %s: %v", s.name, err)
				}
			}
		}
	}
}

func (c *Client) readLoop(s *pathSock) {
	buf := bond.GetBuf()
	rx := make([]bond.Rx, 1)
	for c.ctx.Err() == nil {
		uc := s.conn.Load()
		if uc == nil {
			c.sleep(200 * time.Millisecond)
			continue
		}
		n, err := uc.Read(buf[:])
		if err != nil {
			if s.conn.Load() == uc && !errors.Is(err, net.ErrClosed) {
				c.sleep(10 * time.Millisecond)
			}
			continue
		}
		if n < proto.HeaderLen {
			continue
		}
		if buf[0] == proto.TypeHelloAck {
			select {
			case c.hsAck <- append([]byte{}, buf[:n]...):
			default:
			}
			continue
		}
		e := c.cur.Load()
		if e == nil {
			continue
		}
		rx[0] = bond.Rx{Buf: buf, N: n}
		e.Receive(rx, bond.Now())
		if rx[0].Keep {
			buf = bond.GetBuf()
		}
	}
}

func (c *Client) tunWrite(ds []bond.Deliver) {
	c.tunMu.Lock()
	defer c.tunMu.Unlock()
	c.wbufs = c.wbufs[:0]
	for _, d := range ds {
		c.wbufs = append(c.wbufs, d.Buf[d.Off-proto.DataOffset:d.End])
	}
	if _, err := c.dev.Write(c.wbufs, proto.DataOffset); err != nil && c.ctx.Err() == nil {
		c.logf("tun write: %v", err)
	}
}

func (c *Client) tunLoop() {
	buf := make([]byte, bond.BufSize)
	bufs, sizes := [][]byte{buf}, []int{0}
	for {
		n, err := c.dev.Read(bufs, sizes, proto.DataOffset)
		if err != nil {
			if errors.Is(err, os.ErrClosed) || c.ctx.Err() != nil {
				return
			}
			c.logf("tun read: %v", err)
			continue
		}
		if n == 0 || sizes[0] > bond.BufSize-proto.Overhead {
			continue
		}
		e := c.cur.Load()
		if e == nil {
			continue
		}
		pkt, p := e.SealData(buf, sizes[0], bond.Now())
		if p != nil {
			p.Out.Send(pkt)
		}
	}
}

func (c *Client) tickLoop() {
	t := time.NewTicker(time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			if e := c.cur.Load(); e != nil {
				e.Tick(bond.Now())
			}
		}
	}
}

// sessionLoop performs the handshake and redoes it when the relay goes silent
// (e.g. it restarted and forgot the session).
func (c *Client) sessionLoop() {
	for c.ctx.Err() == nil {
		if e := c.cur.Load(); e != nil {
			last := e.LastRx.Load()
			if last != 0 && bond.Now()-last < int64(10*time.Second) {
				c.sleep(time.Second)
				continue
			}
			c.logf("relay silent, reconnecting")
		}
		ne, err := c.handshake()
		if err != nil {
			if c.ctx.Err() == nil {
				c.logf("handshake: %v", err)
				c.sleep(time.Second)
			}
			continue
		}
		c.cur.Store(ne)
		c.statusMu.Lock()
		c.since = time.Now()
		c.statusMu.Unlock()
		c.logf("session %08x established", ne.SID)
		if c.cfg.DefaultRoute {
			c.netMu.Lock()
			if !c.routed {
				if err := routeAllTraffic(c.dev, c.dns); err != nil {
					c.logf("%v", err)
				} else {
					c.routed = true
					// IPv4 now goes through the tunnel; keep IPv6 from going around it.
					if err := firewall.BlockIPv6(); err != nil {
						c.logf("IPv6 leak protection: %v", err)
					} else {
						c.v6Blocked = true
					}
				}
			}
			c.netMu.Unlock()
		}
		// Give the new session time to receive its first pongs.
		c.sleep(5 * time.Second)
	}
}

func (c *Client) handshake() (*bond.Engine, error) {
	// A fresh ephemeral key per handshake; it is dropped when this returns.
	cr, priv := proto.NewRandom(), proto.Ephemeral()
	cpub := priv.PublicKey().Bytes()
	for attempt := 0; ; attempt++ {
		for _, s := range c.socks {
			s.Send(proto.BuildHello(c.psk, proto.Hello{
				Path: uint8(s.id), ClientRandom: cr, ClientPub: cpub, UnixNano: time.Now().UnixNano(),
			}))
		}
		deadline := time.NewTimer(time.Second)
	wait:
		for {
			select {
			case <-c.ctx.Done():
				deadline.Stop()
				return nil, c.ctx.Err()
			case b := <-c.hsAck:
				ack, err := proto.ParseHelloAck(c.psk, b)
				if err != nil || !bytes.Equal(ack.ClientRandom, cr) {
					continue
				}
				shared, err := proto.SharedSecret(priv, ack.ServerPub)
				if err != nil {
					continue
				}
				deadline.Stop()
				c2s, s2c, err := proto.DeriveKeys(c.psk, cr, ack.ServerRandom, cpub, ack.ServerPub, shared)
				clear(shared)
				if err != nil {
					return nil, err
				}
				e := bond.NewEngine(ack.SID, c2s, s2c, c.cfg.Reorder)
				e.PingAll = true
				e.TunWrite = c.tunWrite
				for _, s := range c.socks {
					e.Paths[s.id].Out = s
				}
				return e, nil
			case <-deadline.C:
				break wait
			}
		}
		if attempt%5 == 4 {
			c.logf("no answer from relay %v yet", c.server)
		}
	}
}

// Engine returns the current session engine, or nil before the first
// handshake. Path i of the engine is Config.Paths[i].
func (c *Client) Engine() *bond.Engine { return c.cur.Load() }

type PathStatus struct {
	Name    string  `json:"name"`
	LocalIP string  `json:"localIP"`
	Up      bool    `json:"up"`
	RxMbps  float64 `json:"rxMbps"`
	TxMbps  float64 `json:"txMbps"`
	RTTms   float64 `json:"rttMs"`
}

type Status struct {
	State   string       `json:"state"` // "connecting" or "connected"
	Session string       `json:"session"`
	Since   int64        `json:"since"` // unix ms of the current session
	RxMbps  float64      `json:"rxMbps"`
	TxMbps  float64      `json:"txMbps"`
	Paths   []PathStatus `json:"paths"`
	Message string       `json:"message"`
	Relay   string       `json:"relay"`
}

// Status returns a snapshot; rates are averaged since the previous call.
func (c *Client) Status() Status {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	st := Status{State: "connecting", Message: c.lastMsg, Relay: c.server.IP.String()}
	now, t := bond.Now(), time.Now()
	e := c.cur.Load()
	// Rates are measured over windows of at least ~1s and shared by all
	// callers, so several pollers (window, tray) see the same numbers.
	dt := t.Sub(c.prevAt).Seconds()
	if e != c.prevEng || len(c.prevBytes) != len(c.socks) {
		c.prevBytes = make([]struct{ tx, rx uint64 }, len(c.socks))
		c.rates = make([]struct{ tx, rx float64 }, len(c.socks))
		c.prevEng, dt = e, 0
		c.prevAt = t
	}
	measure := dt >= 0.9
	if measure {
		c.prevAt = t
	}
	for i, s := range c.socks {
		ps := PathStatus{Name: s.name, LocalIP: s.localIP()}
		if e != nil {
			p := e.Paths[s.id]
			stats := p.Stats(now)
			ps.Up = stats.Alive
			ps.RTTms = float64(stats.SRTT) / 1e6
			prev, rate := &c.prevBytes[i], &c.rates[i]
			if measure {
				rate.tx = float64(stats.TxBytes-prev.tx) * 8 / dt / 1e6
				rate.rx = float64(stats.RxBytes-prev.rx) * 8 / dt / 1e6
				prev.tx, prev.rx = stats.TxBytes, stats.RxBytes
			} else if dt == 0 {
				prev.tx, prev.rx = stats.TxBytes, stats.RxBytes
			}
			ps.TxMbps, ps.RxMbps = rate.tx, rate.rx
		}
		st.RxMbps += ps.RxMbps
		st.TxMbps += ps.TxMbps
		if ps.Up {
			st.State = "connected"
		}
		st.Paths = append(st.Paths, ps)
	}
	if e != nil {
		st.Session = fmt.Sprintf("%08x", e.SID)
		st.Since = c.since.UnixMilli()
	}
	return st
}
