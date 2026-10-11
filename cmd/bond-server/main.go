//go:build linux

// bond-server is the relay end of the bonding tunnel. It accepts a client's
// paths on one UDP port, reorders what they carry into a TUN device and
// spreads return traffic back over all of the client's paths.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/rdbuff/bond/internal/bond"
	"github.com/rdbuff/bond/internal/proto"
)

var (
	listen     = flag.String("listen", ":51820", "UDP listen address")
	keyFile    = flag.String("key", "/etc/bond/key", "file holding the base64 pre-shared key")
	tunName    = flag.String("tun", "bond0", "TUN interface name")
	tunAddr    = flag.String("addr", "10.77.0.1/24", "tunnel address of the server")
	mtu        = flag.Int("mtu", 1420, "TUN MTU")
	reorder    = flag.Duration("reorder", 100*time.Millisecond, "minimum reorder timeout (adapts upwards)")
	statsEvery = flag.Duration("stats", 30*time.Second, "stats interval (0 disables)")
	pprofAddr  = flag.String("pprof", "", "serve net/http/pprof on this address (e.g. 127.0.0.1:6060)")
)

const tunWriteOffset = 16 // >= virtio-net header length

type srvOut struct {
	conn *net.UDPConn
	addr atomic.Pointer[net.UDPAddr]
}

func (o *srvOut) Send(b []byte) error {
	a := o.addr.Load()
	if a == nil {
		return errors.New("no address")
	}
	_, err := o.conn.WriteToUDP(b, a)
	return err
}

type session struct {
	sid     uint32
	cr, sr  []byte
	spub    []byte // our ephemeral public key, to repeat the ack
	e       *bond.Engine
	outs    [bond.MaxPaths]*srvOut
	created time.Time
}

type server struct {
	psk  []byte
	conn *net.UDPConn
	pc   *ipv4.PacketConn
	dev  tun.Device

	mu       sync.Mutex
	byRandom map[string]*session
	bySID    map[uint32]*session
	active   atomic.Pointer[session]

	wmu    sync.Mutex
	wbufs  [][]byte
	wslice [][]byte
}

func main() {
	flag.Parse()
	if *pprofAddr != "" {
		go func() { log.Println(http.ListenAndServe(*pprofAddr, nil)) }()
	}
	psk := loadKey(*keyFile)

	dev, err := tun.CreateTUN(*tunName, *mtu)
	if err != nil {
		log.Fatalf("create tun: %v", err)
	}
	name, _ := dev.Name()
	run("ip", "addr", "replace", *tunAddr, "dev", name)
	run("ip", "link", "set", name, "up")
	run("ip", "link", "set", name, "txqueuelen", "1000")

	laddr, err := net.ResolveUDPAddr("udp4", *listen)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		log.Fatal(err)
	}
	conn.SetReadBuffer(32 << 20)
	conn.SetWriteBuffer(32 << 20)

	s := &server{
		psk: psk, conn: conn, pc: ipv4.NewPacketConn(conn), dev: dev,
		byRandom: map[string]*session{}, bySID: map[uint32]*session{},
	}
	for i := 0; i < 128; i++ {
		s.wbufs = append(s.wbufs, make([]byte, 65536+tunWriteOffset))
	}
	s.wslice = make([][]byte, len(s.wbufs))
	log.Printf("bond-server listening on %s, tun %s %s mtu %d (batch %d)", conn.LocalAddr(), name, *tunAddr, *mtu, dev.BatchSize())

	go s.tunLoop()
	go s.tickLoop()
	if *statsEvery > 0 {
		go s.statsLoop()
	}
	s.udpLoop()
}

func loadKey(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read key: %v", err)
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) < 32 {
		log.Fatalf("key must be base64 of at least 32 bytes")
	}
	return k
}

func run(args ...string) {
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		log.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func (s *server) udpLoop() {
	const n = 64
	msgs := make([]ipv4.Message, n)
	bufs := make([]*bond.Buf, n)
	for i := range msgs {
		bufs[i] = bond.GetBuf()
		msgs[i].Buffers = [][]byte{bufs[i][:]}
	}
	rx := make([]bond.Rx, 0, n)
	idx := make([]int, 0, n)
	var cur *session
	flushRx := func() {
		if len(rx) == 0 {
			return
		}
		cur.e.Receive(rx, bond.Now())
		for j := range rx {
			if rx[j].Keep {
				i := idx[j]
				bufs[i] = bond.GetBuf()
				msgs[i].Buffers[0] = bufs[i][:]
			}
		}
		rx, idx = rx[:0], idx[:0]
	}
	for {
		k, err := s.pc.ReadBatch(msgs, 0)
		if err != nil {
			log.Printf("read: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		for i := 0; i < k; i++ {
			b := bufs[i][:msgs[i].N]
			if len(b) < proto.HeaderLen {
				continue
			}
			addr, _ := msgs[i].Addr.(*net.UDPAddr)
			if b[0] == proto.TypeHello {
				s.handleHello(b, addr)
				continue
			}
			s.mu.Lock()
			sess := s.bySID[binary.BigEndian.Uint32(b[4:])]
			s.mu.Unlock()
			if sess == nil {
				continue
			}
			if sess != cur {
				flushRx()
				cur = sess
			}
			rx = append(rx, bond.Rx{Buf: bufs[i], N: msgs[i].N, Addr: addr})
			idx = append(idx, i)
		}
		flushRx()
	}
}

func (s *server) handleHello(b []byte, addr *net.UDPAddr) {
	h, err := proto.ParseHello(s.psk, b)
	if err != nil || addr == nil {
		return
	}
	if d := time.Since(time.Unix(0, h.UnixNano)); d > 2*time.Minute || d < -2*time.Minute {
		log.Printf("hello from %v: clock skew %v, ignored", addr, d)
		return
	}
	s.mu.Lock()
	sess := s.byRandom[string(h.ClientRandom)]
	if sess == nil {
		if sess = s.newSession(h); sess == nil {
			s.mu.Unlock()
			return
		}
		log.Printf("new session %08x from %v", sess.sid, addr)
	}
	s.mu.Unlock()
	s.conn.WriteToUDP(proto.BuildHelloAck(s.psk, proto.HelloAck{
		Path: h.Path, SID: sess.sid, ClientRandom: sess.cr, ServerRandom: sess.sr, ServerPub: sess.spub,
	}), addr)
}

// newSession is called with s.mu held. The ephemeral private key lives only
// for the duration of this call.
func (s *server) newSession(h proto.Hello) *session {
	cr := append([]byte{}, h.ClientRandom...)
	sr := proto.NewRandom()
	priv := proto.Ephemeral()
	spub := priv.PublicKey().Bytes()
	shared, err := proto.SharedSecret(priv, h.ClientPub)
	if err != nil {
		log.Printf("hello with bad public key: %v", err)
		return nil
	}
	c2s, s2c, err := proto.DeriveKeys(s.psk, cr, sr, h.ClientPub, spub, shared)
	clear(shared)
	if err != nil {
		log.Printf("derive keys: %v", err)
		return nil
	}
	var sid uint32
	for sid == 0 || s.bySID[sid] != nil {
		var r [4]byte
		rand.Read(r[:])
		sid = binary.BigEndian.Uint32(r[:])
	}
	sess := &session{sid: sid, cr: cr, sr: sr, spub: spub, created: time.Now()}
	e := bond.NewEngine(sid, s2c, c2s, *reorder)
	for i := range e.Paths {
		sess.outs[i] = &srvOut{conn: s.conn}
		e.Paths[i].Out = sess.outs[i]
	}
	e.TunWrite = s.tunWrite
	e.OnAuth = func(p *bond.Path, rx *bond.Rx) {
		a, _ := rx.Addr.(*net.UDPAddr)
		if a == nil {
			return
		}
		out := sess.outs[p.ID]
		if old := out.addr.Load(); old == nil || old.Port != a.Port || !old.IP.Equal(a.IP) {
			out.addr.Store(a)
			log.Printf("session %08x path %d at %v", sid, p.ID, a)
		}
		if s.active.Load() != sess {
			s.active.Store(sess)
			log.Printf("session %08x active", sid)
		}
	}
	sess.e = e
	s.byRandom[string(cr)] = sess
	s.bySID[sid] = sess
	return sess
}

func (s *server) tunWrite(ds []bond.Deliver) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	for len(ds) > 0 {
		k := min(len(ds), len(s.wbufs))
		for i := 0; i < k; i++ {
			pkt := ds[i].Buf[ds[i].Off:ds[i].End]
			s.wslice[i] = s.wbufs[i][:tunWriteOffset+copy(s.wbufs[i][tunWriteOffset:], pkt)]
		}
		if _, err := s.dev.Write(s.wslice[:k], tunWriteOffset); err != nil {
			log.Printf("tun write: %v", err)
		}
		ds = ds[k:]
	}
}

func (s *server) tunLoop() {
	batch := s.dev.BatchSize()
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, bond.BufSize)
	}
	sender := newUDPSender(s.conn, s.pc, batch)
	log.Printf("UDP GSO: %v", sender.gso)
	var perPath [bond.MaxPaths][][]byte
	for {
		n, err := s.dev.Read(bufs, sizes, proto.DataOffset)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				log.Fatal("tun closed")
			}
			log.Printf("tun read: %v", err)
			continue
		}
		sess := s.active.Load()
		if sess == nil {
			continue
		}
		now := bond.Now()
		for i := 0; i < n; i++ {
			if sizes[i] == 0 || sizes[i] > bond.BufSize-proto.Overhead {
				continue
			}
			pkt, p := sess.e.SealData(bufs[i], sizes[i], now)
			if p == nil {
				continue
			}
			perPath[p.ID] = append(perPath[p.ID], pkt)
		}
		for id, pkts := range perPath {
			if addr := sess.outs[id].addr.Load(); addr != nil {
				sender.Send(pkts, addr)
			}
			clear(pkts)
			perPath[id] = pkts[:0]
		}
	}
}

func (s *server) tickLoop() {
	t := time.NewTicker(time.Millisecond)
	var list []*session
	for range t.C {
		now := bond.Now()
		s.mu.Lock()
		list = list[:0]
		for sid, sess := range s.bySID {
			last := sess.e.LastRx.Load()
			if time.Since(sess.created) > time.Minute && (last == 0 || now-last > int64(time.Minute)) {
				delete(s.bySID, sid)
				delete(s.byRandom, string(sess.cr))
				s.active.CompareAndSwap(sess, nil)
				log.Printf("session %08x expired", sid)
				continue
			}
			list = append(list, sess)
		}
		s.mu.Unlock()
		for _, sess := range list {
			sess.e.Tick(now)
		}
	}
}

func (s *server) statsLoop() {
	var mon bond.Monitor
	for range time.Tick(*statsEvery) {
		sess := s.active.Load()
		if sess == nil {
			continue
		}
		if mon.E != sess.e {
			mon = bond.Monitor{E: sess.e}
		}
		if r := mon.Report(); r != "" {
			log.Printf("session %08x %s", sess.sid, r)
		}
	}
}
