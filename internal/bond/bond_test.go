package bond

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/rdbuff/bond/internal/proto"
)

func pushSeq(r *Reorder, d uint64, pid uint8, now int64) {
	b := GetBuf()
	binary.BigEndian.PutUint64(b[:], d)
	r.Push(d, pid, b, 0, 8, now)
}

func drained(r *Reorder) []uint64 {
	var out []uint64
	for _, d := range r.out {
		out = append(out, binary.BigEndian.Uint64(d.Buf[:8]))
	}
	r.out = r.out[:0]
	return out
}

func TestReorderInOrderAcrossPaths(t *testing.T) {
	r := NewReorder(int64(50 * time.Millisecond))
	pushSeq(r, 1, 0, 1)
	pushSeq(r, 3, 1, 2) // path 1 is ahead
	pushSeq(r, 4, 1, 3)
	if got := drained(r); len(got) != 1 || got[0] != 1 {
		t.Fatalf("got %v", got)
	}
	pushSeq(r, 2, 0, 4)
	if got := drained(r); len(got) != 3 || got[0] != 2 || got[2] != 4 {
		t.Fatalf("got %v", got)
	}
}

func TestReorderFastSkip(t *testing.T) {
	r := NewReorder(int64(50 * time.Millisecond))
	pushSeq(r, 1, 0, 1)
	pushSeq(r, 2, 1, 1)
	drained(r)
	// 3 lost on path 0; path 1 delivers 4, then path 0 delivers 5: both paths
	// have now passed 3, so it must be skipped without waiting.
	pushSeq(r, 4, 1, 2)
	if got := drained(r); len(got) != 0 {
		t.Fatalf("delivered early: %v", got)
	}
	pushSeq(r, 5, 0, 3)
	if got := drained(r); len(got) != 2 || got[0] != 4 || r.FastSkips != 1 {
		t.Fatalf("got %v fast=%d", got, r.FastSkips)
	}
	// Late arrival of 3 is still delivered.
	pushSeq(r, 3, 0, 4)
	if got := drained(r); len(got) != 1 || r.Late != 1 {
		t.Fatalf("late: %v", got)
	}
}

func TestReorderTimeout(t *testing.T) {
	to := int64(50 * time.Millisecond)
	r := NewReorder(to)
	pushSeq(r, 1, 0, 1)
	pushSeq(r, 3, 0, 2) // single path: 2 lost; fast skip would apply...
	// ...since path 0 passed 2 and it's the only active path.
	if got := drained(r); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	// Two active paths, path 1 silent past the gap: needs the timeout.
	pushSeq(r, 4, 1, 3)
	pushSeq(r, 6, 0, 4)
	drained(r)
	r.Tick(4 + to - 1)
	if got := drained(r); len(got) != 0 {
		t.Fatalf("timed out early: %v", got)
	}
	r.Tick(4 + to + 1)
	if got := drained(r); len(got) != 1 || got[0] != 6 || r.Timeouts != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestReplay(t *testing.T) {
	var r proto.Replay
	for _, c := range []uint64{1, 3, 2, 100000} {
		if !r.Check(c) {
			t.Fatalf("rejected %d", c)
		}
	}
	if r.Check(3) || r.Check(100000) || r.Check(1) {
		t.Fatal("accepted replay")
	}
	if !r.Check(99999) {
		t.Fatal("rejected in-window")
	}
}

type queued struct {
	peer *Engine
	rx   Rx
}

var wire []queued

func pump() {
	for len(wire) > 0 {
		q := wire[0]
		wire = wire[1:]
		q.peer.Receive([]Rx{q.rx}, Now())
	}
}

type memOut struct {
	peer *Engine
	drop func() bool
}

func (m *memOut) Send(b []byte) error {
	if m.drop != nil && m.drop() {
		return nil
	}
	buf := GetBuf()
	n := copy(buf[:], b)
	wire = append(wire, queued{m.peer, Rx{Buf: buf, N: n}})
	return nil
}

func TestEngineLoopback(t *testing.T) {
	psk := make([]byte, 32)
	cr, sr := proto.NewRandom(), proto.NewRandom()
	ck, sk := proto.Ephemeral(), proto.Ephemeral()
	cpub, spub := ck.PublicKey().Bytes(), sk.PublicKey().Bytes()
	cs, _ := proto.SharedSecret(ck, spub)
	ss, _ := proto.SharedSecret(sk, cpub)
	c2s, s2c, _ := proto.DeriveKeys(psk, cr, sr, cpub, spub, cs)
	c2s2, s2c2, _ := proto.DeriveKeys(psk, cr, sr, cpub, spub, ss)
	cli := NewEngine(7, c2s, s2c, 20*time.Millisecond)
	srv := NewEngine(7, s2c2, c2s2, 20*time.Millisecond)
	var got []uint32
	srv.TunWrite = func(ds []Deliver) {
		for _, d := range ds {
			got = append(got, binary.BigEndian.Uint32(d.Buf[d.Off:]))
		}
	}
	cli.TunWrite = func([]Deliver) {}
	n := 0
	for i := 0; i < 2; i++ {
		cli.Paths[i].Out = &memOut{peer: srv}
		srv.Paths[i].Out = &memOut{peer: cli, drop: func() bool { n++; return false }}
	}
	cli.PingAll = true
	cli.Tick(Now()) // pings -> pongs mark paths alive
	pump()
	for i := 0; i < 2; i++ {
		if !cli.Paths[i].Alive(Now()) {
			t.Fatalf("path %d not alive", i)
		}
	}
	buf := make([]byte, BufSize)
	used := map[uint8]int{}
	for i := uint32(0); i < 1000; i++ {
		binary.BigEndian.PutUint32(buf[proto.DataOffset:], i)
		pkt, p := cli.SealData(buf, 100, Now())
		used[p.ID]++
		p.Out.Send(pkt)
		if i%10 == 0 {
			pump()
		}
	}
	pump()
	if len(got) != 1000 {
		t.Fatalf("delivered %d", len(got))
	}
	for i, v := range got {
		if v != uint32(i) {
			t.Fatalf("out of order at %d: %d", i, v)
		}
	}
	if used[0] == 0 || used[1] == 0 {
		t.Fatalf("scheduler used only one path: %v", used)
	}
	t.Logf("path usage %v, server->client ctrl msgs %d", used, n)
}

// A path whose measured delay is far above the others (e.g. a congested
// mobile link with a stale, low best-case RTT) must not be used while the
// fast path can still deliver sooner: in-order delivery would make every
// packet on the fast path wait for it.
func TestSchedulerAvoidsLaggyPath(t *testing.T) {
	e := NewEngine(1, nil, nil, 100*time.Millisecond)
	now := Now()
	fast, laggy := e.Paths[0], e.Paths[1]
	for _, p := range []*Path{fast, laggy} {
		p.Out = &memOut{}
		p.lastRx.Store(now)
	}
	fast.minRTT, fast.srtt = int64(10*time.Millisecond), int64(20*time.Millisecond)
	laggy.minRTT, laggy.srtt = int64(25*time.Millisecond), int64(200*time.Millisecond)

	used := map[uint8]int{}
	for i := 0; i < 500; i++ {
		p := e.pick(1444, now)
		used[p.ID]++
		p.txBytes += 1444 // as SealData would
	}
	if used[1] != 0 {
		t.Fatalf("laggy path got %d of 500 packets while the fast path was barely queued", used[1])
	}

	// Once the fast path is genuinely more backed up than the laggy one is
	// slow, the laggy path helps out.
	fast.txBytes += 2 << 20
	if p := e.pick(1444, now); p != laggy {
		t.Fatal("laggy path not used when the fast path is heavily queued")
	}
}
