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
	fast.cwnd = 8 << 20 // an established path that has proven its capacity
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
	// slow (its measured RTT rises with its queue), the laggy path helps out.
	fast.txBytes += 2 << 20
	fast.srtt = int64(220 * time.Millisecond)
	later := now + benchMax // past any time-out from the first half
	for _, p := range []*Path{fast, laggy} {
		p.lastRx.Store(later)
		p.ackProgress = later
	}
	if p := e.pick(1444, later); p != laggy {
		t.Fatal("laggy path not used when the fast path is heavily queued")
	}
}

// A path that hasn't proven its capacity yet (a phone's weak uplink, say)
// must not be handed a large burst just because its default rate estimate
// and idle RTT make it look attractive: that burst would arrive late and
// stall the whole in-order stream.
func TestSchedulerLimitsUntestedPath(t *testing.T) {
	e := NewEngine(1, nil, nil, 100*time.Millisecond)
	now := Now()
	fast, phone := e.Paths[0], e.Paths[1]
	for _, p := range []*Path{fast, phone} {
		p.Out = &memOut{}
		p.lastRx.Store(now)
	}
	// Fast path: established, already somewhat queued.
	fast.minRTT, fast.srtt, fast.cwnd = int64(12*time.Millisecond), int64(20*time.Millisecond), 8<<20
	fast.txBytes = 400 << 10
	// Phone: only pings so far, default (optimistic) rate estimate.
	phone.minRTT, phone.srtt = int64(30*time.Millisecond), int64(60*time.Millisecond)

	var phoneBytes int
	for i := 0; i < 400; i++ {
		p := e.pick(1444, now)
		if p == phone {
			phoneBytes += 1444
		}
		p.txBytes += 1444
	}
	if phoneBytes > 40<<10 {
		t.Fatalf("untested path was handed %d KB before any of it was acknowledged", phoneBytes>>10)
	}
	if phoneBytes == 0 {
		t.Fatal("untested path never probed")
	}
	t.Logf("untested path got %d KB of 400 packets", phoneBytes>>10)
}

// Quiet periods (little to send) must not lower a path's rate estimate, but a
// busy path that delivers less must.
func TestRateEstimateIgnoresIdleSamples(t *testing.T) {
	p := &Path{rate: 30e6, cwnd: 1 << 20}
	now := Now()
	p.onFeedback(0, 0, 0, 0, 0, now) // starts the rate window
	var rx uint64
	us := int64(0)
	for i := 0; i < 20; i++ { // 20 windows of 25 ms carrying only 1 KB each
		rx += 1024
		us += 25000
		p.onFeedback(0, 0, rx, 0, us, now)
	}
	if p.rate < 29e6 {
		t.Fatalf("idle samples dragged the rate down to %.1f MB/s", p.rate/1e6)
	}
	p.txBytes = 900 << 10 // now busy: plenty in flight, still delivering 1 KB/25 ms
	for i := 0; i < 40; i++ {
		rx += 1024
		us += 25000
		p.onFeedback(0, 0, rx, 0, us, now)
	}
	if p.rate > 5e6 {
		t.Fatalf("busy but slow path kept a rate of %.1f MB/s", p.rate/1e6)
	}
}

// A path far laggier than the best gets no data at all, sits out for a while
// once it has been found laggy, and is used again after it recovers. If it is
// the only path left, it still carries traffic.
func TestSchedulerBenchesLaggyPath(t *testing.T) {
	e := NewEngine(1, nil, nil, 100*time.Millisecond)
	now := Now()
	fast, phone := e.Paths[0], e.Paths[1]
	for _, p := range []*Path{fast, phone} {
		p.Out = &memOut{}
		p.lastRx.Store(now)
	}
	fast.minRTT, fast.srtt, fast.cwnd = int64(12*time.Millisecond), int64(40*time.Millisecond), 8<<20
	fast.txBytes = 300 << 10 // moderately queued: the phone's base cost would win
	phone.minRTT, phone.srtt, phone.cwnd = int64(30*time.Millisecond), int64(400*time.Millisecond), 1<<20

	for i := 0; i < 200; i++ {
		if p := e.pick(1444, now); p == phone {
			t.Fatal("laggy phone path got data")
		}
	}
	// It recovers (pings now show 50 ms) but is still sitting out.
	phone.srtt = int64(50 * time.Millisecond)
	if p := e.pick(1444, now+int64(time.Second)); p == phone {
		t.Fatal("benched path used before its time-out")
	}
	// After the time-out it is used again.
	later := now + benchMin + int64(time.Second)
	fast.lastRx.Store(later)
	phone.lastRx.Store(later)
	fast.ackProgress, phone.ackProgress = later, later // acks kept coming
	used := false
	for i := 0; i < 400 && !used; i++ {
		p := e.pick(1444, later)
		used = p == phone
		p.txBytes += 1444
	}
	if !used {
		t.Fatal("recovered path never used again")
	}
	// Only the laggy path left: it must carry traffic.
	fast.lastRx.Store(0)
	phone.srtt = int64(400 * time.Millisecond)
	if p := e.pick(1444, later); p != phone {
		t.Fatal("sole remaining path not used")
	}
}
