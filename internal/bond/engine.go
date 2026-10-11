// Package bond implements the multipath engine shared by client and server:
// per-path scheduling, feedback, liveness and in-order delivery.
package bond

import (
	"crypto/cipher"
	"encoding/binary"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rdbuff/bond/internal/proto"
)

const (
	MaxPaths = 8
	BufSize  = 2048

	ringSize = 1 << 16
	ringMask = ringSize - 1

	feedbackEvery    = 32 // packets
	feedbackInterval = int64(4 * time.Millisecond)
	pingInterval     = int64(500 * time.Millisecond)
	pathDeadAfter    = int64(3 * time.Second)
	rateWindow       = int64(20 * time.Millisecond)

	// Each path may only have cwnd bytes in flight. It starts small and
	// grows by what the path delivers (like TCP slow start), so a path of
	// unknown capacity, e.g. a phone's weak uplink, can't swallow a burst
	// that then arrives seconds late and stalls the in-order stream.
	initCwnd = 16 << 10
	maxCwnd  = 64 << 20

	// Paths more than 2x the best path's RTT plus lagSlack get no data, for
	// benchMin doubling up to benchMax each time they are found laggy.
	lagSlack = int64(30 * time.Millisecond)
	benchMin = int64(5 * time.Second)
	benchMax = int64(60 * time.Second)
)

type Buf [BufSize]byte

var bufPool = sync.Pool{New: func() any { return new(Buf) }}

func GetBuf() *Buf  { return bufPool.Get().(*Buf) }
func PutBuf(b *Buf) { bufPool.Put(b) }

var epoch = time.Now()

// Now is a monotonic clock in nanoseconds.
func Now() int64 { return int64(time.Since(epoch)) }

// PathOut sends a datagram on a path.
type PathOut interface {
	Send(b []byte) error
}

type txRec struct {
	t   int64
	cum uint64
}

type Path struct {
	ID  uint8
	Out PathOut

	lastRx atomic.Int64

	// Sender side, guarded by mu.
	mu          sync.Mutex
	txSeq       uint32
	txBytes     uint64
	ring        [ringSize]txRec
	ackValid    bool
	ackSeq      uint32
	ackCum      uint64
	ackProgress int64
	srtt        int64
	minRTT      int64
	minRTTAt    int64
	rate        float64 // delivered bytes/s
	rateValid   bool
	rateBytes   uint64
	rateAtUs    int64
	fbHigh      uint32
	fbRxPkts    uint32
	cwnd        uint64 // bytes allowed in flight
	benchUntil  int64  // no data before this (too laggy, see pick)
	benchFor    int64
	goodSince   int64

	// Receiver side, guarded by Engine.rxMu.
	rxValid   bool
	rxHigh    uint32
	rxHighAt  int64
	rxPkts    uint32
	rxBytes   uint64
	rxSinceFb int
	lastFb    int64
	lastPing  int64

	StatTx, StatRx atomic.Uint64
	StatOOO        atomic.Uint64 // data packets that arrived behind a later one on the same path
}

func (p *Path) Alive(now int64) bool {
	t := p.lastRx.Load()
	return p.Out != nil && t != 0 && now-t < pathDeadAfter
}

// cost estimates when a packet of the given size, sent now, would arrive:
// the path's one-way delay including its queue. Two estimates are combined:
// one from bytes in flight (reacts instantly to what we just sent) and the
// measured smoothed RTT (catches paths, like mobile links, whose real delay
// is far above their best-case RTT). Since packets are delivered in order,
// a path that is much slower than the others holds back everything sent
// after it, so it must only be used once the faster paths are equally
// backed up.
func (p *Path) cost(size int, now int64, bestSRTT int64) float64 {
	inflight := p.txBytes - p.ackCum
	if inflight > 0 {
		lim := 4 * p.srtt
		if lim < int64(250*time.Millisecond) {
			lim = int64(250 * time.Millisecond)
		}
		if now-p.ackProgress > lim {
			// Tail loss or a stalled path: forget what is in flight.
			p.ackCum = p.txBytes
			inflight = 0
		}
	}
	rate := p.rate
	if rate < 1e6 {
		rate = 1e6
	}
	q := float64(inflight)/rate*1e9 - float64(p.minRTT)
	if q < 0 {
		q = 0
	}
	owd := q + float64(p.minRTT)/2
	if measured := float64(p.srtt) / 2; measured > owd {
		owd = measured
	}
	// Bytes beyond what the path has proven it can carry (cwnd per RTT) are
	// expected to drain at that proven rate, so they add delay. This keeps an
	// untested or weak path from being handed a large burst.
	if over := inflight + uint64(size); over > p.cwnd {
		rtt := float64(max(p.srtt, p.minRTT, int64(time.Millisecond)))
		penalty := float64(over-p.cwnd) * rtt / float64(p.cwnd)
		// A path already much laggier than the best one gets a
		// proportionally smaller first burst: on a weak mobile uplink even
		// a few dozen KB arrive hundreds of ms late.
		if bestSRTT > 0 && p.srtt > bestSRTT {
			penalty *= float64(p.srtt) / float64(bestSRTT)
		}
		owd += penalty
	}
	return owd + float64(size)/rate*1e9
}

func (p *Path) rttSample(rtt, now int64) {
	if rtt <= 0 {
		return
	}
	if p.srtt == 0 {
		p.srtt = rtt
	} else {
		p.srtt += (rtt - p.srtt) / 8
	}
	if p.minRTT == 0 || rtt < p.minRTT || now-p.minRTTAt > int64(10*time.Second) {
		p.minRTT, p.minRTTAt = rtt, now
	}
}

func (p *Path) onFeedback(high, rxPkts uint32, rxBytes uint64, delayUs uint32, remoteUs int64, now int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.txSeq-high <= ringSize && (!p.ackValid || int32(high-p.ackSeq) > 0) {
		rec := p.ring[high&ringMask]
		p.rttSample(now-rec.t-int64(delayUs)*1000, now)
		if rec.cum > p.ackCum {
			p.cwnd = min(p.cwnd+(rec.cum-p.ackCum), maxCwnd)
		}
		p.ackValid, p.ackSeq, p.ackCum, p.ackProgress = true, high, rec.cum, now
		if p.ackCum > p.txBytes { // stale record after a reset
			p.ackCum = p.txBytes
		}
		p.fbHigh, p.fbRxPkts = high, rxPkts
	}
	if !p.rateValid {
		p.rateValid, p.rateBytes, p.rateAtUs = true, rxBytes, remoteUs
		return
	}
	dt := remoteUs - p.rateAtUs
	switch {
	case dt*1000 > 5*rateWindow, dt < 0:
		// Idle gap or clock confusion: restart the window without sampling.
		p.rateBytes, p.rateAtUs = rxBytes, remoteUs
	case dt*1000 >= rateWindow:
		sample := float64(rxBytes-p.rateBytes) / float64(dt) * 1e6
		switch {
		case sample > p.rate:
			p.rate += (sample - p.rate) / 2
		case p.txBytes-p.ackCum >= p.cwnd/4:
			// Only a busy path that still delivered less is slower. While a
			// path has little to send its samples just measure our own
			// demand; letting those drag the estimate down made a fast path
			// look congested at the start of the next transfer, which then
			// went to a slow path instead.
			p.rate += (sample - p.rate) / 8
		}
		p.rateBytes, p.rateAtUs = rxBytes, remoteUs
	}
}

// PathStats is a snapshot for display.
type PathStats struct {
	Alive            bool
	SRTT, MinRTT     time.Duration
	RateBps          float64
	Inflight         uint64
	SentUpTo, RxPkts uint32
	TxBytes, RxBytes uint64
	OOO              uint64
}

func (p *Path) Stats(now int64) PathStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PathStats{
		Alive: p.Alive(now), SRTT: time.Duration(p.srtt), MinRTT: time.Duration(p.minRTT),
		RateBps: p.rate * 8, Inflight: p.txBytes - p.ackCum,
		SentUpTo: p.fbHigh + 1, RxPkts: p.fbRxPkts,
		TxBytes: p.StatTx.Load(), RxBytes: p.StatRx.Load(), OOO: p.StatOOO.Load(),
	}
}

type Engine struct {
	SID   uint32
	tx    cipher.AEAD
	rx    cipher.AEAD
	ctr   atomic.Uint64
	Paths [MaxPaths]*Path

	dseq uint64 // owned by the single goroutine calling SealData

	rxMu    sync.Mutex
	replay  proto.Replay
	RO      *Reorder
	ctrlBuf [256]byte

	// TunWrite is called with in-order packets while the receive lock is held.
	TunWrite func([]Deliver)
	// OnAuth is called for every authenticated, non-replayed datagram.
	OnAuth func(p *Path, rx *Rx)

	LastRx atomic.Int64

	// PingAll keeps pinging paths that have never received anything; the
	// client sets it so every path opens its NAT binding.
	PingAll bool
}

func NewEngine(sid uint32, tx, rx cipher.AEAD, reorderTimeout time.Duration) *Engine {
	e := &Engine{SID: sid, tx: tx, rx: rx, RO: NewReorder(int64(reorderTimeout))}
	for i := range e.Paths {
		e.Paths[i] = &Path{ID: uint8(i), rate: 10e6, cwnd: initCwnd}
	}
	return e
}

func (e *Engine) pick(size int, now int64) *Path {
	var bestSRTT int64
	for _, p := range e.Paths {
		if p.Alive(now) {
			p.mu.Lock()
			if p.srtt > 0 && (bestSRTT == 0 || p.srtt < bestSRTT) {
				bestSRTT = p.srtt
			}
			p.mu.Unlock()
		}
	}
	// "Do no harm": since packets are delivered in order, a path much laggier
	// than the best one stalls everything behind each packet it carries.
	// Such a path gets no data (pings keep measuring it), and each time it
	// turns out laggy again it sits out longer.
	gate := 2*bestSRTT + lagSlack
	var best, fallback *Path
	bestCost, fallbackCost := math.Inf(1), math.Inf(1)
	for _, p := range e.Paths {
		if !p.Alive(now) {
			continue
		}
		p.mu.Lock()
		c := p.cost(size, now, bestSRTT)
		usable := true
		switch {
		case bestSRTT > 0 && p.srtt > gate:
			if now >= p.benchUntil {
				p.benchFor = min(max(2*p.benchFor, benchMin), benchMax)
				p.benchUntil = now + p.benchFor
			}
			p.goodSince = 0
			usable = false
		case now < p.benchUntil:
			usable = false
		default:
			if p.goodSince == 0 {
				p.goodSince = now
			} else if now-p.goodSince > benchMax {
				p.benchFor = 0 // well behaved for a while: forgive
			}
		}
		p.mu.Unlock()
		if usable && c < bestCost {
			best, bestCost = p, c
		}
		if c < fallbackCost {
			fallback, fallbackCost = p, c
		}
	}
	if best == nil {
		return fallback // never black-hole traffic
	}
	return best
}

// SealData schedules and encrypts the IP packet at b[DataOffset:DataOffset+n].
// b needs TagLen bytes of spare room after the packet. It returns the datagram
// and the path to send it on, or a nil path when no path is alive. Must be
// called from a single goroutine.
func (e *Engine) SealData(b []byte, n int, now int64) ([]byte, *Path) {
	size := proto.Overhead + n
	p := e.pick(size, now)
	if p == nil {
		return nil, nil
	}
	p.mu.Lock()
	ps := p.txSeq
	p.txSeq++
	if p.txBytes == p.ackCum {
		p.ackProgress = now
	}
	p.txBytes += uint64(size)
	p.ring[ps&ringMask] = txRec{t: now, cum: p.txBytes}
	p.mu.Unlock()

	e.dseq++
	proto.PutHeader(b, proto.TypeData, p.ID, e.SID, e.ctr.Add(1))
	binary.BigEndian.PutUint64(b[proto.HeaderLen:], e.dseq)
	binary.BigEndian.PutUint32(b[proto.HeaderLen+8:], ps)
	out := proto.Seal(e.tx, b, proto.DataHdrLen+n)
	p.StatTx.Add(uint64(len(out)))
	return out, p
}

// Rx is one received datagram: Buf[:N]. After Receive, Keep reports whether
// the engine took ownership of Buf.
type Rx struct {
	Buf  *Buf
	N    int
	Addr any
	Keep bool

	typ, pid uint8
	ctr      uint64
	body     []byte
}

// Receive authenticates and processes a batch of datagrams.
func (e *Engine) Receive(batch []Rx, now int64) {
	for i := range batch {
		r := &batch[i]
		r.typ, r.Keep = 0, false
		b := r.Buf[:r.N]
		if len(b) < proto.HeaderLen+proto.TagLen {
			continue
		}
		typ, pid, sid, ctr := proto.ParseHeader(b)
		if sid != e.SID || pid >= MaxPaths || typ < proto.TypeData {
			continue
		}
		body, err := proto.Open(e.rx, b)
		if err != nil {
			continue
		}
		r.typ, r.pid, r.ctr, r.body = typ, pid, ctr, body
	}

	e.rxMu.Lock()
	defer e.rxMu.Unlock()
	for i := range batch {
		r := &batch[i]
		if r.typ == 0 || !e.replay.Check(r.ctr) {
			continue
		}
		p := e.Paths[r.pid]
		p.lastRx.Store(now)
		e.LastRx.Store(now)
		p.StatRx.Add(uint64(r.N))
		if e.OnAuth != nil {
			e.OnAuth(p, r)
		}
		body := r.body
		switch r.typ {
		case proto.TypeData:
			if len(body) < proto.DataHdrLen {
				continue
			}
			dseq := binary.BigEndian.Uint64(body)
			ps := binary.BigEndian.Uint32(body[8:])
			if !p.rxValid || int32(ps-p.rxHigh) > 0 {
				p.rxValid, p.rxHigh, p.rxHighAt = true, ps, now
			} else {
				p.StatOOO.Add(1)
			}
			p.rxPkts++
			p.rxBytes += uint64(r.N)
			p.rxSinceFb++
			if p.rxSinceFb >= feedbackEvery {
				e.sendFeedback(p, now)
			}
			r.Keep = true
			e.RO.Push(dseq, r.pid, r.Buf, proto.DataOffset, proto.HeaderLen+len(body), now)
		case proto.TypeFeedback:
			if len(body) < proto.FeedbackLen {
				continue
			}
			p.onFeedback(binary.BigEndian.Uint32(body), binary.BigEndian.Uint32(body[4:]),
				binary.BigEndian.Uint64(body[8:]), binary.BigEndian.Uint32(body[16:]),
				int64(binary.BigEndian.Uint64(body[20:])), now)
		case proto.TypePing:
			if len(body) >= 8 {
				e.sendCtrl(p, proto.TypePong, body[:8])
			}
		case proto.TypePong:
			if len(body) >= 8 {
				p.mu.Lock()
				p.rttSample(now-int64(binary.BigEndian.Uint64(body)), now)
				p.mu.Unlock()
			}
		}
	}
	e.flush()
}

func (e *Engine) flush() {
	if len(e.RO.out) == 0 {
		return
	}
	e.TunWrite(e.RO.out)
	for i := range e.RO.out {
		PutBuf(e.RO.out[i].Buf)
		e.RO.out[i] = Deliver{}
	}
	e.RO.out = e.RO.out[:0]
}

// sendCtrl seals and sends a small control message. Caller holds rxMu.
func (e *Engine) sendCtrl(p *Path, typ uint8, body []byte) {
	if p.Out == nil {
		return
	}
	b := e.ctrlBuf[:]
	proto.PutHeader(b, typ, p.ID, e.SID, e.ctr.Add(1))
	copy(b[proto.HeaderLen:], body)
	p.Out.Send(proto.Seal(e.tx, b, len(body)))
}

func (e *Engine) sendFeedback(p *Path, now int64) {
	var body [proto.FeedbackLen]byte
	binary.BigEndian.PutUint32(body[0:], p.rxHigh)
	binary.BigEndian.PutUint32(body[4:], p.rxPkts)
	binary.BigEndian.PutUint64(body[8:], p.rxBytes)
	binary.BigEndian.PutUint32(body[16:], uint32((now-p.rxHighAt)/1000))
	binary.BigEndian.PutUint64(body[20:], uint64(now/1000))
	e.sendCtrl(p, proto.TypeFeedback, body[:])
	p.rxSinceFb, p.lastFb = 0, now
}

// Ping sends a ping on one path; usable before the path is known to be alive.
func (e *Engine) Ping(p *Path, now int64) {
	var body [8]byte
	binary.BigEndian.PutUint64(body[:], uint64(now))
	e.rxMu.Lock()
	e.sendCtrl(p, proto.TypePing, body[:])
	p.lastPing = now
	e.rxMu.Unlock()
}

// Tick runs timers: reorder timeouts, pending feedback and keepalives. Call it
// every millisecond or two.
func (e *Engine) Tick(now int64) {
	e.rxMu.Lock()
	defer e.rxMu.Unlock()
	e.RO.Tick(now)
	e.flush()
	for _, p := range e.Paths {
		if p.Out == nil {
			continue
		}
		if p.rxSinceFb > 0 && now-p.lastFb >= feedbackInterval {
			e.sendFeedback(p, now)
		}
		if (p.lastPing == 0 || now-p.lastPing >= pingInterval) && (e.PingAll || p.lastRx.Load() != 0) {
			var body [8]byte
			binary.BigEndian.PutUint64(body[:], uint64(now))
			e.sendCtrl(p, proto.TypePing, body[:])
			p.lastPing = now
		}
	}
}
