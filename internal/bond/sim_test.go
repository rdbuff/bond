package bond

import (
	"math/rand"
	"sort"
	"testing"
	"time"
)

// simLink is a bottleneck with a FIFO queue, a base one-way delay and, for
// Wi-Fi, short airtime stalls during which nothing drains.
type simLink struct {
	rate     float64 // bytes/s
	owd      int64
	buf      int64 // max queueing delay before drops
	stallP   float64
	stallMin int64
	stallMax int64
	rxJitter int64 // the receiver timestamps feedback up to this late
	rxBatch  int64 // the receiver only wakes up every 0..rxBatch to read
	rxWake   int64
	rng      *rand.Rand

	busyUntil  int64
	stallUntil int64
	nextStall  int64

	arrivals []simPkt // in flight to the receiver, FIFO
	fbs      []simFb  // feedback in flight back to the sender, FIFO
	pongs    []simFb

	// receiver state
	rxHigh    uint32
	rxHighAt  int64
	rxPkts    uint32
	rxBytes   uint64
	rxSinceFb int
	lastFb    int64

	delivered uint64
	drops     int
}

type simPkt struct {
	at   int64
	seq  uint32
	size int
	ping int64 // ping send time, or 0 for data
	dseq uint64
}

type simFb struct {
	at                 int64
	high, pkts         uint32
	bytes              uint64
	delayUs            uint32
	remoteUs, pingSent int64
}

func (l *simLink) send(pk simPkt, now int64, rng *rand.Rand) {
	if l.stallP > 0 && now >= l.nextStall {
		l.nextStall = now + int64(10*time.Millisecond)
		if rng.Float64() < l.stallP {
			start := max(now, l.busyUntil)
			l.stallUntil = start + l.stallMin + rng.Int63n(l.stallMax-l.stallMin+1)
		}
	}
	start := max(now, l.busyUntil, l.stallUntil)
	if start-now > l.buf {
		l.drops++
		return
	}
	l.busyUntil = start + int64(float64(pk.size)/l.rate*1e9)
	pk.at = l.busyUntil + l.owd
	l.arrivals = append(l.arrivals, pk)
}

func (l *simLink) jitter() int64 {
	if l.rxJitter == 0 {
		return 0
	}
	return l.rng.Int63n(l.rxJitter)
}

func (l *simLink) feedback(now int64) {
	l.fbs = append(l.fbs, simFb{at: now + l.owd, high: l.rxHigh, pkts: l.rxPkts, bytes: l.rxBytes,
		delayUs: uint32((now - l.rxHighAt) / 1000), remoteUs: (now + l.jitter()) / 1000})
	l.rxSinceFb, l.lastFb = 0, now
}

type simResult struct {
	mbps     []float64
	rateMbps []float64 // the scheduler's final rate estimates
	total    float64
	stallP99 time.Duration // extra in-order delay at the 99th percentile
}

// simulate offers a constant load to the scheduler over links and reports
// what each one delivered in the second half of the run.
func simulate(links []*simLink, offeredMbps float64, dur time.Duration, seed int64) simResult {
	rng := rand.New(rand.NewSource(seed))
	e := NewEngine(1, nil, nil, 100*time.Millisecond)
	for i := range links {
		e.Paths[i].Out = &memOut{}
		links[i].rng = rng
		e.Paths[i].lastRx.Store(1)
	}
	const size = 1444
	const step = int64(10 * time.Microsecond)
	end := int64(dur)
	half := end / 2
	pps := offeredMbps * 1e6 / 8 / size
	var credit float64
	var dseq uint64
	var lastPing int64 = -1 << 62
	var nextDeliver uint64 // in-order delivery tracking
	arrivedAt := map[uint64]int64{}
	var extra []int64
	inOrderUpTo := int64(0)
	startDelivered := make([]uint64, len(links))

	for now := int64(1); now < end; now += step {
		if now >= half && startDelivered != nil && now-step < half {
			for i, l := range links {
				startDelivered[i] = l.delivered
			}
		}
		// Receiver side.
		for i, l := range links {
			p := e.Paths[i]
			if l.rxBatch > 0 {
				if now < l.rxWake {
					goto sender
				}
				l.rxWake = now + rng.Int63n(l.rxBatch)
			}
			for len(l.arrivals) > 0 && l.arrivals[0].at <= now {
				pk := l.arrivals[0]
				l.arrivals = l.arrivals[1:]
				if pk.ping != 0 {
					l.pongs = append(l.pongs, simFb{at: now + l.owd, pingSent: pk.ping})
					continue
				}
				if int32(pk.seq-l.rxHigh) > 0 || l.rxPkts == 0 {
					l.rxHigh, l.rxHighAt = pk.seq, now
				}
				l.rxPkts++
				l.rxBytes += uint64(pk.size)
				l.delivered += uint64(pk.size)
				l.rxSinceFb++
				if l.rxSinceFb >= feedbackEvery {
					l.feedback(now)
				}
				if now >= half {
					arrivedAt[pk.dseq] = now
				}
			}
			if l.rxSinceFb > 0 && now-l.lastFb >= feedbackInterval {
				l.feedback(now)
			}
		sender:
			// Sender side: feedback and pongs.
			for len(l.fbs) > 0 && l.fbs[0].at <= now {
				f := l.fbs[0]
				l.fbs = l.fbs[1:]
				p.lastRx.Store(now)
				p.onFeedback(f.high, f.pkts, f.bytes, f.delayUs, f.remoteUs, now)
			}
			for len(l.pongs) > 0 && l.pongs[0].at <= now {
				f := l.pongs[0]
				l.pongs = l.pongs[1:]
				p.lastRx.Store(now)
				p.mu.Lock()
				p.rttSample(now-f.pingSent, now)
				p.mu.Unlock()
			}
		}
		// In-order delivery: how long each packet waits for earlier ones.
		for {
			at, ok := arrivedAt[nextDeliver]
			if !ok {
				break
			}
			delete(arrivedAt, nextDeliver)
			if at > inOrderUpTo {
				inOrderUpTo = at
			}
			extra = append(extra, inOrderUpTo-at)
			nextDeliver++
		}
		if now-lastPing >= pingInterval {
			lastPing = now
			for _, l := range links {
				l.send(simPkt{size: 64, ping: now}, now, rng)
			}
		}
		// Offered load.
		credit += pps * float64(step) / 1e9
		for ; credit >= 1; credit-- {
			p := e.pick(size, now)
			p.mu.Lock()
			ps := p.txSeq
			p.txSeq++
			if p.txBytes == p.ackCum {
				p.ackProgress = now
			}
			p.txBytes += size
			p.ring[ps&ringMask] = txRec{t: now, cum: p.txBytes}
			p.mu.Unlock()
			if dseq == 0 && now < half {
				nextDeliver = 0
			}
			pk := simPkt{seq: ps, size: size, dseq: dseq}
			dseq++
			if now < half {
				nextDeliver = dseq
			}
			links[p.ID].send(pk, now, rng)
		}
	}
	var r simResult
	secs := float64(end-half) / 1e9
	for i, l := range links {
		m := float64(l.delivered-startDelivered[i]) * 8 / secs / 1e6
		r.rateMbps = append(r.rateMbps, e.Paths[i].rate*8/1e6)
		r.mbps = append(r.mbps, m)
		r.total += m
	}
	if len(extra) > 0 {
		sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
		r.stallP99 = time.Duration(extra[len(extra)*99/100])
	}
	return r
}

func ethernet() *simLink {
	return &simLink{rate: 290e6 / 8, owd: int64(9 * time.Millisecond), buf: int64(40 * time.Millisecond)}
}

func wifi() *simLink {
	// Airtime contention: now and then the link stalls for 20-80 ms.
	return &simLink{rate: 340e6 / 8, owd: int64(10 * time.Millisecond), buf: int64(150 * time.Millisecond),
		stallP: 0.03, stallMin: int64(20 * time.Millisecond), stallMax: int64(80 * time.Millisecond)}
}

// Two healthy paths (Ethernet and a jittery Wi-Fi) must add up: Wi-Fi's
// occasional airtime stalls must not get it benched as if it were a laggy
// phone.
func TestSimEthernetPlusWifi(t *testing.T) {
	for seed := int64(1); seed <= 3; seed++ {
		r := simulate([]*simLink{ethernet(), wifi()}, 600, 20*time.Second, seed)
		t.Logf("seed %d: eth %.0f + wifi %.0f = %.0f Mbit/s, in-order wait p99 %v", seed, r.mbps[0], r.mbps[1], r.total, r.stallP99)
		if r.total < 530 {
			t.Errorf("seed %d: bonded only %.0f Mbit/s of 630", seed, r.total)
		}
	}
}

func phone() *simLink {
	// A weak, erratic mobile uplink: a few Mbit/s, with stalls of up to most
	// of a second.
	return &simLink{rate: 5e6 / 8, owd: int64(20 * time.Millisecond), buf: int64(time.Second),
		stallP: 0.05, stallMin: int64(100 * time.Millisecond), stallMax: int64(700 * time.Millisecond)}
}

// Adding such a phone to Ethernet and Wi-Fi must not cost much: it would
// stall the in-order stream if it carried more than a trickle.
func TestSimPhoneDoesNoHarm(t *testing.T) {
	for seed := int64(1); seed <= 3; seed++ {
		two := simulate([]*simLink{ethernet(), wifi()}, 550, 20*time.Second, seed)
		three := simulate([]*simLink{ethernet(), wifi(), phone()}, 550, 20*time.Second, seed)
		t.Logf("seed %d: eth+wifi %.0f, +phone %.0f (phone %.1f), in-order wait p99 %v -> %v",
			seed, two.total, three.total, three.mbps[2], two.stallP99, three.stallP99)
		if three.stallP99 > two.stallP99+50*time.Millisecond {
			t.Errorf("seed %d: phone raised the in-order wait from %v to %v", seed, two.stallP99, three.stallP99)
		}
	}
}

// Feedback timing jitter makes some rate samples overshoot. The estimate must
// still settle near what the link really carries: one stuck at a burst's
// peak (745 Mbit/s on a 290 Mbit/s line, seen on a real relay) overloads the
// path into loss.
func TestSimRateEstimateTracksLink(t *testing.T) {
	for seed := int64(1); seed <= 3; seed++ {
		eth, wf := ethernet(), wifi()
		eth.rxBatch, wf.rxBatch = int64(16*time.Millisecond), int64(16*time.Millisecond)
		r := simulate([]*simLink{eth, wf}, 600, 20*time.Second, seed)
		t.Logf("seed %d: eth %.0f (est %.0f) + wifi %.0f (est %.0f) = %.0f Mbit/s, drops %d/%d",
			seed, r.mbps[0], r.rateMbps[0], r.mbps[1], r.rateMbps[1], r.total, eth.drops, wf.drops)
		for i, l := range []*simLink{eth, wf} {
			if real := l.rate * 8 / 1e6; r.rateMbps[i] > 1.3*real {
				t.Errorf("seed %d path %d: rate estimate %.0f Mbit/s for a %.0f Mbit/s link", seed, i, r.rateMbps[i], real)
			}
		}
	}
}

// A rare long Wi-Fi stall (a background scan, say) must cost only the stall
// itself. Once Wi-Fi stops getting data, only pings update its RTT; if those
// recover too slowly it looks laggy long after it is fine and gets benched,
// leaving Ethernet alone for many seconds.
func TestSimWifiRecoversAfterLongStall(t *testing.T) {
	for seed := int64(1); seed <= 3; seed++ {
		wf := wifi()
		wf.stallP, wf.stallMin, wf.stallMax = 0.003, int64(250*time.Millisecond), int64(500*time.Millisecond)
		r := simulate([]*simLink{ethernet(), wf}, 600, 30*time.Second, seed)
		t.Logf("seed %d: eth %.0f + wifi %.0f = %.0f Mbit/s", seed, r.mbps[0], r.mbps[1], r.total)
		if r.mbps[1] < 220 {
			t.Errorf("seed %d: Wi-Fi carried only %.0f Mbit/s around a few stalls", seed, r.mbps[1])
		}
	}
}
