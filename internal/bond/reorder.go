package bond

import "time"

// Reorder restores the global sequence order of packets that arrive over
// several paths. Each path is FIFO, so a missing sequence number is declared
// lost as soon as every active path has delivered a later one; otherwise it is
// skipped after a timeout. The timeout adapts: a skipped packet that shows up
// later proves the timeout was too short for the current delay spread between
// paths. Not safe for concurrent use.
type Reorder struct {
	timeout, minTimeout, maxTimeout int64
	lastDecay                       int64
	lateSinceDecay                  bool

	next    uint64
	started bool
	count   int
	slots   [roSize]slot

	pathMax  [MaxPaths]uint64
	pathSeen [MaxPaths]int64

	out []Deliver

	Late, Skipped, FastSkips, Timeouts uint64
}

const (
	roSize = 1 << 15
	roMask = roSize - 1

	// A path silent for longer than this no longer holds back fast skips.
	pathActiveWindow = int64(time.Second)
	maxReorderWait   = int64(500 * time.Millisecond)
)

type slot struct {
	buf      *Buf
	off, end int
	t        int64 // arrival, or when it was skipped (ok == false)
	waited   int64 // timeout in force when it was skipped
	ok       bool
}

// Deliver is an in-order inner packet: buf[off:end].
type Deliver struct {
	Buf      *Buf
	Off, End int
}

func NewReorder(timeoutNs int64) *Reorder {
	return &Reorder{timeout: timeoutNs, minTimeout: timeoutNs, maxTimeout: max(timeoutNs, maxReorderWait)}
}

// Timeout returns the current adaptive reorder timeout.
func (r *Reorder) Timeout() time.Duration { return time.Duration(r.timeout) }

func (r *Reorder) Push(d uint64, pid uint8, buf *Buf, off, end int, now int64) {
	if d > r.pathMax[pid] {
		r.pathMax[pid] = d
	}
	r.pathSeen[pid] = now
	if !r.started {
		r.started, r.next = true, d
	}
	if d < r.next {
		// Skipped as lost but only late; late is still better than never.
		r.Late++
		if r.next-d < roSize {
			if s := &r.slots[d&roMask]; !s.ok && s.t != 0 {
				r.adapt(s.waited, now-s.t)
				s.t = 0
			}
		}
		r.out = append(r.out, Deliver{buf, off, end})
		return
	}
	if d-r.next >= roSize {
		r.flushAll(now)
		r.next = d
	}
	s := &r.slots[d&roMask]
	if s.ok {
		PutBuf(buf)
		return
	}
	*s = slot{buf: buf, off: off, end: end, t: now, ok: true}
	r.count++
	r.drain()
	r.fastSkip(now)
}

// adapt grows the timeout after a packet arrived `lateBy` after being skipped
// under a timeout of `waited`.
func (r *Reorder) adapt(waited, lateBy int64) {
	if want := (waited + lateBy) * 6 / 5; want > r.timeout {
		r.timeout = min(want, r.maxTimeout)
	}
	r.lateSinceDecay = true
}

func (r *Reorder) drain() {
	for r.count > 0 {
		s := &r.slots[r.next&roMask]
		if !s.ok {
			return
		}
		r.out = append(r.out, Deliver{s.buf, s.off, s.end})
		*s = slot{}
		r.count--
		r.next++
	}
}

// skip gives up on the missing head packet.
func (r *Reorder) skip(now int64) {
	r.slots[r.next&roMask] = slot{t: now, waited: r.timeout}
	r.Skipped++
	r.next++
}

func (r *Reorder) flushAll(now int64) {
	for r.count > 0 {
		if !r.slots[r.next&roMask].ok {
			r.skip(now)
			continue
		}
		r.drain()
	}
}

// fastSkip declares the head gap lost when every active path has moved past it.
func (r *Reorder) fastSkip(now int64) {
	for r.count > 0 {
		active := false
		for pid := range r.pathSeen {
			if r.pathSeen[pid] == 0 || now-r.pathSeen[pid] > pathActiveWindow {
				continue
			}
			active = true
			if r.pathMax[pid] <= r.next {
				return
			}
		}
		if !active {
			return
		}
		r.FastSkips++
		r.skip(now)
		r.drain()
	}
}

// Tick skips head gaps that have blocked delivery for longer than the timeout
// and slowly decays the timeout while nothing arrives late.
func (r *Reorder) Tick(now int64) {
	if now-r.lastDecay >= int64(time.Second) {
		if !r.lateSinceDecay {
			r.timeout = max(r.minTimeout, r.timeout-r.timeout/16)
		}
		r.lastDecay, r.lateSinceDecay = now, false
	}
	for r.count > 0 {
		i := r.next
		for !r.slots[i&roMask].ok {
			i++
		}
		if now-r.slots[i&roMask].t < r.timeout {
			return
		}
		r.Timeouts++
		for r.next != i {
			r.skip(now)
		}
		r.drain()
	}
}
