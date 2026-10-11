package bond

import (
	"fmt"
	"strings"
	"time"
)

// ReorderStats returns cumulative reorder counters.
func (e *Engine) ReorderStats() (late, skipped, fast, timeouts uint64, timeout time.Duration) {
	e.rxMu.Lock()
	defer e.rxMu.Unlock()
	return e.RO.Late, e.RO.Skipped, e.RO.FastSkips, e.RO.Timeouts, e.RO.Timeout()
}

// Monitor formats periodic per-path throughput and health lines.
type Monitor struct {
	E     *Engine
	Names [MaxPaths]string

	at   time.Time
	prev [MaxPaths]PathStats
	ro   [4]uint64
}

func (m *Monitor) Report() string {
	now, t := Now(), time.Now()
	dt := t.Sub(m.at).Seconds()
	first := m.at.IsZero()
	m.at = t
	var sb strings.Builder
	var totTx, totRx float64
	for i, p := range m.E.Paths {
		if p.Out == nil || p.lastRx.Load() == 0 {
			continue
		}
		s := p.Stats(now)
		pv := m.prev[i]
		m.prev[i] = s
		if first {
			continue
		}
		tx := float64(s.TxBytes-pv.TxBytes) * 8 / dt / 1e6
		rx := float64(s.RxBytes-pv.RxBytes) * 8 / dt / 1e6
		totTx += tx
		totRx += rx
		loss := 0.0
		if sent := s.SentUpTo - pv.SentUpTo; sent > 0 && pv.SentUpTo != 0 {
			loss = 100 * (1 - float64(s.RxPkts-pv.RxPkts)/float64(sent))
		}
		name := m.Names[i]
		if name == "" {
			name = fmt.Sprintf("path%d", i)
		}
		state := "up"
		if !s.Alive {
			state = "DOWN"
		}
		fmt.Fprintf(&sb, "  %-9s %-4s tx %7.1f rx %7.1f Mbit/s  rtt %5.1f/%5.1f ms  rate %6.1f  infl %5d KB  loss %4.1f%%  ooo %d\n",
			name, state, tx, rx, ms(s.SRTT), ms(s.MinRTT), s.RateBps/1e6, s.Inflight/1024, loss, s.OOO-pv.OOO)
	}
	late, skipped, fast, tmo, cur := m.E.ReorderStats()
	ro := [4]uint64{late, skipped, fast, tmo}
	d := [4]uint64{}
	for i := range ro {
		d[i] = ro[i] - m.ro[i]
	}
	m.ro = ro
	if first {
		return ""
	}
	return fmt.Sprintf("total tx %7.1f rx %7.1f Mbit/s | reorder late %d skipped %d fast %d timeout %d (wait %.0f ms)\n%s",
		totTx, totRx, d[0], d[1], d[2], d[3], ms(cur), sb.String())
}

func ms(d time.Duration) float64 { return float64(d) / 1e6 }
