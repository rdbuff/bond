// Package adblock is a filtering DNS forwarder: queries for domains on a
// blocklist are answered with 0.0.0.0 / ::, everything else is forwarded
// unchanged to upstream resolvers.
package adblock

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DefaultListURL is StevenBlack's unified hosts list (ads, trackers, malware).
const DefaultListURL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

const blockedTTL = 60

// Filter decides which names are blocked. It is safe for concurrent use.
type Filter struct {
	enabled atomic.Bool

	mu      sync.RWMutex
	block   map[string]struct{}
	allow   map[string]struct{}
	updated time.Time

	Queries, Blocked atomic.Uint64
}

func NewFilter() *Filter { return &Filter{} }

func (f *Filter) SetEnabled(on bool) { f.enabled.Store(on) }
func (f *Filter) Enabled() bool      { return f.enabled.Load() }

// Count returns the number of blocklist entries and when the list was fetched.
func (f *Filter) Count() (int, time.Time) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.block), f.updated
}

// SetAllow replaces the allowlist; an allowed domain also allows its
// subdomains.
func (f *Filter) SetAllow(domains []string) {
	m := map[string]struct{}{}
	for _, d := range domains {
		if d = normalize(d); d != "" {
			m[d] = struct{}{}
		}
	}
	f.mu.Lock()
	f.allow = m
	f.mu.Unlock()
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// matches reports whether name or one of its parent domains is in set.
func matches(set map[string]struct{}, name string) bool {
	for {
		if _, ok := set[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}

// Blocks reports whether queries for name should be blocked right now.
func (f *Filter) Blocks(name string) bool {
	if !f.Enabled() {
		return false
	}
	name = normalize(name)
	f.mu.RLock()
	defer f.mu.RUnlock()
	return !matches(f.allow, name) && matches(f.block, name)
}

// Load replaces the blocklist with one in hosts format ("0.0.0.0 domain") or
// a plain one-domain-per-line list.
func (f *Filter) Load(r io.Reader, updated time.Time) (int, error) {
	m := make(map[string]struct{}, 100000)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		switch len(fields) {
		case 0:
			continue
		case 1:
		default:
			fields = fields[1:] // hosts format: address then names
		}
		for _, d := range fields {
			d = normalize(d)
			if d == "" || !strings.Contains(d, ".") || net.ParseIP(d) != nil ||
				d == "localhost.localdomain" || d == "local" || d == "broadcasthost" {
				continue
			}
			m[d] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if len(m) == 0 {
		return 0, errors.New("blocklist is empty")
	}
	f.mu.Lock()
	f.block, f.updated = m, updated
	f.mu.Unlock()
	return len(m), nil
}

// Update loads the list from cachePath if it is younger than maxAge and
// otherwise downloads it from url, falling back to a stale cache when the
// download fails.
func (f *Filter) Update(ctx context.Context, url, cachePath string, maxAge time.Duration) (int, error) {
	loadCache := func() (int, error) {
		fh, err := os.Open(cachePath)
		if err != nil {
			return 0, err
		}
		defer fh.Close()
		st, _ := fh.Stat()
		return f.Load(fh, st.ModTime())
	}
	if st, err := os.Stat(cachePath); err == nil && time.Since(st.ModTime()) < maxAge {
		if n, err := loadCache(); err == nil {
			return n, nil
		}
	}
	n, err := f.download(ctx, url, cachePath)
	if err != nil {
		if n, cerr := loadCache(); cerr == nil {
			return n, nil
		}
		return 0, err
	}
	return n, nil
}

func (f *Filter) download(ctx context.Context, url, cachePath string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("download blocklist: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download blocklist: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return 0, fmt.Errorf("download blocklist: %w", err)
	}
	n, err := f.Load(strings.NewReader(string(body)), time.Now())
	if err != nil {
		return 0, err
	}
	os.MkdirAll(filepath.Dir(cachePath), 0o755)
	tmp := cachePath + ".tmp"
	if os.WriteFile(tmp, body, 0o644) == nil {
		os.Rename(tmp, cachePath)
	}
	return n, nil
}

// Server is a DNS forwarder on UDP and TCP that applies a Filter.
type Server struct {
	filter    *Filter
	upstreams []string
	udp       net.PacketConn
	tcp       net.Listener
	logf      func(string, ...any)
	wg        sync.WaitGroup
}

// Serve listens on addr (host:port) and forwards to upstreams (IP, or IP:port;
// the port defaults to 53).
func Serve(addr string, upstreams []string, f *Filter, logf func(string, ...any)) (*Server, error) {
	if len(upstreams) == 0 {
		return nil, errors.New("no upstream DNS servers")
	}
	s := &Server{filter: f, logf: logf}
	for _, u := range upstreams {
		if _, _, err := net.SplitHostPort(u); err != nil {
			u = net.JoinHostPort(u, "53")
		}
		s.upstreams = append(s.upstreams, u)
	}
	var err error
	if s.udp, err = net.ListenPacket("udp", addr); err != nil {
		return nil, err
	}
	if s.tcp, err = net.Listen("tcp", addr); err != nil {
		s.udp.Close()
		return nil, err
	}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return s, nil
}

func (s *Server) Close() {
	s.udp.Close()
	s.tcp.Close()
	s.wg.Wait()
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	for {
		buf := make([]byte, 4096)
		n, from, err := s.udp.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			if resp := s.handle(buf[:n], "udp"); resp != nil {
				s.udp.WriteTo(resp, from)
			}
		}()
	}
}

func (s *Server) serveTCP() {
	defer s.wg.Done()
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readTCPMsg(c)
				if err != nil {
					return
				}
				resp := s.handle(q, "tcp")
				if resp == nil || writeTCPMsg(c, resp) != nil {
					return
				}
			}
		}()
	}
}

func readTCPMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeTCPMsg(w io.Writer, b []byte) error {
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	copy(out[2:], b)
	_, err := w.Write(out)
	return err
}

// handle answers one query: blocked locally, or forwarded over the same
// transport it arrived on.
func (s *Server) handle(q []byte, network string) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		return nil
	}
	question, err := p.Question()
	if err != nil {
		return nil
	}
	s.filter.Queries.Add(1)
	if s.filter.Blocks(question.Name.String()) {
		s.filter.Blocked.Add(1)
		return blockedResponse(h, question)
	}
	for _, up := range s.upstreams {
		if resp, err := forward(q, network, up); err == nil {
			return resp
		}
	}
	return servfail(h, question)
}

func forward(q []byte, network, upstream string) ([]byte, error) {
	c, err := net.DialTimeout(network, upstream, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if network == "tcp" {
		if err := writeTCPMsg(c, q); err != nil {
			return nil, err
		}
		return readTCPMsg(c)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && buf[0] == q[0] && buf[1] == q[1] { // same query ID
			return buf[:n], nil
		}
	}
}

func reply(h dnsmessage.Header, q dnsmessage.Question, rcode dnsmessage.RCode) *dnsmessage.Builder {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: h.ID, Response: true, OpCode: h.OpCode, RecursionDesired: h.RecursionDesired,
		RecursionAvailable: true, RCode: rcode,
	})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(q)
	return &b
}

// blockedResponse answers A with 0.0.0.0, AAAA with :: and anything else with
// an empty NOERROR, so clients get a definite answer and do not retry
// elsewhere.
func blockedResponse(h dnsmessage.Header, q dnsmessage.Question) []byte {
	b := reply(h, q, dnsmessage.RCodeSuccess)
	b.StartAnswers()
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: blockedTTL}
	switch q.Type {
	case dnsmessage.TypeA:
		b.AResource(rh, dnsmessage.AResource{})
	case dnsmessage.TypeAAAA:
		b.AAAAResource(rh, dnsmessage.AAAAResource{})
	}
	out, _ := b.Finish()
	return out
}

func servfail(h dnsmessage.Header, q dnsmessage.Question) []byte {
	out, _ := reply(h, q, dnsmessage.RCodeServerFailure).Finish()
	return out
}
