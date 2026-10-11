package adblock

import (
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const hosts = `# comment
127.0.0.1 localhost
0.0.0.0 0.0.0.0
0.0.0.0 doubleclick.net
0.0.0.0 ads.example.com tracker.example.org # trailing
plain-list.example
`

func TestFilter(t *testing.T) {
	f := NewFilter()
	n, err := f.Load(strings.NewReader(hosts), time.Now())
	if err != nil || n != 4 {
		t.Fatalf("loaded %d, %v", n, err)
	}
	if f.Blocks("doubleclick.net") {
		t.Fatal("blocked while disabled")
	}
	f.SetEnabled(true)
	for name, want := range map[string]bool{
		"doubleclick.net.": true, "ad.DoubleClick.net": true, "ads.example.com": true,
		"example.com": false, "plain-list.example": true, "notdoubleclick.net": false, "localhost": false,
	} {
		if got := f.Blocks(name); got != want {
			t.Errorf("Blocks(%q) = %v, want %v", name, got, want)
		}
	}
	f.SetAllow([]string{"doubleclick.net"})
	if f.Blocks("ad.doubleclick.net") {
		t.Error("allowlist ignored")
	}
}

func query(t *testing.T, addr, name string, typ dnsmessage.Type) *dnsmessage.Message {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 77, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(q)
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	return &m
}

func TestServer(t *testing.T) {
	// Fake upstream answering every A query with 192.0.2.1.
	up, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer up.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			m.Unpack(buf[:n])
			m.Header.Response = true
			m.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 5},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
			}}
			out, _ := m.Pack()
			up.WriteTo(out, from)
		}
	}()

	f := NewFilter()
	f.Load(strings.NewReader(hosts), time.Now())
	f.SetEnabled(true)
	s, err := Serve("127.0.0.1:0", []string{up.LocalAddr().String()}, f, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := s.udp.LocalAddr().String()

	m := query(t, addr, "ad.doubleclick.net.", dnsmessage.TypeA)
	if m.ID != 77 || len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{} {
		t.Fatalf("blocked A: %+v", m)
	}
	m = query(t, addr, "ads.example.com.", dnsmessage.TypeAAAA)
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA != [16]byte{} {
		t.Fatalf("blocked AAAA: %+v", m)
	}
	m = query(t, addr, "example.com.", dnsmessage.TypeA)
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 1} {
		t.Fatalf("forwarded: %+v", m)
	}
	f.SetEnabled(false)
	m = query(t, addr, "doubleclick.net.", dnsmessage.TypeA)
	if m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 1} {
		t.Fatal("blocked while disabled")
	}
	if f.Blocked.Load() != 2 || f.Queries.Load() != 4 {
		t.Fatalf("counters %d/%d", f.Blocked.Load(), f.Queries.Load())
	}
}
