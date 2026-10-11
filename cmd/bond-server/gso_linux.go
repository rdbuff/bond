//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	gsoMaxSegments = 64
	gsoMaxBytes    = 65000
)

// udpSender sends datagrams in batches, coalescing runs of equal-sized
// datagrams to the same address into UDP GSO super-datagrams so the kernel
// walks its send path once per run instead of once per packet.
type udpSender struct {
	pc   *ipv4.PacketConn
	gso  bool
	msgs []ipv4.Message
	oobs [][]byte
}

func newUDPSender(conn *net.UDPConn, pc *ipv4.PacketConn, n int) *udpSender {
	s := &udpSender{pc: pc, gso: gsoSupported(conn)}
	s.msgs = make([]ipv4.Message, n+1)
	s.oobs = make([][]byte, n+1)
	for i := range s.msgs {
		s.msgs[i].Buffers = make([][]byte, 0, gsoMaxSegments)
		s.oobs[i] = make([]byte, unix.CmsgSpace(2))
	}
	return s
}

func gsoSupported(conn *net.UDPConn) bool {
	rc, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	rc.Control(func(fd uintptr) {
		_, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		ok = err == nil
	})
	return ok
}

func (s *udpSender) setSegment(oob []byte, size int) []byte {
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.SOL_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(size))
	return oob[:unix.CmsgSpace(2)]
}

// Send transmits pkts, in order, to addr.
func (s *udpSender) Send(pkts [][]byte, addr *net.UDPAddr) {
	if len(pkts) == 0 {
		return
	}
	m := 0
	if s.gso {
		var seg, total int
		for _, p := range pkts {
			msg := &s.msgs[m]
			if len(msg.Buffers) == 0 {
				msg.Buffers = append(msg.Buffers, p)
				seg, total = len(p), len(p)
				continue
			}
			// Every segment but the last must be exactly seg bytes long.
			if len(p) <= seg && total+len(p) <= gsoMaxBytes && len(msg.Buffers) < gsoMaxSegments {
				msg.Buffers = append(msg.Buffers, p)
				total += len(p)
				if len(p) < seg {
					m = s.close(m, seg)
				}
				continue
			}
			m = s.close(m, seg)
			s.msgs[m].Buffers = append(s.msgs[m].Buffers, p)
			seg, total = len(p), len(p)
		}
		if len(s.msgs[m].Buffers) > 0 {
			m = s.close(m, seg)
		}
	} else {
		for _, p := range pkts {
			s.msgs[m].Buffers = append(s.msgs[m].Buffers, p)
			s.msgs[m].OOB = nil
			m++
		}
	}
	for i := 0; i < m; i++ {
		s.msgs[i].Addr = addr
	}
	err := s.write(m)
	if err != nil && s.gso && errors.Is(err, syscall.EIO) {
		// No checksum offload for GSO on this NIC: fall back for good.
		log.Printf("UDP GSO unsupported (%v), disabling", err)
		s.gso = false
		s.reset(m)
		s.Send(pkts, addr)
		return
	}
	if err != nil {
		log.Printf("udp write: %v", err)
	}
	s.reset(m)
}

// close finishes message m, attaching the segment size if it carries more
// than one datagram, and returns the index of the next free message.
func (s *udpSender) close(m, seg int) int {
	msg := &s.msgs[m]
	if len(msg.Buffers) > 1 {
		msg.OOB = s.setSegment(s.oobs[m], seg)
	} else {
		msg.OOB = nil
	}
	return m + 1
}

func (s *udpSender) write(m int) error {
	for off := 0; off < m; {
		k, err := s.pc.WriteBatch(s.msgs[off:m], 0)
		if err != nil {
			return err
		}
		off += k
	}
	return nil
}

func (s *udpSender) reset(m int) {
	for i := 0; i < m && i < len(s.msgs); i++ {
		clear(s.msgs[i].Buffers)
		s.msgs[i].Buffers = s.msgs[i].Buffers[:0]
		s.msgs[i].OOB = nil
		s.msgs[i].Addr = nil
	}
}
