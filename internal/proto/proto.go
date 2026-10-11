// Package proto defines the wire format, handshake and crypto of the bonding
// tunnel.
//
// Every UDP datagram starts with a 16-byte header that is sent in clear and
// authenticated as AEAD additional data:
//
//	0      type
//	1      path id
//	2..3   reserved (0)
//	4..7   session id   (big endian)
//	8..15  counter      (big endian, AEAD nonce, unique per direction)
//
// Session packets carry an AES-256-GCM sealed body after the header. Handshake
// packets (Hello/HelloAck) carry a clear body followed by a truncated
// HMAC-SHA256 keyed with the pre-shared key; they exchange ephemeral X25519
// keys so that session keys have forward secrecy.
package proto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	TypeHello    = 1
	TypeHelloAck = 2
	TypeData     = 3
	TypeFeedback = 4
	TypePing     = 5
	TypePong     = 6
)

const (
	HeaderLen  = 16
	DataHdrLen = 12 // dseq u64 + path seq u32
	TagLen     = 16
	MacLen     = 16
	RandomLen  = 32
	PubLen     = 32 // X25519 public key

	// DataOffset is where the inner IP packet starts inside a data datagram.
	DataOffset = HeaderLen + DataHdrLen
	// Overhead is the number of bytes a data datagram adds to an IP packet.
	Overhead = DataOffset + TagLen

	HelloLen    = HeaderLen + RandomLen + PubLen + 8 + MacLen
	HelloAckLen = HeaderLen + 2*RandomLen + PubLen + MacLen
	FeedbackLen = 28
)

var ErrAuth = errors.New("authentication failed")

func PutHeader(b []byte, typ, path uint8, sid uint32, ctr uint64) {
	b[0] = typ
	b[1] = path
	b[2], b[3] = 0, 0
	binary.BigEndian.PutUint32(b[4:], sid)
	binary.BigEndian.PutUint64(b[8:], ctr)
}

func ParseHeader(b []byte) (typ, path uint8, sid uint32, ctr uint64) {
	return b[0], b[1], binary.BigEndian.Uint32(b[4:]), binary.BigEndian.Uint64(b[8:])
}

// Seal encrypts b[HeaderLen:HeaderLen+bodyLen] in place, authenticating the
// header. b must have TagLen bytes of spare capacity after the body.
func Seal(aead cipher.AEAD, b []byte, bodyLen int) []byte {
	var nonce [12]byte
	copy(nonce[4:], b[8:16])
	ct := aead.Seal(b[HeaderLen:HeaderLen], nonce[:], b[HeaderLen:HeaderLen+bodyLen], b[:HeaderLen])
	return b[:HeaderLen+len(ct)]
}

// Open decrypts a sealed datagram in place and returns its body.
func Open(aead cipher.AEAD, b []byte) ([]byte, error) {
	if len(b) < HeaderLen+TagLen {
		return nil, ErrAuth
	}
	var nonce [12]byte
	copy(nonce[4:], b[8:16])
	return aead.Open(b[HeaderLen:HeaderLen], nonce[:], b[HeaderLen:], b[:HeaderLen])
}

// Ephemeral generates a fresh X25519 key pair for one handshake. Dropping the
// private key once the session keys are derived is what gives forward
// secrecy.
func Ephemeral() *ecdh.PrivateKey {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// SharedSecret computes the X25519 secret between our key and the peer's.
func SharedSecret(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub) // fails on low-order points (all-zero secret)
}

// DeriveKeys returns the client-to-server and server-to-client AEADs for a
// session. The key material is the PSK together with the ephemeral X25519
// shared secret, so recorded traffic stays unreadable even if the PSK leaks
// later: the ephemeral private keys no longer exist anywhere.
func DeriveKeys(psk, clientRandom, serverRandom, clientPub, serverPub, shared []byte) (c2s, s2c cipher.AEAD, err error) {
	ikm := append(append([]byte{}, psk...), shared...)
	salt := bytes.Join([][]byte{clientRandom, serverRandom, clientPub, serverPub}, nil)
	mk := func(info string) (cipher.AEAD, error) {
		key := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, []byte(info)), key); err != nil {
			return nil, err
		}
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	}
	if c2s, err = mk("bond c2s v2"); err != nil {
		return
	}
	s2c, err = mk("bond s2c v2")
	return
}

func mac(psk, msg []byte) []byte {
	h := hmac.New(sha256.New, psk)
	h.Write(msg)
	return h.Sum(nil)[:MacLen]
}

func NewRandom() []byte {
	r := make([]byte, RandomLen)
	if _, err := rand.Read(r); err != nil {
		panic(err)
	}
	return r
}

// Hello is the client's handshake message. The MAC over it (keyed with the
// PSK) authenticates the ephemeral public key, which stops a man in the middle
// from substituting his own.
type Hello struct {
	Path         uint8
	ClientRandom []byte
	ClientPub    []byte
	UnixNano     int64
}

// Body layout: clientRandom | clientPub | unixNano.
func BuildHello(psk []byte, h Hello) []byte {
	b := make([]byte, HelloLen)
	PutHeader(b, TypeHello, h.Path, 0, 0)
	copy(b[HeaderLen:], h.ClientRandom)
	copy(b[HeaderLen+RandomLen:], h.ClientPub)
	binary.BigEndian.PutUint64(b[HeaderLen+RandomLen+PubLen:], uint64(h.UnixNano))
	copy(b[HelloLen-MacLen:], mac(psk, b[:HelloLen-MacLen]))
	return b
}

func ParseHello(psk, b []byte) (Hello, error) {
	if len(b) != HelloLen || b[0] != TypeHello || !hmac.Equal(mac(psk, b[:HelloLen-MacLen]), b[HelloLen-MacLen:]) {
		return Hello{}, ErrAuth
	}
	o := HeaderLen
	return Hello{
		Path:         b[1],
		ClientRandom: b[o : o+RandomLen],
		ClientPub:    b[o+RandomLen : o+RandomLen+PubLen],
		UnixNano:     int64(binary.BigEndian.Uint64(b[o+RandomLen+PubLen:])),
	}, nil
}

// HelloAck is the server's answer, echoing the client's random.
type HelloAck struct {
	Path         uint8
	SID          uint32
	ClientRandom []byte
	ServerRandom []byte
	ServerPub    []byte
}

// Body layout: clientRandom | serverRandom | serverPub.
func BuildHelloAck(psk []byte, a HelloAck) []byte {
	b := make([]byte, HelloAckLen)
	PutHeader(b, TypeHelloAck, a.Path, a.SID, 0)
	copy(b[HeaderLen:], a.ClientRandom)
	copy(b[HeaderLen+RandomLen:], a.ServerRandom)
	copy(b[HeaderLen+2*RandomLen:], a.ServerPub)
	copy(b[HelloAckLen-MacLen:], mac(psk, b[:HelloAckLen-MacLen]))
	return b
}

func ParseHelloAck(psk, b []byte) (HelloAck, error) {
	if len(b) != HelloAckLen || b[0] != TypeHelloAck || !hmac.Equal(mac(psk, b[:HelloAckLen-MacLen]), b[HelloAckLen-MacLen:]) {
		return HelloAck{}, ErrAuth
	}
	o := HeaderLen
	return HelloAck{
		Path:         b[1],
		SID:          binary.BigEndian.Uint32(b[4:]),
		ClientRandom: b[o : o+RandomLen],
		ServerRandom: b[o+RandomLen : o+2*RandomLen],
		ServerPub:    b[o+2*RandomLen : o+2*RandomLen+PubLen],
	}, nil
}

// Replay is a sliding-window replay filter over AEAD counters. The window is
// large because packets on different paths arrive with a large skew. Not safe
// for concurrent use.
type Replay struct {
	last uint64
	bits [replayWords]uint64
}

const (
	replayWords = 1024
	replayBits  = replayWords * 64
)

func (r *Replay) Check(c uint64) bool {
	if c == 0 {
		return false
	}
	if c > r.last {
		if c-r.last >= replayBits {
			r.bits = [replayWords]uint64{}
		} else {
			for i := r.last + 1; i <= c; i++ {
				r.bits[(i/64)%replayWords] &^= 1 << (i % 64)
			}
		}
		r.last = c
	} else if r.last-c >= replayBits {
		return false
	}
	w, m := &r.bits[(c/64)%replayWords], uint64(1)<<(c%64)
	if *w&m != 0 {
		return false
	}
	*w |= m
	return true
}
