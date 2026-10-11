package proto

import (
	"bytes"
	"testing"
)

// handshake runs both sides and returns their derived keys' behaviour.
func TestHandshakeForwardSecrecy(t *testing.T) {
	psk := bytes.Repeat([]byte{7}, 32)
	cr, cpriv := NewRandom(), Ephemeral()
	hello := BuildHello(psk, Hello{Path: 1, ClientRandom: cr, ClientPub: cpriv.PublicKey().Bytes(), UnixNano: 42})

	// Server side.
	h, err := ParseHello(psk, hello)
	if err != nil || h.UnixNano != 42 || h.Path != 1 {
		t.Fatalf("parse hello: %v %+v", err, h)
	}
	sr, spriv := NewRandom(), Ephemeral()
	sshared, err := SharedSecret(spriv, h.ClientPub)
	if err != nil {
		t.Fatal(err)
	}
	sc2s, _, _ := DeriveKeys(psk, h.ClientRandom, sr, h.ClientPub, spriv.PublicKey().Bytes(), sshared)
	ackb := BuildHelloAck(psk, HelloAck{Path: 1, SID: 9, ClientRandom: h.ClientRandom, ServerRandom: sr, ServerPub: spriv.PublicKey().Bytes()})

	// Client side.
	ack, err := ParseHelloAck(psk, ackb)
	if err != nil || ack.SID != 9 || !bytes.Equal(ack.ClientRandom, cr) {
		t.Fatalf("parse ack: %v", err)
	}
	cshared, _ := SharedSecret(cpriv, ack.ServerPub)
	cc2s, _, _ := DeriveKeys(psk, cr, ack.ServerRandom, cpriv.PublicKey().Bytes(), ack.ServerPub, cshared)

	pkt := make([]byte, HeaderLen+5, HeaderLen+5+TagLen)
	PutHeader(pkt, TypePing, 0, 9, 1)
	copy(pkt[HeaderLen:], "hello")
	sealed := Seal(cc2s, pkt, 5)
	body, err := Open(sc2s, append([]byte{}, sealed...))
	if err != nil || string(body) != "hello" {
		t.Fatalf("keys differ: %v", err)
	}

	// Someone who later learns the PSK and recorded the handshake, but not an
	// ephemeral private key, cannot rebuild the session key.
	attacker := Ephemeral()
	guess, _ := SharedSecret(attacker, ack.ServerPub)
	ac2s, _, _ := DeriveKeys(psk, cr, ack.ServerRandom, h.ClientPub, ack.ServerPub, guess)
	if _, err := Open(ac2s, append([]byte{}, sealed...)); err == nil {
		t.Fatal("decrypted without the ephemeral secret")
	}

	// A swapped public key (man in the middle) breaks the MAC.
	bad := append([]byte{}, hello...)
	bad[HeaderLen+RandomLen] ^= 1
	if _, err := ParseHello(psk, bad); err == nil {
		t.Fatal("tampered hello accepted")
	}
	bad = append([]byte{}, ackb...)
	bad[HeaderLen+2*RandomLen] ^= 1
	if _, err := ParseHelloAck(psk, bad); err == nil {
		t.Fatal("tampered ack accepted")
	}
}
