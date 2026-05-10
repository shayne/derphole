// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

type DiscoveryKey [32]byte

type directProbeToken struct {
	mac   bool
	nonce [16]byte
}

var discoMACMagic = [16]byte{0, 'd', 'e', 'r', 'p', 'h', 'o', 'l', 'e', '-', 'd', 'i', 's', 'c', 'o', '1'}

const (
	discoMACKindProbe byte = 1
	discoMACKindAck   byte = 2
	discoMACSize           = len(discoMACMagic) + 1 + 16 + sha256.Size
)

func (k DiscoveryKey) IsZero() bool {
	return k == DiscoveryKey{}
}

func newDirectProbePayload(key DiscoveryKey) ([]byte, directProbeToken, error) {
	if key.IsZero() {
		return append([]byte(nil), discoProbePayload...), directProbeToken{}, nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, directProbeToken{}, err
	}
	return encodeDiscoveryMAC(key, discoMACKindProbe, nonce), directProbeToken{mac: true, nonce: nonce}, nil
}

func directAckPayloadForProbe(key DiscoveryKey, payload []byte) ([]byte, bool) {
	if key.IsZero() {
		if string(payload) != string(discoProbePayload) {
			return nil, false
		}
		return append([]byte(nil), discoAckPayload...), true
	}
	nonce, ok := decodeDiscoveryMAC(key, payload, discoMACKindProbe)
	if !ok {
		return nil, false
	}
	return encodeDiscoveryMAC(key, discoMACKindAck, nonce), true
}

func directAckTokenForPayload(key DiscoveryKey, payload []byte) (directProbeToken, bool) {
	if key.IsZero() {
		return directProbeToken{}, string(payload) == string(discoAckPayload)
	}
	nonce, ok := decodeDiscoveryMAC(key, payload, discoMACKindAck)
	if !ok {
		return directProbeToken{}, false
	}
	return directProbeToken{mac: true, nonce: nonce}, true
}

func isDirectDiscoveryMACPayload(payload []byte) bool {
	return len(payload) == discoMACSize && string(payload[:len(discoMACMagic)]) == string(discoMACMagic[:])
}

func isLegacyDirectDiscoveryPayload(payload []byte) bool {
	return string(payload) == string(discoProbePayload) || string(payload) == string(discoAckPayload)
}

func encodeDiscoveryMAC(key DiscoveryKey, kind byte, nonce [16]byte) []byte {
	payload := make([]byte, 0, discoMACSize)
	payload = append(payload, discoMACMagic[:]...)
	payload = append(payload, kind)
	payload = append(payload, nonce[:]...)
	mac := hmac.New(sha256.New, key[:])
	mac.Write(payload)
	payload = mac.Sum(payload)
	return payload
}

func decodeDiscoveryMAC(key DiscoveryKey, payload []byte, kind byte) ([16]byte, bool) {
	var nonce [16]byte
	if len(payload) != discoMACSize {
		return nonce, false
	}
	if string(payload[:len(discoMACMagic)]) != string(discoMACMagic[:]) {
		return nonce, false
	}
	if payload[len(discoMACMagic)] != kind {
		return nonce, false
	}
	copy(nonce[:], payload[len(discoMACMagic)+1:len(discoMACMagic)+1+len(nonce)])
	macStart := len(discoMACMagic) + 1 + len(nonce)
	mac := hmac.New(sha256.New, key[:])
	mac.Write(payload[:macStart])
	return nonce, hmac.Equal(payload[macStart:], mac.Sum(nil))
}
