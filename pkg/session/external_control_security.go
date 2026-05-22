// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/shayne/derphole/pkg/token"
)

var errUnauthenticatedEnvelope = errors.New("unauthenticated envelope")

type externalPeerControlAuth struct {
	EnvelopeKey [32]byte
}

func externalPeerControlAuthForToken(tok token.Token) externalPeerControlAuth {
	return externalPeerControlAuth{
		EnvelopeKey: externalSessionSubkey(tok, "derphole-control-envelope-v1"),
	}
}

func (auth externalPeerControlAuth) envelopeEnabled() bool {
	return auth.EnvelopeKey != [32]byte{}
}

func optionalPeerControlAuth(auth []externalPeerControlAuth) externalPeerControlAuth {
	if len(auth) == 0 {
		return externalPeerControlAuth{}
	}
	return auth[0]
}

func externalSessionSubkey(tok token.Token, label string) [32]byte {
	mac := hmac.New(sha256.New, tok.BearerSecret[:])
	mac.Write([]byte(label))
	mac.Write(tok.SessionID[:])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func marshalAuthenticatedEnvelope(env envelope, auth externalPeerControlAuth) ([]byte, error) {
	env = signEnvelopeMAC(env, auth)
	return json.Marshal(env)
}

func signEnvelopeMAC(env envelope, auth externalPeerControlAuth) envelope {
	if !auth.envelopeEnabled() {
		return env
	}
	env.MAC = ""
	env.MAC = externalEnvelopeMAC(auth, env)
	return env
}

func verifyEnvelopeMAC(env envelope, auth externalPeerControlAuth) bool {
	if !auth.envelopeEnabled() {
		return true
	}
	if env.MAC == "" {
		return false
	}
	want := externalEnvelopeMAC(auth, env)
	return hmac.Equal([]byte(env.MAC), []byte(want))
}

func decodeAuthenticatedEnvelope(payload []byte, auth externalPeerControlAuth) (envelope, error) {
	env, err := decodeEnvelope(payload)
	if err != nil {
		return env, err
	}
	if !verifyEnvelopeMAC(env, auth) {
		return env, errUnauthenticatedEnvelope
	}
	return env, nil
}

func ignoreAuthenticatedEnvelopeError(err error, auth externalPeerControlAuth) bool {
	return auth.envelopeEnabled() && errors.Is(err, errUnauthenticatedEnvelope)
}

func externalEnvelopeMAC(auth externalPeerControlAuth, env envelope) string {
	env.MAC = ""
	payload, err := json.Marshal(env)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, auth.EnvelopeKey[:])
	mac.Write([]byte("envelope"))
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
