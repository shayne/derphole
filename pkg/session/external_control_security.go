package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"github.com/shayne/derphole/pkg/token"
)

type externalPeerControlAuth struct {
	HeartbeatKey [32]byte
}

func externalPeerControlAuthForToken(tok token.Token) externalPeerControlAuth {
	return externalPeerControlAuth{
		HeartbeatKey: externalSessionSubkey(tok, "derphole-peer-heartbeat-v1"),
	}
}

func (auth externalPeerControlAuth) heartbeatEnabled() bool {
	return auth.HeartbeatKey != [32]byte{}
}

func externalSessionSubkey(tok token.Token, label string) [32]byte {
	mac := hmac.New(sha256.New, tok.BearerSecret[:])
	mac.Write([]byte(label))
	mac.Write(tok.SessionID[:])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func newAuthenticatedPeerHeartbeat(bytesTransferred int64, sequence uint64, auth externalPeerControlAuth) *peerHeartbeat {
	hb := newPeerHeartbeat(bytesTransferred)
	if !auth.heartbeatEnabled() {
		return hb
	}
	hb.Sequence = sequence
	hb.MAC = externalPeerHeartbeatMAC(auth, sequence, bytesTransferred)
	return hb
}

func verifyPeerHeartbeat(hb *peerHeartbeat, auth externalPeerControlAuth, lastSequence *uint64) bool {
	if hb == nil {
		return false
	}
	if !auth.heartbeatEnabled() {
		return true
	}
	if hb.MAC == "" {
		return false
	}
	bytesTransferred := int64(0)
	if hb.BytesTransferred != nil {
		bytesTransferred = *hb.BytesTransferred
	}
	want := externalPeerHeartbeatMAC(auth, hb.Sequence, bytesTransferred)
	if !hmac.Equal([]byte(hb.MAC), []byte(want)) {
		return false
	}
	if lastSequence != nil {
		if hb.Sequence <= *lastSequence {
			return false
		}
		*lastSequence = hb.Sequence
	}
	return true
}

func externalPeerHeartbeatMAC(auth externalPeerControlAuth, sequence uint64, bytesTransferred int64) string {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], sequence)
	binary.BigEndian.PutUint64(buf[8:], uint64(bytesTransferred))
	mac := hmac.New(sha256.New, auth.HeartbeatKey[:])
	mac.Write([]byte("heartbeat"))
	mac.Write(buf[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
