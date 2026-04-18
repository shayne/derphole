package derptun

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sessiontoken "github.com/shayne/derphole/pkg/token"
	"tailscale.com/types/key"
)

const (
	TokenPrefix  = "dt1_"
	TokenVersion = 1
	DefaultDays  = 7
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
)

var (
	ErrExpired      = errors.New("derptun token expired")
	ErrInvalidToken = errors.New("invalid derptun token")
)

type TokenOptions struct {
	Now     time.Time
	Days    int
	Expires time.Time
}

type ForwardSpec struct {
	Protocol           string `json:"protocol"`
	ListenAddr         string `json:"listen_addr,omitempty"`
	TargetAddr         string `json:"target_addr,omitempty"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds,omitempty"`
}

type Credential struct {
	Version      int           `json:"version"`
	SessionID    [16]byte      `json:"session_id"`
	ExpiresUnix  int64         `json:"expires_unix"`
	BearerSecret [32]byte      `json:"bearer_secret"`
	DERPPrivate  string        `json:"derp_private"`
	QUICPrivate  []byte        `json:"quic_private"`
	Forwards     []ForwardSpec `json:"forwards,omitempty"`
}

func GenerateToken(opts TokenOptions) (string, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	expires := opts.Expires
	if expires.IsZero() {
		days := opts.Days
		if days == 0 {
			days = DefaultDays
		}
		if days < 1 {
			return "", fmt.Errorf("days must be at least 1")
		}
		expires = now.Add(time.Duration(days) * 24 * time.Hour)
	}
	if !expires.After(now) {
		return "", fmt.Errorf("expiry must be in the future")
	}

	cred := Credential{
		Version:     TokenVersion,
		ExpiresUnix: expires.Unix(),
	}
	if _, err := rand.Read(cred.SessionID[:]); err != nil {
		return "", err
	}
	if _, err := rand.Read(cred.BearerSecret[:]); err != nil {
		return "", err
	}
	derpPrivate := key.NewNode()
	derpText, err := derpPrivate.MarshalText()
	if err != nil {
		return "", err
	}
	cred.DERPPrivate = string(derpText)
	_, quicPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	cred.QUICPrivate = append([]byte(nil), quicPrivate...)

	return EncodeCredential(cred)
}

func EncodeCredential(cred Credential) (string, error) {
	if cred.Version == 0 {
		cred.Version = TokenVersion
	}
	if cred.Version != TokenVersion {
		return "", ErrInvalidToken
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeToken(encoded string, now time.Time) (Credential, error) {
	if len(encoded) <= len(TokenPrefix) || encoded[:len(TokenPrefix)] != TokenPrefix {
		return Credential{}, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded[len(TokenPrefix):])
	if err != nil {
		return Credential{}, err
	}
	var cred Credential
	if err := json.Unmarshal(raw, &cred); err != nil {
		return Credential{}, err
	}
	if cred.Version != TokenVersion ||
		cred.SessionID == ([16]byte{}) ||
		cred.BearerSecret == ([32]byte{}) ||
		cred.DERPPrivate == "" ||
		len(cred.QUICPrivate) != ed25519.PrivateKeySize {
		return Credential{}, ErrInvalidToken
	}
	if _, err := cred.DERPKey(); err != nil {
		return Credential{}, ErrInvalidToken
	}
	if now.IsZero() {
		now = time.Now()
	}
	if now.Unix() >= cred.ExpiresUnix {
		return Credential{}, ErrExpired
	}
	return cred, nil
}

func (cred Credential) DERPKey() (key.NodePrivate, error) {
	var derpKey key.NodePrivate
	if err := derpKey.UnmarshalText([]byte(cred.DERPPrivate)); err != nil {
		return key.NodePrivate{}, err
	}
	return derpKey, nil
}

func (cred Credential) QUICPrivateKey() (ed25519.PrivateKey, error) {
	if len(cred.QUICPrivate) != ed25519.PrivateKeySize {
		return nil, ErrInvalidToken
	}
	return ed25519.PrivateKey(append([]byte(nil), cred.QUICPrivate...)), nil
}

func (cred Credential) SessionToken() (sessiontoken.Token, error) {
	derpKey, err := cred.DERPKey()
	if err != nil {
		return sessiontoken.Token{}, err
	}
	quicPrivate, err := cred.QUICPrivateKey()
	if err != nil {
		return sessiontoken.Token{}, err
	}
	var quicPublic [32]byte
	copy(quicPublic[:], quicPrivate.Public().(ed25519.PublicKey))
	var derpPublic [32]byte
	copy(derpPublic[:], derpKey.Public().AppendTo(nil))

	return sessiontoken.Token{
		Version:      sessiontoken.SupportedVersion,
		SessionID:    cred.SessionID,
		ExpiresUnix:  cred.ExpiresUnix,
		DERPPublic:   derpPublic,
		QUICPublic:   quicPublic,
		BearerSecret: cred.BearerSecret,
		Capabilities: sessiontoken.CapabilityDerptunTCP,
	}, nil
}
