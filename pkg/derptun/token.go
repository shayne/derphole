// Copyright (c) 2026 Shayne All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derptun

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sessiontoken "github.com/shayne/derphole/pkg/token"
	"tailscale.com/types/key"
)

const (
	ServerTokenPrefix = "dts1_"
	ClientTokenPrefix = "dtc1_"
	TokenVersion      = 1
	DefaultServerDays = 180
	DefaultClientDays = 90
	ProtocolTCP       = "tcp"
	ProtocolUDP       = "udp"
)

var (
	ErrExpired      = errors.New("derptun token expired")
	ErrInvalidToken = errors.New("invalid derptun token")
)

type ServerTokenOptions struct {
	Now     time.Time
	Days    int
	Expires time.Time
}

type ClientTokenOptions struct {
	Now         time.Time
	ServerToken string
	Days        int
	Expires     time.Time
}

type ForwardSpec struct {
	Protocol           string `json:"protocol"`
	ListenAddr         string `json:"listen_addr,omitempty"`
	TargetAddr         string `json:"target_addr,omitempty"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds,omitempty"`
}

type ServerCredential struct {
	Version       int           `json:"version"`
	SessionID     [16]byte      `json:"session_id"`
	ExpiresUnix   int64         `json:"expires_unix"`
	DERPPrivate   string        `json:"derp_private"`
	QUICPrivate   []byte        `json:"quic_private"`
	SigningSecret [32]byte      `json:"signing_secret"`
	Forwards      []ForwardSpec `json:"forwards,omitempty"`
}

type ClientCredential struct {
	Version      int      `json:"version"`
	SessionID    [16]byte `json:"session_id"`
	ClientID     [16]byte `json:"client_id"`
	TokenID      [16]byte `json:"token_id"`
	ClientName   string   `json:"client_name"`
	ExpiresUnix  int64    `json:"expires_unix"`
	DERPPublic   [32]byte `json:"derp_public"`
	QUICPublic   [32]byte `json:"quic_public"`
	BearerSecret [32]byte `json:"bearer_secret"`
	ProofMAC     string   `json:"proof_mac"`
}

func GenerateServerToken(opts ServerTokenOptions) (string, error) {
	now := normalizedNow(opts.Now)
	expires, err := resolveExpiry(now, opts.Days, opts.Expires, DefaultServerDays)
	if err != nil {
		return "", err
	}
	cred := ServerCredential{
		Version:     TokenVersion,
		ExpiresUnix: expires.Unix(),
	}
	if _, err := rand.Read(cred.SessionID[:]); err != nil {
		return "", err
	}
	if _, err := rand.Read(cred.SigningSecret[:]); err != nil {
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
	return encodeJSONToken(ServerTokenPrefix, cred)
}

func GenerateClientToken(opts ClientTokenOptions) (string, error) {
	now := normalizedNow(opts.Now)
	server, err := DecodeServerToken(opts.ServerToken, now)
	if err != nil {
		return "", err
	}
	expires, err := resolveExpiry(now, opts.Days, opts.Expires, DefaultClientDays)
	if err != nil {
		return "", err
	}
	if expires.Unix() > server.ExpiresUnix {
		return "", fmt.Errorf("client expiry exceeds server expiry")
	}
	client := ClientCredential{
		Version:     TokenVersion,
		SessionID:   server.SessionID,
		ExpiresUnix: expires.Unix(),
	}
	if _, err := rand.Read(client.ClientID[:]); err != nil {
		return "", err
	}
	if _, err := rand.Read(client.TokenID[:]); err != nil {
		return "", err
	}
	client.ClientName = clientNameForID(client.ClientID)
	serverTok, err := server.SessionToken()
	if err != nil {
		return "", err
	}
	client.DERPPublic = serverTok.DERPPublic
	client.QUICPublic = serverTok.QUICPublic
	client.BearerSecret = deriveClientBearerSecret(server.SigningSecret, client.ClientID)
	client.ProofMAC = computeClientProofMAC(server.SigningSecret, client)
	return encodeJSONToken(ClientTokenPrefix, client)
}

func EncodeClientCredential(cred ClientCredential) (string, error) {
	return encodeJSONToken(ClientTokenPrefix, cred)
}

func DecodeServerToken(encoded string, now time.Time) (ServerCredential, error) {
	var cred ServerCredential
	if err := decodeJSONToken(encoded, ServerTokenPrefix, &cred); err != nil {
		return ServerCredential{}, err
	}
	if cred.Version != TokenVersion ||
		cred.SessionID == ([16]byte{}) ||
		cred.DERPPrivate == "" ||
		len(cred.QUICPrivate) != ed25519.PrivateKeySize ||
		cred.SigningSecret == ([32]byte{}) {
		return ServerCredential{}, ErrInvalidToken
	}
	if _, err := cred.DERPKey(); err != nil {
		return ServerCredential{}, ErrInvalidToken
	}
	if expired(now, cred.ExpiresUnix) {
		return ServerCredential{}, ErrExpired
	}
	return cred, nil
}

func DecodeClientToken(encoded string, now time.Time) (ClientCredential, error) {
	var cred ClientCredential
	if err := decodeJSONToken(encoded, ClientTokenPrefix, &cred); err != nil {
		return ClientCredential{}, err
	}
	if cred.Version != TokenVersion ||
		cred.SessionID == ([16]byte{}) ||
		cred.ClientID == ([16]byte{}) ||
		cred.TokenID == ([16]byte{}) ||
		cred.ClientName == "" ||
		cred.DERPPublic == ([32]byte{}) ||
		cred.QUICPublic == ([32]byte{}) ||
		cred.BearerSecret == ([32]byte{}) ||
		!validProofMACHex(cred.ProofMAC) {
		return ClientCredential{}, ErrInvalidToken
	}
	if expired(now, cred.ExpiresUnix) {
		return ClientCredential{}, ErrExpired
	}
	return cred, nil
}

func (cred ServerCredential) DERPKey() (key.NodePrivate, error) {
	var derpKey key.NodePrivate
	if err := derpKey.UnmarshalText([]byte(cred.DERPPrivate)); err != nil {
		return key.NodePrivate{}, err
	}
	return derpKey, nil
}

func (cred ServerCredential) QUICPrivateKey() (ed25519.PrivateKey, error) {
	if len(cred.QUICPrivate) != ed25519.PrivateKeySize {
		return nil, ErrInvalidToken
	}
	return ed25519.PrivateKey(append([]byte(nil), cred.QUICPrivate...)), nil
}

func (cred ServerCredential) SessionToken() (sessiontoken.Token, error) {
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
		BearerSecret: deriveClientBearerSecret(cred.SigningSecret, [16]byte{}),
		Capabilities: sessiontoken.CapabilityDerptunTCP,
	}, nil
}

func (cred ClientCredential) SessionToken() (sessiontoken.Token, error) {
	return sessiontoken.Token{
		Version:      sessiontoken.SupportedVersion,
		SessionID:    cred.SessionID,
		ExpiresUnix:  cred.ExpiresUnix,
		DERPPublic:   cred.DERPPublic,
		QUICPublic:   cred.QUICPublic,
		BearerSecret: cred.BearerSecret,
		Capabilities: sessiontoken.CapabilityDerptunTCP,
	}, nil
}

func DeriveClientBearerSecretForClaim(secret [32]byte, clientID [16]byte) [32]byte {
	return deriveClientBearerSecret(secret, clientID)
}

func VerifyClientCredential(secret [32]byte, client ClientCredential, now time.Time) error {
	if expired(now, client.ExpiresUnix) {
		return ErrExpired
	}
	if client.BearerSecret != deriveClientBearerSecret(secret, client.ClientID) {
		return ErrInvalidToken
	}
	if !validClientProofMAC(secret, client) {
		return ErrInvalidToken
	}
	return nil
}

func clientNameForID(clientID [16]byte) string {
	return "client-" + hex.EncodeToString(clientID[:4])
}

func normalizedNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now()
	}
	return now
}

func resolveExpiry(now time.Time, days int, expires time.Time, defaultDays int) (time.Time, error) {
	if expires.IsZero() {
		if days == 0 {
			days = defaultDays
		}
		if days < 1 {
			return time.Time{}, fmt.Errorf("days must be at least 1")
		}
		expires = now.Add(time.Duration(days) * 24 * time.Hour)
	}
	if !expires.After(now) {
		return time.Time{}, fmt.Errorf("expiry must be in the future")
	}
	return expires, nil
}

func expired(now time.Time, expiresUnix int64) bool {
	if now.IsZero() {
		now = time.Now()
	}
	return now.Unix() >= expiresUnix
}

func validProofMACHex(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size
}

func validClientProofMAC(secret [32]byte, client ClientCredential) bool {
	got, err := hex.DecodeString(client.ProofMAC)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(computeClientProofMAC(secret, client))
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

func encodeJSONToken(prefix string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeJSONToken(encoded, prefix string, dst any) error {
	if len(encoded) <= len(prefix) || encoded[:len(prefix)] != prefix {
		return ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded[len(prefix):])
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return err
	}
	return nil
}

func deriveClientBearerSecret(secret [32]byte, clientID [16]byte) [32]byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte("derptun-client-bearer-v1"))
	mac.Write(clientID[:])
	sum := mac.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out
}

func computeClientProofMAC(secret [32]byte, client ClientCredential) string {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte("derptun-client-proof-v1"))
	mac.Write(client.SessionID[:])
	mac.Write(client.ClientID[:])
	mac.Write(client.TokenID[:])
	mac.Write([]byte(client.ClientName))
	mac.Write(client.DERPPublic[:])
	mac.Write(client.QUICPublic[:])
	mac.Write(client.BearerSecret[:])
	mac.Write([]byte(fmt.Sprintf("%d", client.ExpiresUnix)))
	return hex.EncodeToString(mac.Sum(nil))
}
