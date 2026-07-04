# Derptun Serve Invite And Token Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `DT1...` the only public derptun client token, make `derptun serve --tcp ...` print the matching `derptun open --token DT1...` command by default, and remove the old client-token format from product behavior.

**Architecture:** Keep `dts1_...` server tokens JSON/base64 encoded. Move client-token generation and decoding onto the existing compact binary payload, but rename the exported behavior around "client token" instead of "compact invite". CLI commands resolve explicit token sources, `serve` gets an optional token source plus ephemeral server-token generation, and shared derpssh/mobile/session code consumes the canonical `DT1...` token through `derptun.DecodeClientToken`.

**Tech Stack:** Go, yargs CLI helpers, existing derptun session transport, qrterminal, shell smoke scripts, README docs.

---

## File Structure

- Modify `pkg/derptun/token.go`
  - Keep server-token JSON helpers and server credential validation.
  - Make `ClientTokenPrefix` equal `DT1`.
  - Make `GenerateClientToken`, `DecodeClientToken`, and `EncodeClientCredential` use compact binary client-token encoding.
  - Keep `ErrInvalidToken`/`ErrExpired` behavior for malformed and expired client tokens.

- Modify and likely rename `pkg/derptun/invite.go` to `pkg/derptun/client_token.go`
  - Replace exported invite names with client-token names.
  - Keep compact codec helpers unexported.
  - Remove `EncodeClientInvite`, `DecodeClientInvite`, `CompactInvitePrefix`, and invite-specific validation names from product code.

- Modify `pkg/derptun/token_test.go` and `pkg/derptun/invite_test.go`
  - Update prefix assertions to `DT1`.
  - Replace invite terminology with client-token terminology.
  - Add explicit rejection coverage for an old `dtc1_...` token.

- Modify `cmd/derptun/token_source.go`
  - Add an optional token-source resolver for `serve`.
  - Keep exact-one token-source behavior for `token client`, `open`, and `connect`.

- Modify `cmd/derptun/serve.go`
  - Allow no server token source.
  - Generate an ephemeral server token when no source is supplied.
  - Derive a client token and always print the `npx -y derptun@latest open --token DT1...` command.
  - Make `--qr` render the same token, not a separate invite wrapper.

- Modify `cmd/derptun/open.go` and `cmd/derptun/connect.go`
  - Validate client token strings after source resolution.
  - Return a clear role-specific CLI error for `dts1_...` passed to `open`/`connect`.
  - Let removed `dtc1_...` strings fail as generic invalid client tokens.

- Modify `cmd/derptun/root.go`, `cmd/derptun/token.go`, `cmd/derptun/command_test.go`, `cmd/derptun/token_test.go`, and `cmd/derptun/root_test.go`
  - Update help/examples/tests to use `DT1...` and `client.dt1`.
  - Add `serve` tests for ephemeral server token and printed open command.

- Modify `pkg/session/derptun.go`, `pkg/session/derptun_app.go`, and tests only where needed
  - Keep public configs string-based unless a narrow typed-credential change is clearly simpler.
  - Ensure session decoding accepts `DT1...` and rejects `dtc1_...`.

- Modify `pkg/derpssh/session/invite.go`, `pkg/derpssh/session/share.go`, and `pkg/derpssh/session/share_connect_test.go`
  - Validate embedded derptun client tokens by decoding canonical `DT1...`, not by prefix-checking old tokens.
  - Update all test stubs from `dtc1_test` to generated canonical client tokens.

- Modify `pkg/derpholemobile/mobile.go` and `pkg/derpholemobile/mobile_test.go`
  - Treat a standalone `DT1...` payload as a TCP tunnel token directly.
  - Stop converting compact payloads through `EncodeClientCredential` from an old format.

- Modify `scripts/smoke-remote-derptun.sh`
  - Rename the local client token file to `client.dt1`.
  - Keep the same serve/open/connect smoke behavior.

- Modify `README.md`
  - Use the Caveman skill before editing because `AGENTS.md` requires it for README changes.
  - Make the first derptun example `serve --tcp ...` followed by the printed `open --token DT1...` command.
  - Move persistent server/client token files after the one-off path and use `client.dt1`.

## Task 1: Make DT1 The Canonical Client Token API

**Files:**
- Modify: `pkg/derptun/token.go`
- Modify or move: `pkg/derptun/invite.go` -> `pkg/derptun/client_token.go`
- Modify: `pkg/derptun/token_test.go`
- Modify: `pkg/derptun/invite_test.go` -> `pkg/derptun/client_token_test.go`

- [ ] **Step 1: Rename the compact invite test file**

Run:

```bash
mv pkg/derptun/invite_test.go pkg/derptun/client_token_test.go
```

Expected: no output. This is a file rename before editing; do not commit yet.

- [ ] **Step 2: Write failing package tests for canonical DT1 behavior**

In `pkg/derptun/token_test.go`, update `TestGenerateClientTokenFromServerToken` so it expects `ClientTokenPrefix == "DT1"` and no longer tries to JSON-decode the client token:

```go
func TestGenerateClientTokenFromServerToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	serverToken, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	clientToken, err := GenerateClientToken(ClientTokenOptions{
		Now:         now,
		ServerToken: serverToken,
		Days:        7,
	})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	if !strings.HasPrefix(clientToken, ClientTokenPrefix) {
		t.Fatalf("client token = %q, want %s prefix", clientToken, ClientTokenPrefix)
	}
	if strings.HasPrefix(clientToken, "dtc1_") {
		t.Fatalf("client token = %q, want removed format to be unused", clientToken)
	}
	clientCred, err := DecodeClientToken(clientToken, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	if clientCred.ClientName == "" {
		t.Fatalf("ClientName = empty, want generated name")
	}
	if got, want := time.Unix(clientCred.ExpiresUnix, 0).UTC(), now.Add(7*24*time.Hour); !got.Equal(want) {
		t.Fatalf("client expiry = %s, want %s", got, want)
	}
}
```

Add `strings` to the test imports.

Replace `TestDecodeClientTokenRejectsMalformedProofMAC` with a compact-token malformed-input test:

```go
func TestDecodeClientTokenRejectsMalformedInput(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, raw := range []string{
		"",
		"dtc1_legacy",
		"DT2ABC",
		"DT1",
		"DT1not valid",
		ClientTokenPrefix + strings.Repeat("0", compactClientTokenPayloadLen-1),
		ClientTokenPrefix + strings.Repeat("0", compactClientTokenPayloadLen+1),
	} {
		if _, err := DecodeClientToken(raw, now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("DecodeClientToken(%q) error = %v, want ErrInvalidToken", raw, err)
		}
	}
}
```

Update `TestEncodeClientCredentialAndDecodeServerValidation` so `EncodeClientCredential` round-trips to a `DT1...` token:

```go
encoded, err := EncodeClientCredential(clientCred)
if err != nil {
	t.Fatalf("EncodeClientCredential() error = %v", err)
}
if !strings.HasPrefix(encoded, ClientTokenPrefix) {
	t.Fatalf("EncodeClientCredential() = %q, want %s prefix", encoded, ClientTokenPrefix)
}
roundTrip, err := DecodeClientToken(encoded, now)
if err != nil {
	t.Fatalf("DecodeClientToken(encoded credential) error = %v", err)
}
if roundTrip.ClientID != clientCred.ClientID || roundTrip.ProofMAC != clientCred.ProofMAC {
	t.Fatal("encoded client credential did not round-trip")
}
```

In renamed `pkg/derptun/client_token_test.go`, rename test names and function calls:

```go
func TestClientTokenRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	server, err := GenerateServerToken(ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	token, err := GenerateClientToken(ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	if !strings.HasPrefix(token, ClientTokenPrefix) {
		t.Fatalf("token prefix = %q, want %q", token[:len(ClientTokenPrefix)], ClientTokenPrefix)
	}
	if strings.Contains(token, "://") || strings.Contains(token, "?") || strings.Contains(token, "&") {
		t.Fatalf("token = %q, want compact non-URL text", token)
	}
	if len(token) != len(ClientTokenPrefix)+compactClientTokenPayloadLen {
		t.Fatalf("token length = %d, want %d", len(token), len(ClientTokenPrefix)+compactClientTokenPayloadLen)
	}
	assertCompactClientTokenText(t, token)

	cred, err := DecodeClientToken(token, now)
	if err != nil {
		t.Fatalf("DecodeClientToken() error = %v", err)
	}
	if err := VerifyClientCredential(mustServerSigningSecret(t, server, now), cred, now); err != nil {
		t.Fatalf("VerifyClientCredential() error = %v", err)
	}
}
```

Add this helper in the same test file:

```go
func mustServerSigningSecret(t *testing.T, serverToken string, now time.Time) [32]byte {
	t.Helper()
	server, err := DecodeServerToken(serverToken, now)
	if err != nil {
		t.Fatalf("DecodeServerToken() error = %v", err)
	}
	return server.SigningSecret
}
```

Rename the remaining test helper/function identifiers in that file:

```go
generateCompactClientToken
validCompactClientTokenRaw
assertCompactClientTokenText
compactClientTokenAlphabetContains
```

Expected failing command:

```bash
go test ./pkg/derptun -run 'TestGenerateClientTokenFromServerToken|TestDecodeClientTokenRejectsMalformedInput|TestClientTokenRoundTrip' -count=1
```

Expected: FAIL with undefined identifiers such as `compactClientTokenPayloadLen` and references to removed invite names until the implementation is updated.

- [ ] **Step 3: Rename compact invite implementation to client-token implementation**

Rename the implementation file:

```bash
mv pkg/derptun/invite.go pkg/derptun/client_token.go
```

In `pkg/derptun/client_token.go`, change constants and function names from invite terminology to token terminology. The top of the file should look like:

```go
const (
	compactClientTokenRawLen     = 186
	compactClientTokenPayloadLen = 279
	compactClientTokenBase       = 41
	compactClientTokenVersion    = 1
	compactClientTokenKindTCP    = 1

	compactClientTokenVersionOffset = 0
	compactClientTokenKindOffset    = 1
	compactClientTokenSessionOffset = 2
	compactClientTokenClientOffset  = 18
	compactClientTokenTokenOffset   = 34
	compactClientTokenExpiryOffset  = 50
	compactClientTokenDERPOffset    = 58
	compactClientTokenQUICOffset    = 90
	compactClientTokenBearerOffset  = 122
	compactClientTokenProofOffset   = 154
)

var compactClientTokenAlphabet = []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+-./:")
```

Replace exported invite functions with unexported compact helpers:

```go
func encodeCompactClientToken(cred ClientCredential) (string, error) {
	if cred.ClientName != clientNameForID(cred.ClientID) {
		return "", ErrInvalidToken
	}
	proofMAC, err := hex.DecodeString(cred.ProofMAC)
	if err != nil || len(proofMAC) != 32 {
		return "", ErrInvalidToken
	}

	raw := make([]byte, compactClientTokenRawLen)
	raw[compactClientTokenVersionOffset] = compactClientTokenVersion
	raw[compactClientTokenKindOffset] = compactClientTokenKindTCP
	copy(raw[compactClientTokenSessionOffset:compactClientTokenClientOffset], cred.SessionID[:])
	copy(raw[compactClientTokenClientOffset:compactClientTokenTokenOffset], cred.ClientID[:])
	copy(raw[compactClientTokenTokenOffset:compactClientTokenExpiryOffset], cred.TokenID[:])
	binary.BigEndian.PutUint64(raw[compactClientTokenExpiryOffset:compactClientTokenDERPOffset], uint64(cred.ExpiresUnix))
	copy(raw[compactClientTokenDERPOffset:compactClientTokenQUICOffset], cred.DERPPublic[:])
	copy(raw[compactClientTokenQUICOffset:compactClientTokenBearerOffset], cred.QUICPublic[:])
	copy(raw[compactClientTokenBearerOffset:compactClientTokenProofOffset], cred.BearerSecret[:])
	copy(raw[compactClientTokenProofOffset:], proofMAC)

	return ClientTokenPrefix + compactClientTokenEncode(raw), nil
}

func decodeCompactClientToken(token string, now time.Time) (ClientCredential, error) {
	raw, err := compactClientTokenRaw(token)
	if err != nil {
		return ClientCredential{}, ErrInvalidToken
	}
	if !validCompactClientTokenHeader(raw) {
		return ClientCredential{}, ErrInvalidToken
	}

	cred := compactClientTokenCredential(raw)
	if !validClientCredential(cred) {
		return ClientCredential{}, ErrInvalidToken
	}
	if expired(now, cred.ExpiresUnix) {
		return ClientCredential{}, ErrExpired
	}
	return cred, nil
}
```

Update the remaining helper names in this file:

```go
compactClientTokenRaw
validCompactClientTokenHeader
compactClientTokenCredential
compactClientTokenEncode
compactClientTokenDecode
compactClientTokenDecodeTriple
compactClientTokenTripleValues
compactClientTokenDecodePair
compactClientTokenValue
```

Use `ClientTokenPrefix` in `compactClientTokenRaw`:

```go
func compactClientTokenRaw(token string) ([]byte, error) {
	if len(token) <= len(ClientTokenPrefix) || token[:len(ClientTokenPrefix)] != ClientTokenPrefix {
		return nil, ErrInvalidToken
	}
	encoded := token[len(ClientTokenPrefix):]
	if len(encoded) != compactClientTokenPayloadLen {
		return nil, ErrInvalidToken
	}
	return compactClientTokenDecode(encoded)
}
```

- [ ] **Step 4: Make token.go use compact client tokens**

In `pkg/derptun/token.go`, remove `ClientTokenPrefix = "dtc1_"` and set it to `DT1`:

```go
const (
	ServerTokenPrefix = "dts1_"
	ClientTokenPrefix = "DT1"
	TokenVersion      = 1
	DefaultServerDays = 180
	DefaultClientDays = 90
	ProtocolTCP       = "tcp"
	ProtocolUDP       = "udp"
)
```

Change the end of `GenerateClientToken`:

```go
client.BearerSecret = deriveClientBearerSecret(server.SigningSecret, client.ClientID)
client.ProofMAC = computeClientProofMAC(server.SigningSecret, client)
return EncodeClientCredential(client)
```

Change `EncodeClientCredential` and `DecodeClientToken`:

```go
func EncodeClientCredential(cred ClientCredential) (string, error) {
	if !validClientCredential(cred) {
		return "", ErrInvalidToken
	}
	return encodeCompactClientToken(cred)
}

func DecodeClientToken(encoded string, now time.Time) (ClientCredential, error) {
	return decodeCompactClientToken(encoded, now)
}
```

Remove the `encoding/base64` and `encoding/json` imports from `pkg/derptun/token_test.go` if the helper functions are no longer used there. Keep those imports in `pkg/derptun/token.go` because server tokens still use JSON.

- [ ] **Step 5: Run focused derptun token tests**

Run:

```bash
go test ./pkg/derptun -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit Task 1**

Use GitButler, not raw git:

```bash
but diff
```

From the `but diff` output, copy the change IDs for `pkg/derptun/token.go`, `pkg/derptun/client_token.go`, `pkg/derptun/token_test.go`, and `pkg/derptun/client_token_test.go`. Commit only those IDs with:

```bash
but commit codex/derptun-token-cleanup-spec -m "refactor: make DT1 the derptun client token" --changes
```

Append the copied comma-separated IDs immediately after `--changes`.

Expected: commit created on the existing `codex/derptun-token-cleanup-spec` branch; no unrelated files included.

## Task 2: Update Derptun CLI Token Sources And Serve UX

**Files:**
- Modify: `cmd/derptun/token_source.go`
- Modify: `cmd/derptun/serve.go`
- Modify: `cmd/derptun/open.go`
- Modify: `cmd/derptun/connect.go`
- Modify: `cmd/derptun/token.go`
- Modify: `cmd/derptun/root.go`
- Modify: `cmd/derptun/command_test.go`
- Modify: `cmd/derptun/token_test.go`
- Modify: `cmd/derptun/root_test.go`

- [ ] **Step 1: Write failing CLI tests for serve command output and DT1 token sources**

In `cmd/derptun/command_test.go`, add this helper:

```go
func newDerptunClientToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	server, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	return client
}
```

Add a command extractor:

```go
func extractDerptunOpenCommandToken(t *testing.T, output string) string {
	t.Helper()
	fields := strings.Fields(output)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--token" && strings.HasPrefix(fields[i+1], derptun.ClientTokenPrefix) {
			return fields[i+1]
		}
	}
	t.Fatalf("open command token not found in output %q", output)
	return ""
}
```

Add an ephemeral serve test:

```go
func TestRunServeWithoutTokenGeneratesEphemeralServerTokenAndPrintsOpenCommand(t *testing.T) {
	oldServe := derptunServe
	defer func() { derptunServe = oldServe }()
	called := false
	derptunServe = func(ctx context.Context, cfg session.DerptunServeConfig) error {
		called = true
		if !strings.HasPrefix(cfg.ServerToken, derptun.ServerTokenPrefix) {
			t.Fatalf("ServerToken = %q, want generated server token", cfg.ServerToken)
		}
		if cfg.TargetAddr != "127.0.0.1:8080" {
			t.Fatalf("TargetAddr = %q, want 127.0.0.1:8080", cfg.TargetAddr)
		}
		return nil
	}

	var stderr bytes.Buffer
	code := run([]string{"serve", "--tcp", "127.0.0.1:8080"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !called {
		t.Fatal("derptunServe was not called")
	}
	clientToken := extractDerptunOpenCommandToken(t, stderr.String())
	if _, err := derptun.DecodeClientToken(clientToken, time.Now()); err != nil {
		t.Fatalf("DecodeClientToken(open command token) error = %v", err)
	}
}
```

Update `TestRunServePassesServerTokenAndTCP` to also assert the printed open command token is derived from the supplied server token:

```go
var stderr bytes.Buffer
code := run([]string{"serve", "--token", serverToken, "--tcp", "127.0.0.1:22"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
if code != 0 {
	t.Fatalf("code = %d stderr=%s", code, stderr.String())
}
clientToken := extractDerptunOpenCommandToken(t, stderr.String())
clientCred, err := derptun.DecodeClientToken(clientToken, time.Now())
if err != nil {
	t.Fatalf("DecodeClientToken() error = %v", err)
}
assertDerivedDerptunClientCredential(t, serverToken, clientCred)
```

Update `TestRunOpenPrintsBindAddress`, `TestRunOpenReadsClientTokenFromStdin`, and `TestRunConnectReadsClientTokenFromFile` to use `newDerptunClientToken(t)` rather than `dtc1_*` literals.

Add a CLI role error test:

```go
func TestRunOpenRejectsServerTokenWithRoleError(t *testing.T) {
	serverToken := newDerptunServerToken(t)
	var stderr bytes.Buffer
	code := run([]string{"open", "--token", serverToken}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "server tokens are for derptun serve") {
		t.Fatalf("stderr = %q, want server-token role error", stderr.String())
	}
}
```

Add removed-format rejection coverage:

```go
func TestRunConnectRejectsRemovedClientTokenFormat(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"connect", "--token", "dtc1_legacy", "--stdio"}, strings.NewReader("payload"), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "invalid derptun token") {
		t.Fatalf("stderr = %q, want invalid token error", stderr.String())
	}
	if strings.Contains(stderr.String(), "dtc1") || strings.Contains(stderr.String(), "legacy") {
		t.Fatalf("stderr = %q, should not mention removed format", stderr.String())
	}
}
```

Expected failing command:

```bash
go test ./cmd/derptun -run 'TestRunServeWithoutToken|TestRunServePassesServerToken|TestRunOpen|TestRunConnect' -count=1
```

Expected: FAIL because `serve` still requires a token source and old `dtc1_*` literals are still accepted by stub tests.

- [ ] **Step 2: Add optional token-source and client-token validation helpers**

In `cmd/derptun/token_source.go`, add:

```go
func resolveOptionalTokenSource(stdin io.Reader, source tokenSource) (string, io.Reader, bool, error) {
	count := tokenSourceCount(source)
	if count > 1 {
		return "", stdin, false, errors.New("at most one of --token, --token-file, or --token-stdin may be set")
	}
	if count == 0 {
		return "", stdin, false, nil
	}
	token, reader, err := resolveTokenSource(stdin, source)
	return token, reader, true, err
}
```

In a new section of the same file, add client validation for CLI commands:

```go
func validateClientTokenForCLI(token string) error {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(token, derptunpkg.ServerTokenPrefix) {
		return errors.New("server tokens are for derptun serve; use a client token or copy the command printed by derptun serve")
	}
	if _, err := derptunpkg.DecodeClientToken(token, time.Now()); err != nil {
		return err
	}
	return nil
}
```

Add imports:

```go
	"time"

	derptunpkg "github.com/shayne/derphole/pkg/derptun"
```

- [ ] **Step 3: Implement serve default generation and printed open command**

In `cmd/derptun/serve.go`, update help text:

```go
Description: "Serve a local TCP service and print the command for the connecting side.",
Examples: []string{
	"derptun serve --tcp 127.0.0.1:8080",
	"derptun token server --days 365 > server.dts",
	"derptun serve --token-file server.dts --tcp 127.0.0.1:8080",
},
```

Change serve usage:

```go
Usage: "[--token TOKEN|--token-file PATH|--token-stdin] --tcp HOST:PORT [--force-relay] [--qr]",
```

Replace token source resolution in `runServe` with:

```go
token, _, hasToken, err := resolveOptionalTokenSource(stdin, tokenSource{
	Token:      parsed.SubCommandFlags.Token,
	TokenFile:  parsed.SubCommandFlags.TokenFile,
	TokenStdin: parsed.SubCommandFlags.TokenStdin,
})
if err != nil {
	_, _ = fmt.Fprintln(stderr, err)
	_, _ = fmt.Fprint(stderr, serveHelpText())
	return 2
}
if !hasToken {
	token, err = derptunpkg.GenerateServerToken(derptunpkg.ServerTokenOptions{})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
}
clientToken, err := deriveServeClientToken(token, time.Now())
if err != nil {
	_, _ = fmt.Fprintln(stderr, err)
	return 1
}
writeServeOpenCommand(stderr, clientToken)
if parsed.SubCommandFlags.QR {
	writeServeQRInstruction(stderr, clientToken)
}
```

Rename derivation helpers:

```go
func deriveServeClientToken(serverToken string, now time.Time) (string, error) {
	server, err := derptunpkg.DecodeServerToken(serverToken, now)
	if err != nil {
		return "", err
	}
	expires := now.Add(time.Duration(derptunpkg.DefaultClientDays) * 24 * time.Hour)
	serverExpires := time.Unix(server.ExpiresUnix, 0)
	if serverExpires.Before(expires) {
		expires = serverExpires
	}
	return derptunpkg.GenerateClientToken(derptunpkg.ClientTokenOptions{
		Now:         now,
		ServerToken: serverToken,
		Expires:     expires,
	})
}
```

Add command and QR writers:

```go
func writeServeOpenCommand(stderr io.Writer, clientToken string) {
	if stderr == nil {
		return
	}
	_, _ = fmt.Fprintln(stderr, "On the other machine, run:")
	_, _ = fmt.Fprintf(stderr, "  npx -y derptun@latest open --token %s\n", clientToken)
}

func writeServeQRInstruction(stderr io.Writer, clientToken string) {
	if stderr == nil {
		return
	}
	_, _ = fmt.Fprintln(stderr, "Scan this QR code with a derptun-compatible mobile app to open this TCP tunnel:")
	_, _ = fmt.Fprintf(stderr, "Token: %s\n", clientToken)
	qrterminal.GenerateHalfBlock(clientToken, qrterminal.M, stderr)
}
```

Remove `maybeWriteServeQR`, `serveQRInvite`, and `EncodeClientInvite` usage.

- [ ] **Step 4: Validate client token inputs in open and connect**

In `cmd/derptun/open.go`, after `resolveTokenSource`, add:

```go
if err := validateClientTokenForCLI(token); err != nil {
	_, _ = fmt.Fprintln(stderr, err)
	_, _ = fmt.Fprint(stderr, openHelpText())
	return 2
}
```

In `cmd/derptun/connect.go`, after `resolveTokenSource`, add:

```go
if err := validateClientTokenForCLI(token); err != nil {
	_, _ = fmt.Fprintln(stderr, err)
	_, _ = fmt.Fprint(stderr, connectHelpText())
	return 2
}
```

- [ ] **Step 5: Update CLI docs and token tests**

In `cmd/derptun/token_test.go`, update all client-token prefix assertions:

```go
if !strings.HasPrefix(strings.TrimSpace(stdout.String()), "DT1") {
	t.Fatalf("stdout = %q, want client token", stdout.String())
}
```

In `cmd/derptun/open.go`, change examples from `client.dtc` to `client.dt1`.

In `cmd/derptun/connect.go`, keep `connect` as supported but remove SSH-forwarded marketing from examples. Use a generic stdin/stdout example:

```go
Examples: []string{
	"printf 'GET / HTTP/1.0\\r\\n\\r\\n' | derptun connect --token-file client.dt1 --stdio",
	"printf '%s\\n' \"$DERPTUN_CLIENT_TOKEN\" | derptun connect --token-stdin --stdio",
},
```

In `cmd/derptun/token.go`, keep server/client token command examples but use `client.dt1` where a filename appears.

In `cmd/derptun/root.go`, use:

```go
Examples: []string{
	"derptun serve --tcp 127.0.0.1:8080",
	"derptun open --token DT1...",
	"derptun token server > server.dts",
	"derptun token client --token-file server.dts > client.dt1",
	"derptun open --token-file client.dt1 --listen 127.0.0.1:8081",
	"derptun netcheck",
},
```

- [ ] **Step 6: Run focused CLI tests**

Run:

```bash
go test ./cmd/derptun -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit Task 2**

Use GitButler:

```bash
but diff
```

From the `but diff` output, copy the change IDs for `cmd/derptun/*` files changed in this task. Commit only those IDs with:

```bash
but commit codex/derptun-token-cleanup-spec -m "feat: print derptun open command from serve" --changes
```

Append the copied comma-separated IDs immediately after `--changes`.

Expected: commit created on the existing branch; no docs or shared package changes accidentally included.

## Task 3: Update Shared Session, Derpssh, And Mobile Consumers

**Files:**
- Modify: `pkg/session/derptun.go`
- Modify: `pkg/session/derptun_test.go`
- Modify: `pkg/session/derptun_app_test.go`
- Modify: `pkg/derpssh/session/invite.go`
- Modify: `pkg/derpssh/session/share_connect_test.go`
- Modify: `pkg/derpholemobile/mobile.go`
- Modify: `pkg/derpholemobile/mobile_test.go`

- [ ] **Step 1: Write failing shared-consumer tests for DT1 and removed dtc1**

In `pkg/session/derptun_test.go`, update `TestDerptunRejectsWrongTokenRoles` to include the removed old client format:

```go
if err := DerptunConnect(ctx, DerptunConnectConfig{ClientToken: "dtc1_legacy", StdioIn: strings.NewReader("x"), StdioOut: io.Discard}); !errors.Is(err, derptun.ErrInvalidToken) {
	t.Fatalf("DerptunConnect(old client token) error = %v, want ErrInvalidToken", err)
}
```

In `pkg/derpssh/session/share_connect_test.go`, update `TestInviteRoundTrip` to use a generated client token:

```go
func TestInviteRoundTrip(t *testing.T) {
	clientToken := newTestDerptunClientToken(t)
	encoded, err := EncodeInvite(Invite{ClientToken: clientToken})
	if err != nil {
		t.Fatalf("EncodeInvite() error = %v", err)
	}
	if !strings.HasPrefix(encoded, InvitePrefix) {
		t.Fatalf("invite = %q, want %s prefix", encoded, InvitePrefix)
	}
	decoded, err := DecodeInvite(encoded)
	if err != nil {
		t.Fatalf("DecodeInvite() error = %v", err)
	}
	if decoded.ClientToken != clientToken {
		t.Fatalf("ClientToken = %q, want %q", decoded.ClientToken, clientToken)
	}
}
```

Add helper:

```go
func newTestDerptunClientToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	server, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}
	return client
}
```

Add derpssh old-format rejection:

```go
func TestDecodeInviteRejectsRemovedClientTokenFormat(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"client_token":"dtc1_legacy"}`))
	if _, err := DecodeInvite(InvitePrefix + payload); err == nil {
		t.Fatal("DecodeInvite(old client token) error = nil, want error")
	}
}
```

In `pkg/derpholemobile/mobile_test.go`, replace `TestParsePayloadClassifiesCompactInviteAsTCP` with:

```go
func TestParsePayloadClassifiesClientTokenAsTCP(t *testing.T) {
	now := time.Now()
	server, err := derptun.GenerateServerToken(derptun.ServerTokenOptions{Now: now, Days: 7})
	if err != nil {
		t.Fatalf("GenerateServerToken() error = %v", err)
	}
	client, err := derptun.GenerateClientToken(derptun.ClientTokenOptions{Now: now, ServerToken: server, Days: 3})
	if err != nil {
		t.Fatalf("GenerateClientToken() error = %v", err)
	}

	parsed, err := ParsePayload(client)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	if parsed.Kind() != "tcp" {
		t.Fatalf("Kind() = %q, want tcp", parsed.Kind())
	}
	if parsed.Token() != client {
		t.Fatalf("Token() = %q, want original client token", parsed.Token())
	}
}
```

Expected failing command:

```bash
go test ./pkg/session ./pkg/derpssh/session ./pkg/derpholemobile -run 'TestDerptunRejectsWrongTokenRoles|TestInviteRoundTrip|TestDecodeInviteRejectsRemovedClientTokenFormat|TestParsePayloadClassifiesClientTokenAsTCP' -count=1
```

Expected: FAIL until derpssh validation and mobile parsing are updated.

- [ ] **Step 2: Update derpssh invite validation**

In `pkg/derpssh/session/invite.go`, replace prefix-only validation with decode validation:

```go
func validInviteClientToken(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	_, err := derptun.DecodeClientToken(token, time.Now())
	return err == nil
}
```

Add `time` to imports.

In `pkg/derpssh/session/share_connect_test.go`, replace every stubbed `"dtc1_test"` generated client token with a real token created before assigning the stub:

```go
clientToken := newTestDerptunClientToken(t)
generateClientToken = func(derptun.ClientTokenOptions) (string, error) { return clientToken, nil }
```

When assertions compare `cfg.ClientToken`, compare against the local `clientToken` variable:

```go
if cfg.ClientToken != clientToken {
	t.Fatalf("ClientToken = %q, want %q", cfg.ClientToken, clientToken)
}
```

- [ ] **Step 3: Update mobile payload parsing**

In `pkg/derpholemobile/mobile.go`, replace the standalone compact-invite branch in `ParsePayload`:

```go
if strings.HasPrefix(payload, derptun.ClientTokenPrefix) {
	if _, err := derptun.DecodeClientToken(payload, time.Now()); err != nil {
		return nil, err
	}
	return &ParsedPayload{kind: "tcp", token: payload}, nil
}
```

Remove the call to `derptun.EncodeClientCredential` from `ParsePayload`.

In `pkg/derpholemobile/mobile_test.go`, update direct tunnel stubs to use neutral non-old strings where parsing is not involved, or use generated `DT1...` tokens where parsing is involved. For QR URL payload tests, use `tcp-token` or a generated `DT1...` token instead of `dtc1_test`.

- [ ] **Step 4: Run focused shared-consumer tests**

Run:

```bash
go test ./pkg/session ./pkg/derpssh/session ./pkg/derpholemobile -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit Task 3**

Use GitButler:

```bash
but diff
```

From the `but diff` output, copy the change IDs for `pkg/session`, `pkg/derpssh/session`, and `pkg/derpholemobile` files changed in this task. Commit only those IDs with:

```bash
but commit codex/derptun-token-cleanup-spec -m "refactor: move shared users to DT1 client tokens" --changes
```

Append the copied comma-separated IDs immediately after `--changes`.

Expected: commit created on the existing branch.

## Task 4: Clean Docs, Help, And Smoke Scripts

**Files:**
- Modify: `README.md`
- Modify: `scripts/smoke-remote-derptun.sh`
- Search and update any remaining source docs found by `rg`.

- [ ] **Step 1: Check remaining old-format references**

Run:

```bash
rg -n 'dtc1_|client\.dtc|CompactInvite|EncodeClientInvite|DecodeClientInvite|compact invite' README.md cmd pkg scripts docs --glob '!docs/superpowers/plans/**' --glob '!docs/superpowers/specs/**'
```

Expected before cleanup: matching lines from README, scripts, tests, or code. Expected after cleanup: no output and exit code 1 from `rg`.

- [ ] **Step 2: Use Caveman skill before README edits**

Read the required skill before editing README:

```bash
sed -n '1,220p' /Users/shayne/.agents/skills/caveman/SKILL.md
```

Expected: instructions loaded. Keep README prose tight and technical, but not broken English.

- [ ] **Step 3: Rewrite the README derptun section**

In `README.md`, replace the `### Long-Lived TCP Tunnels` section with copy shaped like:

````markdown
### TCP Tunnels

`derptun` exposes a local TCP service without requiring either side to open an inbound port. Start with a one-off tunnel:

On the serving machine:

```bash
npx -y derptun@latest serve --tcp 127.0.0.1:3000
```

`serve` prints the command for the other side:

```bash
npx -y derptun@latest open --token DT1...
```

Run that command on the connecting machine. It opens a local listener and forwards connections through the tunnel.

For a persistent tunnel, keep a server token on the serving machine:

```bash
npx -y derptun@latest token server > server.dts
npx -y derptun@latest serve --token-file server.dts --tcp 127.0.0.1:3000
```

To provision a client token ahead of time:

```bash
npx -y derptun@latest token client --token-file server.dts > client.dt1
npx -y derptun@latest open --token-file client.dt1 --listen 127.0.0.1:3001
```

The server token is serving authority. Keep it on the serving machine or in a secret manager. Client tokens can connect until expiry, but cannot serve or mint tokens.

Server tokens default to 180 days. Client tokens default to 90 days and cannot outlive their server token. Set a relative lifetime with `--days`, or use an absolute expiry:

```bash
npx -y derptun@latest token server --expires 2026-05-01T00:00:00Z > server.dts
npx -y derptun@latest token client --token-file server.dts --expires 2026-04-25T00:00:00Z > client.dt1
```

Use `--token TOKEN` for inline one-off commands. Prefer `--token-file PATH` for durable tokens. `--token-stdin` reads the token from the first stdin line.
````

Do not include SSH as the primary derptun use case in this section.

- [ ] **Step 4: Update smoke script client token filename**

In `scripts/smoke-remote-derptun.sh`, change:

```bash
client_token_file="${tmp}/client.dtc"
```

to:

```bash
client_token_file="${tmp}/client.dt1"
```

No behavior change is needed; `derptun token client` now writes the canonical token to that file.

- [ ] **Step 5: Confirm removed public names are gone**

Run:

```bash
rg -n 'dtc1_|client\.dtc|CompactInvite|EncodeClientInvite|DecodeClientInvite|DecodeClientInvite|compact invite' README.md cmd pkg scripts --glob '!**/*_test.go'
```

Expected: no output.

Run the broader test/reference check:

```bash
rg -n 'dtc1_|client\.dtc|CompactInvite|EncodeClientInvite|DecodeClientInvite|compact invite' README.md cmd pkg scripts --glob '!docs/superpowers/plans/**' --glob '!docs/superpowers/specs/**'
```

Expected: no output except intentionally historical docs under `docs/superpowers/` if the command is broadened to include those directories.

- [ ] **Step 6: Commit Task 4**

Use GitButler:

```bash
but diff
```

From the `but diff` output, copy the change IDs for `README.md`, `scripts/smoke-remote-derptun.sh`, and any other docs/help files changed in this task. Commit only those IDs with:

```bash
but commit codex/derptun-token-cleanup-spec -m "docs: show derptun serve invite flow" --changes
```

Append the copied comma-separated IDs immediately after `--changes`.

Expected: commit created on the existing branch.

## Task 5: Full Verification And Branch Cleanup

**Files:**
- No new files expected.
- May modify tests only if full-suite failures reveal missed old-token references.

- [ ] **Step 1: Run focused package checks**

Run:

```bash
go test ./pkg/derptun ./cmd/derptun ./pkg/session ./pkg/derpssh/session ./pkg/derpholemobile -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full test suite**

Run:

```bash
mise run test
```

Expected: PASS.

- [ ] **Step 3: Run local smoke if the suite passes**

Run:

```bash
mise run smoke-local
```

Expected: PASS. If this smoke does not exercise derptun, note that explicitly in the final implementation report.

- [ ] **Step 4: Optional remote derptun smoke if time/network allow**

If a remote host is available and this branch is ready for release-grade confidence, run:

```bash
REMOTE_HOST=hetz mise run smoke-remote
```

or the repository's derptun-specific smoke target if one is configured. If no target exists, run the script directly after building:

```bash
scripts/smoke-remote-derptun.sh hetz
```

Expected: PASS with direct-path evidence when public/Tailscale test settings are configured for the host.

- [ ] **Step 5: Final old-format audit**

Run:

```bash
rg -n 'dtc1_|client\.dtc|CompactInvite|EncodeClientInvite|DecodeClientInvite|compact invite' README.md cmd pkg scripts --glob '!docs/superpowers/plans/**' --glob '!docs/superpowers/specs/**'
```

Expected: no output.

- [ ] **Step 6: Check branch state**

Run:

```bash
but status
but pull --check
```

Expected: branch contains only this spec/plan/implementation work and target `origin/main` is up to date or reports cleanly.

- [ ] **Step 7: Commit any missed fixes**

If verification required changes, commit them with GitButler:

```bash
but diff
```

From the `but diff` output, copy only the change IDs for verification fixes that belong to this task. Commit those IDs with:

```bash
but commit codex/derptun-token-cleanup-spec -m "test: cover canonical derptun client tokens" --changes
```

Append the copied comma-separated IDs immediately after `--changes`.

Expected: no uncommitted changes remain except unrelated user work.

## Self-Review Notes

- Spec coverage: Tasks cover canonical token API cleanup, no-compat old format behavior, serve default command output, persistent tokens, open/connect token-source flags, QR behavior, derpssh/mobile/shared consumers, README/help/script cleanup, and verification.
- Completeness scan: No open-ended markers or vague "add tests" steps remain; each test/code step names concrete files, snippets, and commands.
- Type consistency: Public names used in the plan are `ClientTokenPrefix`, `GenerateClientToken`, `DecodeClientToken`, `EncodeClientCredential`, `ServerTokenPrefix`, `deriveServeClientToken`, `validateClientTokenForCLI`, and existing session config fields.
