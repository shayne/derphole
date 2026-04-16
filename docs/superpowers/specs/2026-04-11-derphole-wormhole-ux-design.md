# `derphole` wormhole-shaped UX design

Date: 2026-04-11

## Goal

Add a second first-class CLI, `derphole`, to this repository.

`derphole` should feel familiar to users of `magic-wormhole`, but it must stay on the existing `derphole` architecture:

- same DERP rendezvous/bootstrap model
- same direct-path promotion and fallback behavior
- same self-contained bearer-token session model
- same no-extra-service deployment story

The repo should support `derphole` and `derphole` long-term without forking the transport stack or maintaining two unrelated release systems.

## Product split

Keep the two CLIs intentionally different.

`derphole` remains the lower-level transport-oriented tool:

- raw byte-stream transfer with `listen` / `send`
- service sharing with `share` / `open`
- terminology centered on tokens, DERP, direct paths, and transport behavior

`derphole` becomes the human-oriented transfer tool:

- wormhole-shaped command set
- transfer semantics for text, files, directories, and SSH key exchange
- friendlier prompts and instructional output
- the same technically honest wording as `derphole` where the underlying model matters

This is not a compatibility layer for the `magic-wormhole` protocol. It is a familiar UX built on `derphole` transport.

## Non-goals

- Do not add a mailbox service or any short human-code rendezvous system.
- Do not become protocol-compatible with `magic-wormhole`.
- Do not move `share` / `open` into `derphole` in v1.
- Do not replace `derphole` with `derphole`.
- Do not duplicate DERP, traversal, or direct-transfer logic under a second implementation.
- Do not keep wormhole options that only make sense with wormhole's mailbox/code model, such as `--code-length`.

## User-facing surface

`derphole` should copy the main `magic-wormhole` interaction shape while keeping technically honest naming.

### Top-level commands

- `derphole send`
- `derphole receive`
- `derphole tx` alias for `send`
- `derphole rx` alias for `receive`
- `derphole recv` alias for `receive`
- `derphole recieve` alias for `receive` to match wormhole muscle memory
- `derphole ssh invite`
- `derphole ssh accept`
- `derphole version`
- `derphole help`

### Transfer flows

Sender-first flow:

1. `derphole send` creates a token.
2. It prints a friendly instruction such as `On the other machine, run: derphole receive <token>`.
3. It then sends text, file, directory, or stdin payload once the receiver connects.

Receiver-first flow:

1. `derphole receive --allocate` creates and prints a token.
2. The sender uses `derphole send --token <token> ...`.

Interactive receive:

- `derphole receive` with no positional token should prompt on a TTY.
- Non-interactive use should still allow `derphole receive <token>`.

### Main features in v1

Text transfer:

- `derphole send --text 'hello'`
- `derphole send --text -` to read text from stdin
- `derphole receive --only-text` to refuse file or directory payloads

File transfer:

- `derphole send ./file.iso`
- receiver sees sender-suggested filename
- `--output` lets the receiver override the output path
- `--accept-file` suppresses interactive confirmation

Directory transfer:

- `derphole send ./photos`
- receiver restores the directory tree under the suggested top-level name or under `--output`

SSH key exchange:

- `derphole ssh invite`
- `derphole ssh accept <token>`
- optional target user for invite side
- optional key-file selection and confirmation behavior for accept side

Verification and UX:

- `--verify` should display a verification string on both ends
- `--hide-progress` should suppress the progress display
- progress output should default to TTY-friendly behavior and stay quiet in non-interactive pipelines

### Terminology

The command shape should feel like wormhole. The wording should stay honest to `derphole`.

Use:

- `token`, not `code`
- `receive`, not `listen`
- `DERP` / `direct` only in verbose or technical output

Do not expose wormhole-specific wording that implies a mailbox service, a short shared code, or a separate transit relay product.

## Architecture

Use a hybrid of a new product layer plus targeted shared abstraction cleanup.

### 1. Keep transport in the existing core

The following remain the source of truth:

- `pkg/session`
- `pkg/token`
- `pkg/derpbind`
- `pkg/rendezvous`
- `pkg/traversal`
- `pkg/transport`
- direct UDP / QUIC / relay behavior already implemented for `derphole`

`derphole` must call into these existing layers rather than reimplement transport decisions.

### 2. Add a new `pkg/derphole` application layer

Add a new product-layer package family responsible for wormhole-shaped semantics above the raw stream transport.

Suggested package split:

- `pkg/derphole`
  - public orchestration API used by `cmd/derphole`
- `pkg/derphole/protocol`
  - application-level message headers and metadata
- `pkg/derphole/archive`
  - directory send/receive helpers built around tar streaming
- `pkg/derphole/ssh`
  - SSH invite/accept workflows and authorized-keys updates

This layer owns:

- deciding whether a transfer is text, file, directory, or SSH
- marshaling transfer metadata
- prompting and confirmation rules
- receive-side sink selection
- verification-string derivation

This layer does not own:

- token issuance semantics
- DERP rendezvous
- direct path selection
- packet pacing
- relay/direct upgrade logic

### 3. Use a small application protocol over the existing byte stream

`derphole`'s current `send` / `listen` is a raw byte pipe. `derphole` needs structured payloads.

Define a compact application header at the start of each `derphole` transfer. The header should describe:

- transfer kind: `text`, `file`, `directory_tar`, `ssh_invite`, `ssh_accept`
- sender-suggested name when applicable
- known size when available
- verification material identifier
- SSH-specific metadata when applicable

After the header, the payload remains a stream:

- text payload bytes
- file bytes
- tar stream bytes for directories
- structured SSH payload for invite/accept exchanges

The protocol should be versioned so `derphole` can evolve without entangling raw `derphole` transfers.

The raw transport stays streaming. `derphole` must not require buffering the whole file or directory in RAM.

### 4. Refactor only the shared pieces that benefit both CLIs

Do not force all of `derphole` onto the new `derphole` product protocol.

Do extract shared pieces where permanent dual-CLI support would otherwise cause drift:

- shared version/build info helpers
- shared CLI telemetry-level handling
- shared packaging metadata generation
- shared launcher template logic for npm packaging
- shared release asset staging helpers

The boundary should be:

- transport core shared by both products
- app protocol owned by `derphole`
- raw pipe UX remains valid in `derphole`

## Feature design details

### Text transfer

Text mode is a lightweight header plus streamed body.

Receive behavior:

- if output is a TTY, print the text body naturally
- if output is redirected, write bytes without extra decoration
- `--only-text` accepts only `text` and rejects `file`, `directory_tar`, and SSH payloads

### File transfer

File mode sends:

- a header with the suggested filename and optional size
- the file bytes as a stream

Receive behavior:

- prompt before writing unless `--accept-file` is set or output is explicitly forced
- if `--output` names an existing directory, place the file inside it using the suggested filename
- if `--output` names a file path, write there directly

### Directory transfer

Directory mode should use tar streaming, not a custom tree assembler.

Reasoning:

- preserves streaming behavior
- avoids inventing a second archive format
- maps cleanly onto stdin/stdout transport
- keeps memory bounded

The protocol header identifies the transfer as a directory and carries the top-level name. The payload is a tar stream rooted at that directory.

Receive behavior:

- unpack directly to the chosen destination
- preserve file modes and relative layout within the extracted directory
- reject unsafe tar paths such as absolute paths or `..` traversal

### SSH invite / accept

`derphole ssh invite` mirrors the wormhole product intent: "I want your public key added to my authorized_keys".

Design:

- invite side creates a token and waits for a structured SSH accept payload
- accept side chooses a public key and sends:
  - key type
  - key identifier or comment
  - public key material
- invite side validates and appends to the target authorized_keys file

Constraints:

- no shelling out to `ssh-copy-id`
- no hidden remote execution
- file writes happen only on the invite side's local filesystem
- default target is the current user's `~/.ssh/authorized_keys`
- `--user` allows choosing another local user's authorized_keys path when permissions permit

### Verification string

`--verify` should derive a short human-comparable verification string from token/session material that both ends already know after connection setup.

It does not replace the bearer token. It is only an optional human check that both sides joined the same session.

## CLI design principles

`derphole` should feel conversational without becoming noisy.

Normal mode:

- sender prints the token and the next-step instruction
- receiver prints only what is needed to confirm acceptance and where output went
- pipeline-friendly mode stays quiet on stdout except for transfer payload

Verbose mode:

- expose the same transport truth that `derphole` uses
- do not invent wormhole-style terminology for transport internals

The user should be able to trust that `derphole` is a friendlier frontend, not a different network stack.

## Packaging and release design

The repo should publish two products from one release workflow.

### Binary assets

GitHub releases should include tarballs for both binaries:

- `derphole-<os>-<arch>.tar.gz`
- `derphole-<os>-<arch>.tar.gz`

### npm packages

Publish two npm packages:

- `derphole`
- `derphole`

Both should be built from one workflow, with production releases on `v*` tags and `dev` publishes from `main`, matching the current `derphole` behavior.

### Packaging structure

Refactor the npm build process so it becomes package-aware instead of hard-coded for `derphole`.

Expected direction:

- package template inputs per product under `packaging/npm/`
- a shared build script that can stage one named package at a time
- distinct output directories such as:
  - `dist/npm-derphole`
  - `dist/npm-derphole`
- launcher scripts that vend the correct binary for each package

### Bootstrap publish

Update the bootstrap runbook to include first publish steps for `derphole`.

The runbook should explicitly cover:

- first manual npm publish for `derphole`
- dry-run validation for both packages
- post-bootstrap trusted publishing behavior for both packages

## Documentation design

The repo now has two user-facing CLIs, so docs must stop assuming there is only one entrypoint.

Update:

- top-level `README.md` to describe the repo as containing both `derphole` and `derphole`
- command examples so users can tell which CLI they should reach for
- release docs so both binary and npm outputs are documented

Keep the distinction crisp:

- use `derphole` examples for raw transport and service sharing
- use `derphole` examples for human-driven transfer and SSH exchange

## Testing strategy

### Unit tests

Add focused tests for:

- transfer header encode/decode
- text/file/directory/SSH dispatch decisions
- receive-side output path resolution
- tar extraction safety rules
- SSH authorized_keys append logic
- alias and help surface for `send` / `receive` / `tx` / `rx` / `ssh`

### End-to-end tests

Add local CLI tests for:

- `derphole send --text` to `derphole receive`
- file transfer
- directory transfer
- `receive --allocate` with `send --token`
- SSH invite/accept happy path using temp-home fixtures

### Packaging / CI tests

Release automation should verify:

- both binaries report the workflow version string
- both npm packages dry-run publish successfully
- both vendored launchers run `version`

## Acceptance

This design is successful when:

- `derphole` feels like a wormhole-style CLI for the main user workflows
- it still uses the current `derphole` transport architecture
- the repo can release `derphole` and `derphole` together from one workflow
- the long-term maintenance burden is one transport stack plus two product layers, not two transport stacks

## Explicit decisions

- `derphole` v1 is strictly wormhole-shaped. No `share` / `open`.
- Short human codes are out of scope.
- Terminology stays technically honest: token, not code.
- File, directory, text, and SSH features are all in scope for v1.
- The correct long-term design is a new `derphole` product layer plus selective shared refactors, not a cosmetic wrapper and not a whole-stack fork.
