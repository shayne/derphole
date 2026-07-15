# derpssh Auto-Accept Design

**Date:** 2026-07-15

**Status:** Approved

## Goal

Let a `derpssh share` host choose a standing read-only or read/write policy for
the lifetime of the share process. Any join request carrying the valid invite
is accepted immediately, so the host approval modal does not open.

The existing interactive approval flow remains the default.

## Command Line

The host selects the policy with one value-bearing flag:

```text
derpssh share --auto-accept read
derpssh share --auto-accept write
```

`--auto-accept=read` and `--auto-accept=write` are equivalent forms, matching
the command's existing value-flag parsing.

Only the exact lowercase values `read` and `write` are valid. A missing or
invalid value prints an actionable error plus share usage and exits with status
2. Omitting the flag preserves the current approval modal and terminal prompt.

The selected policy applies to every join attempt while that `share` process
is alive. derpssh still permits only one active guest. After admission, the
host can promote, demote, or kick the guest with the existing controls.

## Configuration and Approval Selection

The CLI maps the validated value to a protocol role and passes it through a new
field on `session.ShareConfig`. The zero value means interactive approval.
`Share` defensively rejects any nonzero role other than `read` or `write` before
creating an invite or starting a PTY.

The share host selects one of two implementations of the existing `Approval`
interface:

- no configured role: keep the current console-backed approval implementation;
- configured role: use `StaticApproval` with that role.

The automatic approval is wrapped with the existing start-on-join behavior.
This matters when the host is still looking at the plain invite interstitial:
the first join attempt must start the host TUI before returning the automatic
decision. The TUI starts normally, but no approval request is sent to it and no
approval modal is created.

The production flag does not reuse or expose `DERPSSH_TEST_AUTO_APPROVE`. That
environment variable remains restricted to the test harness.

## Runtime Behavior

The host sends the normal accepted decision with the configured role. Nothing
changes in the wire protocol or invite token.

Read-only remains enforced by the host runtime: the guest receives terminal
output and chat but guest terminal input is rejected. Read/write permits guest
terminal input through the existing role checks. Automatic admission does not
bypass those checks.

If the guest disconnects and the share remains available for another join, the
same configured role is used again. The policy is immutable for new admissions
until the host process exits, although the active guest's role can still be
changed through the TUI.

## Errors and Compatibility

- `--auto-accept` without a value is a CLI usage error.
- Values other than `read` and `write` are CLI usage errors.
- An invalid programmatic `ShareConfig` role fails before network or PTY side
  effects.
- No flag means byte-for-byte compatible invite generation and the current
  interactive approval path.
- `--force-relay`, `--register`, and `--registry` remain independent and can be
  combined with `--auto-accept`.

## Security

Auto-accept is deliberately a role policy, not an identity policy. Anyone who
has the valid invite and reaches the running host is admitted without a manual
decision. `--auto-accept write` therefore grants shell input to any such guest.
The flag is local to the host process and is not encoded into the invite.

The host-side role checks remain authoritative, and the host retains the
existing promote, demote, and kick controls after admission.

## Testing

CLI tests cover:

- both space-separated and equals forms;
- propagation of read and write roles into `ShareConfig`;
- missing and invalid values returning status 2 with usage;
- unchanged parsing when the flag is absent;
- combinations with the existing share flags.

Session tests cover:

- automatic read and write decisions;
- the same decision being returned for repeated join attempts;
- starting the host TUI from the invite interstitial without opening the
  approval modal;
- the interactive approval seam remaining active when no role is configured;
- defensive rejection of invalid programmatic roles;
- read-only input rejection and read/write input delivery through the host
  runtime.

The full repository checks and local derpssh smoke flow run after the focused
tests.

## Documentation

The `derpssh share` usage string and README terminal-sharing section show both
forms. The README states plainly that `--auto-accept write` grants terminal
control to every admitted join attempt for that running share process.

## Non-Goals

- Adding an auto-accept option to `derpssh connect`.
- Encoding approval policy in an invite or token.
- Adding a production approval environment variable.
- Adding auto-deny or identity-based admission rules.
- Removing the host's post-admission role and kick controls.
