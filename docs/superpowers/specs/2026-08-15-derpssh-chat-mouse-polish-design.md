# Derpssh Chat and Mouse Polish Design

## Goal

Make the derpssh top bar, chat panel, pointer behavior, and dialogs feel native in Ghostty while preserving the existing declarative scene architecture.

## Physical scene

A developer sharing a shell in Ghostty, switching between bright daytime and low-light evening, needs UI chrome to recede while text and interaction states stay unmistakable.

## Approved shape

- Keep the existing `App`, scene compositor, semantic layer targets, and modal stack.
- Remove the chat panel's inner header, peer count, top border, and close action. The top-bar `Chat` action is the only chat toggle.
- Label local messages `you`; label remote messages with the remote display handle. Preserve `Local` when a transport echo is absorbed.
- Use orange for local message identity and blue for remote identity in both color schemes.
- Give each visible message one full-width rectangular surface. Hover, press, and copied feedback affect the complete visible block, including blank cells and wrapped rows.
- Keep click-to-copy on the message body.
- Give top-bar `Chat`, the host peer read/write control, and modal buttons distinct hover and pressed states.
- Use Ghostty-compatible OSC 22 pointer shapes: `text` over the terminal, `ew-resize` over the divider, and `default` elsewhere. Restore `default` when the program exits.
- Preserve divider pointer capture across host-size acknowledgements until the left button is released.
- Base light surfaces and text on the restrained neutral scale already used by the current reference, with readable burnt-orange local and blue remote accents.
- Use a visible warm composer cursor in dark mode. Do not rely on cursor alpha, which terminal cursor APIs do not expose consistently.
- Dim the complete scene behind a modal, then render the modal panel and controls above it.

## Interaction details

- Hover follows the semantic layer under cell-motion events.
- Modal hover is allowed only for the front modal's valid controls; the blocker remains non-interactive except where an existing passive dismissal explicitly permits it.
- Press feedback begins on a matching left press and clears on release, modal replacement, or cancellation.
- Divider drag remains captured even when a resize command causes a runtime state update.
- The console uses an I-beam pointer on both host and guest. Chrome, chat, composer, and dialog controls use the normal arrow; the divider uses horizontal resize.

## Verification

- Regression tests cover message identity and echo absorption, full-cell message painting, header removal, top-bar and modal hover, modal dimming, pointer shape selection, dark cursor color, light palette roles, and divider capture.
- Run focused TUI tests, `mise run check:fast`, the final exhaustive `mise run check`, and repository diff checks before publication.
