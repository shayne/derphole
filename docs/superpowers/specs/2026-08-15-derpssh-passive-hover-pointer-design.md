# derpssh Passive Hover and Pointer Design

## Goal

Make mouse feedback dependable in modern terminals: passive movement reveals hover states, the terminal pane uses an I-beam, ordinary UI uses an arrow, the chat divider uses horizontal resize, and every drag release immediately restores the pointer appropriate to the release position.

## Findings

The TUI currently requests Bubble Tea cell-motion reporting. That mode reports movement only while a button is held, so top-bar and modal hover state cannot react to passive movement. Pointer-shape updates are also limited to motion events and use the captured divider target even after release, leaving `ew-resize` active when no later passive motion event can arrive.

Ghostty supports OSC 22 from version 1.0 and interprets standardized CSS cursor names. The existing `github.com/charmbracelet/x/ansi` helper already emits compatible OSC 22 sequences. The local reference TUI models hover as explicit mouse-enter/mouse-leave state and paints a stronger element surface over the panel surface.

## Design

- Request `tea.MouseModeAllMotion` whenever the main TUI is interactive. Keep mouse reporting disabled only for the existing invite screen.
- Continue hit-testing semantic scene layers. Passive `tea.MouseMotionMsg` updates the hover target and maps `targetTerminal` to `text`, `targetDivider` to `ew-resize`, and every other surface, including modal controls, to `default`.
- Keep divider capture during a drag so resizing remains smooth even when the pointer leaves the divider cell.
- On release, route the event through the captured target first, then re-hit-test the actual release coordinates after capture clears. Update both hover and pointer shape from that live target immediately.
- Send `default` once after the first window-size update, after the initial view has configured terminal mouse reporting. This prevents the host from inheriting Ghostty's pre-app I-beam while avoiding repeated escape sequences.
- Retain the existing hover palette: panel at rest, element surface on hover, pressed surface while held. The missing behavior is event delivery rather than a new visual vocabulary.

## Verification

- Test that interactive views request all-motion reporting while the invite screen still disables reporting.
- Test passive top-bar and modal motion changes both state and rendered ANSI without changing text or geometry.
- Test divider release over the terminal restores `text`; release over chrome restores `default`.
- Test the first window-size update emits exactly one `default` pointer reset.
- Run focused TUI tests, the full TUI package, `mise run check:fast`, and the exhaustive gate before publication.
