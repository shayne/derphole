# derpssh OpenCode-inspired chrome and chat design

## Summary

derpssh will modernize its top bar and side chat for terminals such as Ghostty.
The visual direction follows OpenCode's current TUI: warm near-black surfaces,
layered neutral backgrounds, a restrained set of Unicode glyphs, heavy vertical
rules, generous horizontal spacing, and whole-surface hover paint.

The mouse model will make existing controls visibly interactive and add one new
message action: hovering a chat message highlights it, and clicking it copies
only the message body. Messages will not open menus, become editable, or steal
keyboard focus.

The reference checkout is `anomalyco/opencode` at `4643e65ad6` on `dev`. The
most relevant reference files are:

- `packages/tui/src/theme/assets/opencode.json` for the palette hierarchy;
- `packages/tui/src/ui/border.ts` for the heavy `┃` split rule;
- `packages/tui/src/routes/session/index.tsx` for message surfaces and hover;
- `packages/tui/src/routes/session/subagent-footer.tsx` for compact hoverable
  controls.

## Goals

- Make the top bar and chat feel deliberate in a modern true-color terminal.
- Replace generic ASCII-like chrome with sparse, semantic Unicode glyphs.
- Adopt OpenCode's background, panel, element, border, and accent hierarchy.
- Preserve readable light and dark modes.
- Give every clickable top-bar and chat surface hover and pressed feedback.
- Copy a chat message body by clicking its highlighted message block.
- Preserve terminal selection, embedded-application mouse forwarding, divider
  dragging, modal priority, keyboard shortcuts, and responsive layout.
- Upgrade the Charm dependencies that have newer stable releases.

## Non-goals

- Rebuilding the TUI on OpenCode's TypeScript/OpenTUI stack.
- Restyling every modal, invite screen, or terminal cell in this pass.
- Adding chat replies, reactions, context menus, timestamps, rich text, syntax
  highlighting, or message editing.
- Copying the author label along with a message body.
- Adding terminal-specific Ghostty escape sequences or requiring a patched
  font, Nerd Font, or icon font.
- Changing the derpssh protocol or chat payload.
- Publishing or releasing derpssh as part of this work.

## Considered approaches

### OpenCode-native

This is the chosen direction. It uses OpenCode's warm neutral palette and
surface hierarchy together with its heavy split rules, sparse glyphs, and
whole-row hover treatment. It produces the strongest visual improvement and
matches the selected mockup.

The tradeoff is a more visible departure from derpssh's current Catppuccin
palette. Theme roles and contrast tests will keep that change systematic rather
than scattering literal colors through render code.

### Derphole palette with OpenCode painting

This would retain the existing blue Catppuccin identity while borrowing only
OpenCode's layout and interaction patterns. It would reduce visual change but
would not achieve the selected warm, modern appearance.

### Quiet monochrome

This would use the new glyphs and mouse polish with minimal panel contrast. It
would be restrained, but interactive targets and message grouping would be
harder to scan.

## Visual system

### Palette and roles

The dark theme follows OpenCode's default steps:

- background `#0A0A0A`;
- panel `#141414`;
- interactive element and hovered panel `#1E1E1E`;
- subtle border `#3C3C3C`, border `#484848`, active border `#606060`;
- text `#EEEEEE`, muted text `#808080`;
- primary orange `#FAB283`, secondary blue `#5C9CF5`;
- success `#7FD88F`, warning `#F5A742`, danger `#E06C75`.

The light theme uses OpenCode's corresponding white and gray surface steps,
blue primary, purple secondary, orange accent, and semantic status colors.
Where OpenCode's muted light text does not meet derpssh's existing 4.5:1
contrast test, derpssh will choose the nearest darker neutral that does. The
painting model is the requirement; inaccessible literal color parity is not.

`ThemeRole` will gain explicit roles for the terminal background, panel,
element/hover surface, subtle/normal/active borders, primary, secondary,
success, warning, and copied feedback. Existing component roles will be mapped
onto those primitives so render code continues to request meaning rather than
hex values.

### Glyph vocabulary

The top bar and chat will use a small glyph set that renders in standard modern
monospace fonts:

- `◆` for the derpssh brand;
- `●` for transport and presence state;
- `◈` for chat;
- `⋮` for the action menu;
- `×` for quit or close;
- `┃` for the chat divider and message accent;
- `✓` for copied feedback;
- `▲` and `▼` only when a visible chat scroll affordance is needed.

Glyphs are semantic accents, not decoration on every label. Width-sensitive
rendering continues to use ANSI-aware display-width helpers.

## Top bar

The top bar remains one row and keeps all current information and actions. It
changes from a sequence of background chips separated by `›` into one panel
surface with spaced semantic groups:

1. `◆ derpssh` brand;
2. local side and display identity;
3. `●` transport state, terminal dimensions, and local role;
4. peer identities;
5. right-aligned `◈ Chat`, `⋮` menu, and `×` quit controls.

Muted metadata sits directly on the panel. Only hover, pressed, warning, and
selected states paint an element background. The active chat control uses the
primary accent; transport and healthy presence use success; destructive quit
hover uses danger.

Every actionable or peer segment retains its own semantic scene target. Mouse
motion paints the entire padded target. A left press records the target and a
release activates it only when the pointer is still over the same target. This
prevents accidental actions while dragging away and aligns top-bar behavior
with the modal buttons.

Narrow-width packing keeps the existing priority behavior: essential brand and
right-side actions are retained first, while metadata that does not fit is
omitted. Unicode display width, not byte length, determines packing.

## Chat panel

The open chat panel uses the panel background and a single-cell split edge
rendered with the heavy glyph `┃`. The divider changes to the active border
color on hover and the primary color while dragging.

The header contains `◈ Chat`, a muted peer count when known, and a right-aligned
`×` close target. Closing chat preserves current focus and terminal-resize
semantics.

Messages become vertically grouped blocks:

- the author appears on its own short label line;
- the body wraps beneath it with left padding;
- remote messages use a neutral or secondary accent rule;
- local messages use the primary accent and element background;
- adjacent messages have one blank row when space permits.

The mockup included timestamps to demonstrate hierarchy, but timestamps are not
part of the current protocol and will not be invented in this change.

The composer uses the element background with a primary left accent. Clicking
it focuses chat input. Existing one-to-three-row dynamic height, cursor, Enter
submission, and keyboard focus behavior remain unchanged.

## Mouse and feedback behavior

Bubble Tea cell-motion reporting remains enabled. The app stores a semantic
hover target and a pressed target in addition to existing gesture capture.

- Moving over a top-bar control, peer, divider, chat close control, composer,
  scroll affordance, or message updates its visual state.
- Moving away clears hover without changing focus or running an action.
- Pressing and releasing on the same control activates it; releasing elsewhere
  cancels it.
- Clicking a message copies only its original body with `tea.SetClipboard`.
- Copying does not focus the composer, alter terminal selection, or change the
  chat scroll position.
- The copied message shows `✓ Copied` in its metadata area for about 1.2
  seconds. A sequence number prevents an older timer from clearing newer
  feedback.
- The chat wheel moves three rendered rows per notch and clamps at both ends.
- Existing terminal selection and embedded SGR mouse ownership continue to
  take priority inside the terminal rectangle.
- Existing modal routing continues to take priority over all background hover
  and click targets.

Messages have a useful click action, so their hover treatment is not a false
affordance. There is no context menu or reply action.

## Rendering architecture

### Semantic targets

`layerTarget` will add stable targets for the chat header close control,
composer, and visible message blocks. Message targets use the append-only
message index, which is stable for the lifetime of the current `App`.

Header segment targets remain action- and peer-based. Target parsing stays in
small helpers rather than spreading string-prefix logic through render code.

### Chat layout

The current sidebar is rendered as one large layer, which cannot identify an
individual message. A chat layout helper will produce visible message blocks
with their source index, rendered lines, and rectangle after wrapping and
scroll clipping. `buildSidebarLayers` will compose:

1. the panel background;
2. header and close target;
3. each visible message block;
4. composer separator and composer;
5. the divider above the panel edge.

The helper owns only geometry and clipping. Styling remains in `StyleSet`, and
mouse actions remain in `mouse.go`. This keeps message hit testing consistent
with the exact wrapped rows painted on screen.

Partially visible message blocks may be clipped, but their target still maps to
the original complete message body for copying.

### Interaction state

`App` will store:

- `hoverTarget layerTarget`;
- `pressedTarget layerTarget` for ordinary chrome clicks;
- copied message index, copied-feedback sequence, and active state.

Existing pointer capture remains authoritative for divider and terminal drag
gestures. Ordinary pressed-state handling will not replace modal-specific
choice state or terminal SGR release tracking.

Motion events resolve the target from the current scene before dispatch. When
the hover target changes, the next declarative render paints the new state.
Window resize, modal activation, chat close, invite mode, and pointer-capture
cleanup clear stale hover and pressed targets.

## Dependencies

The repository currently uses:

- `charm.land/bubbles/v2 v2.1.1`, already current;
- `charm.land/bubbletea/v2 v2.0.8`, already current;
- `charm.land/lipgloss/v2 v2.0.5`, with `v2.0.6` available;
- `github.com/charmbracelet/x/ansi v0.11.7`, with `v0.11.8` available.

Implementation will upgrade Lip Gloss to `v2.0.6` and `x/ansi` to `v0.11.8`
through the Go module toolchain, then tidy the module graph. No new UI framework
or icon dependency is needed.

## Error handling and compatibility

- Clipboard commands follow Bubble Tea's existing clipboard lifecycle. A copy
  request is best-effort and does not shell out to platform clipboard tools.
- Empty message bodies do not produce copy commands or copied feedback.
- Invalid, stale, or clipped message targets are ignored safely.
- Unsupported mouse buttons do not trigger chrome actions.
- Hover is enhancement only; every action remains keyboard-accessible.
- Standard Unicode glyphs are used without Nerd Font assumptions.
- Light and dark theme selection continues to follow the terminal background
  response.
- Terminals without cell-motion reporting retain keyboard behavior and static
  styling; lack of hover does not remove functionality.
- Narrow terminals keep the existing automatic sidebar collapse threshold.

## Testing strategy

Implementation will be test-driven with focused failures before behavior
changes.

### Theme and rendering tests

- Assert every primitive and component role exists in light and dark themes.
- Preserve the 4.5:1 contrast requirement for text-bearing roles.
- Verify exact top-bar glyphs, grouping, packing, and ANSI-aware widths.
- Verify normal, hovered, pressed, active, warning, and danger styles.
- Verify chat message grouping, wrapping, clipping, and local/remote accents.
- Verify each visible message and control exposes the correct scene target.
- Verify narrow layouts do not split or corrupt multicolumn glyphs.

### Mouse tests

- Motion enters, changes, and clears semantic hover targets.
- Press/release on the same control activates once; release elsewhere cancels.
- Divider hover and drag preserve existing pointer-capture ordering.
- Composer clicks focus chat without copying a message.
- Message clicks copy only the original body, including multiline commands.
- Empty or stale message targets do nothing.
- Copied feedback appears, supersedes older timers, and clears after its tick.
- Chat wheel movement advances three rows and clamps correctly.
- Modal routing and terminal SGR/local-selection routing remain higher priority.

### Verification

- `go test ./pkg/derpssh/tui`
- `mise run check:fast` during implementation
- `mise run check` once against the final commit stack before any requested
  push or direct landing
- Manual Ghostty smoke check for glyph alignment, light/dark appearance, hover,
  click-to-copy, divider drag, chat scroll, and embedded terminal mouse input

## Delivery boundaries

The implementation belongs in one focused GitButler branch. Generated `dist/`
content will not be edited. Completion of the code does not authorize a push,
landing on `main`, or a release; those remain separate user requests.
