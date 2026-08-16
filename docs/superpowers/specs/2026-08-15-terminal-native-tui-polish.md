# Terminal-native TUI polish design

## Confirmed brief

The derpssh TUI should feel native in modern terminals, especially Ghostty, while remaining a restrained technical tool. The terminal pane stays visually primary; chrome should be quieter, compact, and clearly interactive. The existing orange local accent, blue remote accent, semantic scene graph, and approved top-bar/chat composition remain the visual foundation.

The user approved these six improvements and explicitly excluded persistence:

1. Derive neutral surfaces from the terminal's reported foreground and background, while leaving the terminal canvas unpainted so terminal opacity continues to work.
2. Render the child terminal's cursor shape, blink mode, color, visibility, and position through Bubble Tea instead of simulating it with reverse-video cells.
3. Preserve OSC 8 hyperlinks emitted by the child terminal.
4. Track keyboard versus mouse modality, ignore synthetic stationary motion for hover, and emit OSC 22 pointer shapes only for terminals known to support them.
5. Quiet modal treatment, preserve the dimmed scene's hierarchy, standardize hover/pressed feedback, and use a small toast for transient feedback such as copy and role changes.
6. Enable focus reporting and send silent desktop attention notifications for remote chat and approval requests only while the outer terminal is blurred.

Do not store chat width, chat visibility, focus, or any other UI state between sessions.

## Visual direction

- Scene: a developer uses derpssh in a translucent Ghostty window beside other terminal work, often in low ambient light but with a complete light-mode counterpart.
- Strategy: restrained. Neutral ramps come from the terminal; orange and blue remain sparse identity accents; success, warning, and danger remain semantic.
- Hierarchy: the child terminal is the content surface, the top bar and chat are quiet secondary surfaces, dialogs are the only elevated layer, and toasts sit above dialogs without stealing focus.
- Interaction: pointer targets use visible hover and pressed states, keyboard input suppresses stale hover until the pointer actually moves, and every cursor shape returns to the correct target after capture ends.
- Modal: retain a compact familiar dialog, reduce ornamental framing, keep action controls on a unified footer surface, and dim the existing ANSI scene without flattening it to one color.

## State coverage

- Dark and light terminal-derived themes, including missing foreground or background replies.
- Terminal cursor: block, underline, bar; steady and blinking; custom and default color; hidden and scrolled-back states.
- Hyperlinks: linked text, transitions between links, and reset at line boundaries.
- Pointer: terminal text cursor, divider resize cursor, chrome/modal arrow cursor, drag capture, release, unknown terminal, and supported terminal.
- Input modality: keyboard navigation, real pointer motion, stationary synthetic motion, hover, pressed, copied, and disabled/non-actionable targets.
- Attention: focused, blurred, remote chat, local chat, and approval requests.

## Constraints and anti-goals

- Keep Bubble Tea v2, Lip Gloss v2, x/ansi, x/vt, and Ultraviolet; update stale direct modules without changing frameworks.
- Do not add a framework, icon package, persistent state, animation system, sound, or terminal-specific hard dependency.
- Treat OSC 22 and desktop notifications as optional capabilities with conservative detection and no effect on unsupported terminals.
- Do not repaint the child terminal's default background.
- Do not turn dialogs, messages, or toolbar items into nested cards or decorative chrome.

## Reference and mock decisions

Implementation references are the current derpssh TUI, the user's real Ghostty screenshot, Ghostty's OSC documentation, and the interaction/theme patterns already studied in the local reference application. A generated visual probe and raster north-star mock are intentionally skipped because this is a bounded refinement of an approved, running terminal interface; terminal escape behavior and real cell rendering are the fidelity target.
