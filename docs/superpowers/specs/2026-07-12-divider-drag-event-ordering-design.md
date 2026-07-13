# Reliable Chat Divider Dragging

## Problem

The chat divider is visibly and semantically one terminal cell wide. That is the intended interaction area, but dragging it starts unreliably even when the initial press lands on the divider.

The scene compositor currently resolves each mouse event through `View.OnMouse`, which returns a Bubble Tea command containing a semantic `pointerMsg`. Bubble Tea launches each returned command independently. Press, motion, and release messages can therefore reach the model out of order. The model also ignores the original ordered `tea.MouseMsg` stream, so divider capture may not be established before motion or release is handled.

The defect is event ordering, not target geometry. Expanding the divider hit area would hide the symptom while taking mouse input away from adjacent terminal and chat cells.

## Design Principles

- A drag is an ordered state machine: press, capture, motion, release.
- Input ordering belongs in `Update`; asynchronous commands are for effects, not gesture sequencing.
- Hit-testing should use the semantic Lip Gloss scene that produced the visible interface.
- After capture, pointer coordinates no longer choose the recipient. Motion and release remain routed to the captured target.
- The visible divider and its hit area remain exactly one terminal cell wide.
- `View` remains a rendering operation and does not mutate interaction state.

## Event Flow

`App.Update` will handle supported raw `tea.MouseMsg` values directly instead of discarding them.

For a pointer event with no active capture:

1. Build the semantic scene from the current model state.
2. Ask the scene compositor for the topmost target at the event coordinates.
3. Wrap the raw event and target in the existing `pointerMsg` representation.
4. Dispatch it synchronously through the existing mouse handlers.

For a pointer event with an active capture:

1. Skip coordinate hit-testing.
2. Route the event to the captured semantic target.
3. Keep routing motion to that target even when the pointer crosses into the terminal or sidebar.
4. Clear capture on release through the existing release path.

The view will continue enabling `tea.MouseModeCellMotion`, but it will no longer install an `OnMouse` callback that forwards a second, asynchronous copy of each event.

## Divider Behavior

An exact left-button press on the rendered divider starts a divider drag and captures `targetDivider`. Motion updates the sidebar width using the current pointer coordinate. Release ends the drag and clears capture.

A press in the immediately adjacent terminal or sidebar cell retains that cell's existing behavior. No invisible padding is added around the divider.

Existing cancellation rules remain in force: opening a modal, entering copy mode, or otherwise disabling mouse interaction clears pointer capture.

## Testing

Regression coverage will exercise the public model boundary rather than manually running commands returned by `View.OnMouse`:

- An exact-divider raw press sent to `Update` synchronously establishes divider capture.
- A raw press, motion, and release sequence resizes the chat pane and clears capture.
- Motion outside the divider continues to route to the captured divider.
- An adjacent terminal or sidebar press does not capture the divider.
- The rendered divider remains one cell wide and retains its semantic divider target.
- Existing modal, copy-mode, terminal-mouse, and scene-target tests continue to pass.

The focused TUI tests will run first, followed by the repository check and race suites before completion.

## Scope

This change is limited to local mouse-event routing and its tests. It does not alter divider rendering, layout calculations, sidebar width constraints, keyboard resizing, terminal mouse encoding, or unrelated Charm v2 APIs.
