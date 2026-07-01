# Derphole website product design

## Summary

Refresh the static `web/derphole` site so the first screen presents `derphole`
as the open-source project and shows the repo's user-facing utilities as a
related product family built on DERP connectivity.

The chosen direction is:

```text
private access without a vpn
```

This replaces the current derphole-only framing with a broader OSS product site
that immediately explains what a visitor can do:

- move a file with `derphole`;
- open a TCP tunnel with `derptun`;
- share a terminal with `derpssh`.

The browser file-transfer demo remains on the page, but lower and secondary.
The native CLI and GitHub repo are the primary paths.

## Goals

- Keep `derphole` as the project and repository name.
- Present the tools by user outcome before product name.
- Make the first screen answer what value the visitor gets from the project.
- Link clearly back to `https://github.com/shayne/derphole`.
- Keep the site feeling like a practical open-source project page, not a SaaS
  landing page.
- Follow the existing static site design system: restrained type, grid
  background, compact navigation, borders, command blocks, light/dark theme
  support, and minimal decoration.
- Keep the browser demo intact but visually subordinate to the CLI product
  story.

## Non-goals

- Do not rename the project or invent a new suite brand.
- Do not add a new framework, router, build system, analytics, or external
  asset pipeline.
- Do not add heavy marketing sections, illustrations, comparison tables, or a
  fake terminal skin.
- Do not redesign the browser transfer runtime or change the WASM integration.
- Do not present the browser demo as the primary product path or a performance
  showcase.

## Page Positioning

The masthead keeps the existing `derphole` brand and links to concise page
anchors:

- `tools`
- `not a vpn`
- `demo`
- `github`

The hero headline should be:

```text
private access without a vpn
```

The supporting copy should stay short and concrete:

```text
Run small utilities for file transfer, TCP tunnels, and terminal sharing across
networks that do not accept inbound connections.
```

Primary hero actions:

- `github repo`
- `run with npx`

Use `run with npx`, not `install with npx`, because the page is selling the
low-friction command path rather than asking visitors to install first.

Update the page metadata to match the same language. The meta description
should not use `public listener`; use direct terms such as open inbound port,
tailnet, daemon, and VPN instead.

## Tools Section

The tools section appears immediately after the hero. It uses outcome-first
headings, then product names and command examples.

### Move a file

Product: `derphole`

Value line:

```text
derphole is the one-session path for files, streams, and localhost shares.
```

Example:

```sh
npx -y derphole@latest receive <code>
```

### Open a TCP tunnel

Product: `derptun`

Value line:

```text
derptun gives a private service a reconnectable path and scoped tokens.
```

Example:

```sh
npx -y derptun@latest token server > server.dts
npx -y derptun@latest serve --token-file server.dts --tcp 127.0.0.1:22
```

### Share your terminal

Product: `derpssh`

Value line:

```text
derpssh is terminal sharing over the same no-open-port transport.
```

Example:

```sh
npx -y derpssh@latest connect <invite>
```

Avoid phrasing such as `host-approved` or detailed approval mechanics in the
first product card. Those details can live in README/docs. The homepage should
read as "share your terminal" first.

## Model Section

Keep the transport explanation compact. The first model note should be `not a
vpn`, with copy along these lines:

```text
Scoped tokens authorize one transfer, one tunnel, or one terminal session. No
daemon, overlay interface, tailnet, subnet route, or account-backed control
plane.
```

A second note can explain the shared transport:

```text
DERP gets peers connected first. Encrypted relay fallback keeps sessions working
when direct paths are blocked, and direct transport takes over when the network
allows it.
```

This section should not over-label DERP for users who do not care, but it should
remain precise enough for a technical visitor to understand the difference from
a VPN or mesh network.

## Command Examples

Keep a compact command group for the CLI products. The examples should reinforce
the product family:

```sh
npx -y derphole@latest send ./file
npx -y derptun@latest token server > server.dts
npx -y derptun@latest serve --token-file server.dts --tcp 127.0.0.1:22
npx -y derpssh@latest share
```

Do not make the command group the page headline. It supports the product value;
it does not replace it.

## Browser Demo

Move the existing browser transfer UI below the product and model sections.
Label it plainly:

```text
browser demo
```

or:

```text
browser derphole demo
```

The copy should explain that it is a small derphole file transfer available in
the browser, and that the native CLI is the path for real transfers.

Preserve all existing JavaScript hooks:

- `select-send-file`
- `send-file`
- `start-send`
- `send-token`
- `copy-token`
- `send-progress`
- `send-status`
- `receive-token`
- `start-receive`
- `receive-progress`
- `receive-status`

The demo's behavior, WASM loading, WebRTC path, token copy, status output, and
progress output should remain unchanged.

## Visual Design

Follow the existing design system in `web/derphole/styles.css`:

- low-chroma green/neutral palette;
- grid paper background;
- lowercase navigation and headings;
- small-radius borders;
- command blocks with dark code surfaces;
- compact labels;
- visible focus rings;
- light and dark color schemes.

The first screen should feel like an open-source project front door: restrained,
technical, quick to scan, and immediately linked to GitHub. Avoid decorative
cards inside cards, large marketing panels, gradients, or visual clutter.

## Responsive Behavior

Desktop:

- masthead remains a compact row;
- hero and actions sit at the top;
- tool entries can use a three-column grid;
- model notes and command examples can sit in two-column strips;
- browser demo remains two panels.

Mobile:

- masthead stacks cleanly if needed;
- hero, actions, and tools stack in that order;
- command blocks wrap safely;
- browser demo panels stack;
- no text should overlap or require horizontal page scrolling.

## Accessibility

Keep semantic sections and labels for the demo controls. Retain visible
`:focus-visible` outlines, disabled button states, status text, progress areas,
and textarea labels. Links and buttons should remain keyboard reachable and
touch-friendly.

## Verification

Implementation should verify:

- `web/derphole/index.html` loads locally without console errors from missing
  element IDs;
- the browser demo controls initialize;
- desktop and mobile screenshots show the hierarchy without overlapping text;
- dark mode remains readable if practical;
- `git diff --check` passes.

No Go tests are required unless implementation touches non-web code.
