# Derphole Website Product Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the static `web/derphole` homepage so `derphole` reads as the OSS project and the first screen clearly presents the repo's product utilities: `derphole`, `derptun`, and `derpssh`.

**Architecture:** Keep the existing static HTML/CSS/WASM page. Reorder and rewrite `web/derphole/index.html` around the approved "private access without a vpn" direction, add minimal CSS in `web/derphole/styles.css`, and preserve the existing browser demo JavaScript IDs and runtime behavior.

**Tech Stack:** Static HTML, CSS custom properties, existing browser WASM scripts, GitButler CLI.

---

## File Structure

- Modify `web/derphole/index.html`: page metadata, masthead labels, hero copy, tools section, compact model section, CLI command strip, and lower-priority browser demo placement. Preserve all script tags and demo element IDs.
- Modify `web/derphole/styles.css`: add focused styles for the tools grid, tool command snippets, compact model strip, and responsive layout. Keep the current palette, typography, focus states, button styles, code surfaces, and light/dark theme variables.
- Do not modify `web/derphole/app.js`, `web/derphole/webrtc.js`, `wasm_exec.js`, `wasm_payload.js`, or generated WASM assets.

## Task 1: Rewrite Homepage Structure And Copy

**Files:**
- Modify: `web/derphole/index.html`

- [ ] **Step 1: Verify the current homepage does not already use the approved positioning**

Run:

```bash
rg -n "private access without a vpn|move a file|open a tcp tunnel|share your terminal" web/derphole/index.html; echo "exit=$?"
```

Expected:

```text
exit=1
```

- [ ] **Step 2: Replace the masthead and main page content**

In `web/derphole/index.html`, update the meta description to:

```html
    <meta
      name="description"
      content="Private access without a VPN: file transfer, TCP tunnels, and terminal sharing over DERP connectivity. No open inbound port, tailnet, or daemon required."
    />
```

Then keep the script tags at the end of `<body>` and replace the existing `<header class="masthead">...</header>` and `<main class="site-shell">...</main>` with this content:

```html
    <header class="masthead">
      <a class="brand" href="#top" aria-label="derphole home">
        <span class="brand-mark" aria-hidden="true">d</span>
        <span>derphole</span>
      </a>
      <nav aria-label="Primary">
        <a href="#tools">tools</a>
        <a href="#model">not a vpn</a>
        <a href="#demo">demo</a>
        <a href="https://github.com/shayne/derphole">github</a>
      </nav>
    </header>

    <main class="site-shell">
      <section id="top" class="intro" aria-labelledby="intro-title">
        <div class="intro-copy">
          <p class="kicker">open source access tools built on derp</p>
          <h1 id="intro-title">private access without a vpn</h1>
          <p class="intro-lede">
            Run small utilities for file transfer, TCP tunnels, and terminal
            sharing across networks that do not accept inbound connections.
          </p>
        </div>

        <div class="repo-actions" aria-label="Project links">
          <a class="link-button primary" href="https://github.com/shayne/derphole">github repo</a>
          <a class="link-button" href="#run">run with npx</a>
        </div>
      </section>

      <section id="tools" class="tools-grid" aria-label="derphole tools">
        <article class="tool-entry">
          <p class="tool-name">derphole</p>
          <h2>move a file</h2>
          <p>derphole is the one-session path for files, streams, and localhost shares.</p>
          <pre><code>npx -y derphole@latest receive &lt;code&gt;</code></pre>
        </article>

        <article class="tool-entry">
          <p class="tool-name">derptun</p>
          <h2>open a tcp tunnel</h2>
          <p>derptun gives a private service a reconnectable path and scoped tokens.</p>
          <pre><code>npx -y derptun@latest token server &gt; server.dts
npx -y derptun@latest serve --token-file server.dts --tcp 127.0.0.1:22</code></pre>
        </article>

        <article class="tool-entry">
          <p class="tool-name">derpssh</p>
          <h2>share your terminal</h2>
          <p>derpssh is terminal sharing over the same no-open-port transport.</p>
          <pre><code>npx -y derpssh@latest connect &lt;invite&gt;</code></pre>
        </article>
      </section>

      <section id="model" class="model-strip" aria-label="Transport model">
        <article>
          <p class="label">not a vpn</p>
          <h2>scoped access, not a network</h2>
          <p>
            Scoped tokens authorize one transfer, one tunnel, or one terminal
            session. No daemon, overlay interface, tailnet, subnet route, or
            account-backed control plane.
          </p>
        </article>
        <article>
          <p class="label">derp first</p>
          <h2>relay start, direct when possible</h2>
          <p>
            DERP gets peers connected first. Encrypted relay fallback keeps
            sessions working when direct paths are blocked, and direct transport
            takes over when the network allows it.
          </p>
        </article>
      </section>

      <section id="run" class="command-strip" aria-label="CLI examples">
        <article>
          <p class="label">run with npx</p>
          <h2>use the native tools first</h2>
          <pre><code>npx -y derphole@latest send ./file
npx -y derptun@latest token server &gt; server.dts
npx -y derptun@latest serve --token-file server.dts --tcp 127.0.0.1:22
npx -y derpssh@latest share</code></pre>
        </article>
        <article>
          <p class="label">one transport family</p>
          <h2>small tools, shared path</h2>
          <p>
            derphole handles one-shot transfers and temporary service shares.
            derptun keeps private TCP services reachable with durable tokens.
            derpssh shares a shell over the same no-open-port transport.
          </p>
        </article>
      </section>

      <section class="section-note demo-note" aria-labelledby="demo-title">
        <p class="label">browser demo</p>
        <h2 id="demo-title">try a small derphole transfer</h2>
        <p>
          This page includes a browser derphole demo for small files. It is
          useful for seeing the flow without installing anything. Use the CLI
          for real transfers and throughput work.
        </p>
      </section>

      <section id="demo" class="demo-grid" aria-label="Browser file transfer demo">
        <article class="demo-panel">
          <div class="panel-heading">
            <span class="panel-index">send</span>
            <div>
              <h3>offer a file</h3>
              <p>Select one file. Send the generated token to the receiver.</p>
            </div>
          </div>
          <button id="select-send-file" type="button">select file</button>
          <p id="send-file" class="file-label">No file selected.</p>
          <button id="start-send" type="button" disabled>create token and send</button>
          <label class="token-label" for="send-token">token</label>
          <textarea id="send-token" readonly placeholder="Token appears here after the file offer starts."></textarea>
          <button id="copy-token" type="button" disabled>copy token</button>
          <pre id="send-progress" class="progress">idle</pre>
          <p id="send-status" class="status">idle</p>
        </article>

        <article class="demo-panel">
          <div class="panel-heading">
            <span class="panel-index">recv</span>
            <div>
              <h3>claim the token</h3>
              <p>Paste the token, pick a save location, and receive the file.</p>
            </div>
          </div>
          <label class="token-label" for="receive-token">token</label>
          <textarea id="receive-token" placeholder="Paste sender token here."></textarea>
          <button id="start-receive" type="button">receive file</button>
          <pre id="receive-progress" class="progress">idle</pre>
          <p id="receive-status" class="status">idle</p>
        </article>
      </section>
    </main>
```

- [ ] **Step 3: Update the footer tagline**

Replace the current footer text with:

```html
    <footer class="footer">
      <span>private access tools built on derp connectivity</span>
      <a href="https://github.com/shayne/derphole">github.com/shayne/derphole</a>
    </footer>
```

- [ ] **Step 4: Verify the approved copy exists**

Run:

```bash
rg -n "private access without a vpn|move a file|open a tcp tunnel|share your terminal|run with npx|browser demo" web/derphole/index.html
```

Expected:

```text
web/derphole/index.html:...
```

The output should include one match for each approved phrase.

## Task 2: Add Product-Site Layout Styles

**Files:**
- Modify: `web/derphole/styles.css`

- [ ] **Step 1: Confirm the new classes are not styled yet**

Run:

```bash
rg -n "tools-grid|tool-entry|tool-name|model-strip|demo-note" web/derphole/styles.css; echo "exit=$?"
```

Expected:

```text
exit=1
```

- [ ] **Step 2: Extend muted text and code-block selector groups**

In `web/derphole/styles.css`, replace the grouped muted-text selector:

```css
.intro-lede,
.section-note p,
.command-strip p,
.briefing p,
.panel-heading p,
.capabilities p {
  color: var(--ink-muted);
}
```

with:

```css
.intro-lede,
.section-note p,
.command-strip p,
.model-strip p,
.panel-heading p,
.tool-entry p {
  color: var(--ink-muted);
}
```

Then replace the grouped code-surface selectors:

```css
.install-block pre,
.command-strip pre,
.progress {
  overflow-x: auto;
  border-radius: 0.375rem;
  color: var(--code-ink);
  background: var(--code-bg);
  font-size: 0.875rem;
  line-height: 1.6;
}

.install-block pre,
.command-strip pre {
  padding: var(--space-md);
}

.install-block pre code,
.command-strip pre code {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
```

with:

```css
.tool-entry pre,
.command-strip pre,
.progress {
  overflow-x: auto;
  border-radius: 0.375rem;
  color: var(--code-ink);
  background: var(--code-bg);
  font-size: 0.875rem;
  line-height: 1.6;
}

.tool-entry pre,
.command-strip pre {
  padding: var(--space-md);
}

.tool-entry pre code,
.command-strip pre code {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
```

- [ ] **Step 3: Replace obsolete capabilities styles with tools styles**

Replace the entire `.capabilities` block:

```css
.capabilities {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
  gap: var(--space-md);
}

.capabilities article {
  display: grid;
  gap: var(--space-xs);
  padding-top: var(--space-md);
  border-top: 1px solid var(--line-strong);
}

.capabilities span {
  color: var(--ink-faint);
  font-family: var(--font-code);
  font-size: 0.78rem;
}
```

with:

```css
.tools-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
  gap: var(--space-md);
}

.tool-entry {
  display: grid;
  gap: var(--space-xs);
  align-content: start;
  padding-top: var(--space-md);
  border-top: 1px solid var(--line-strong);
}

.tool-entry .tool-name {
  margin: 0;
  color: var(--ink-faint);
  font-family: var(--font-code);
  font-size: 0.78rem;
  font-weight: 720;
}

.tool-entry pre {
  margin-top: var(--space-xs);
}
```

- [ ] **Step 4: Replace briefing styles with compact model styles**

Replace:

```css
.briefing {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 24rem), 1fr));
  gap: var(--space-lg);
  padding-block: var(--space-xl);
  border-block: 1px solid var(--line);
}

.briefing article {
  display: grid;
  gap: var(--space-sm);
  align-content: start;
  max-width: 42rem;
}
```

with:

```css
.model-strip {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 24rem), 1fr));
  gap: var(--space-lg);
  padding-block: var(--space-xl);
  border-block: 1px solid var(--line);
}

.model-strip article {
  display: grid;
  gap: var(--space-sm);
  align-content: start;
  max-width: 42rem;
}
```

- [ ] **Step 5: Make the browser demo note visually secondary**

Add this block after `.section-note`:

```css
.demo-note {
  padding-top: var(--space-md);
  border-top: 1px solid var(--line);
}
```

- [ ] **Step 6: Update responsive selectors for the new model strip**

In the mobile media query, replace:

```css
  .panel-heading,
  .command-strip {
    grid-template-columns: 1fr;
  }
```

with:

```css
  .panel-heading,
  .command-strip,
  .model-strip {
    grid-template-columns: 1fr;
  }
```

- [ ] **Step 7: Verify old and new class references**

Run:

```bash
rg -n "capabilities|briefing|install-block" web/derphole/index.html web/derphole/styles.css; echo "exit=$?"
rg -n "tools-grid|tool-entry|tool-name|model-strip|demo-note" web/derphole/index.html web/derphole/styles.css
```

Expected:

```text
exit=1
web/derphole/index.html:...
web/derphole/styles.css:...
```

The first command should have no matches for removed classes. The second command should show both markup and CSS references for the new classes.

## Task 3: Preserve Browser Demo Hooks

**Files:**
- Verify: `web/derphole/index.html`
- Verify: `web/derphole/app.js`

- [ ] **Step 1: Run the ID integrity check**

Run:

```bash
python3 - <<'PY'
from pathlib import Path
import re

html = Path("web/derphole/index.html").read_text()
required = [
    "select-send-file",
    "send-file",
    "start-send",
    "send-token",
    "copy-token",
    "send-progress",
    "send-status",
    "receive-token",
    "start-receive",
    "receive-progress",
    "receive-status",
]

missing = [item for item in required if f'id="{item}"' not in html]
duplicates = {
    item: len(re.findall(rf'id="{re.escape(item)}"', html))
    for item in required
    if len(re.findall(rf'id="{re.escape(item)}"', html)) != 1
}

if missing or duplicates:
    print("missing:", missing)
    print("duplicates:", duplicates)
    raise SystemExit(1)

print("all required demo ids found once")
PY
```

Expected:

```text
all required demo ids found once
```

- [ ] **Step 2: Verify JavaScript still references only existing demo IDs**

Run:

```bash
python3 - <<'PY'
from pathlib import Path
import re

html = Path("web/derphole/index.html").read_text()
js = Path("web/derphole/app.js").read_text()
html_ids = set(re.findall(r'id="([^"]+)"', html))
js_ids = set(re.findall(r'\$\("([^"]+)"\)', js))
missing = sorted(js_ids - html_ids)

if missing:
    print("missing ids referenced by app.js:", ", ".join(missing))
    raise SystemExit(1)

print("all app.js id references exist in index.html")
PY
```

Expected:

```text
all app.js id references exist in index.html
```

## Task 4: Browser And Responsive Verification

**Files:**
- Verify: `web/derphole/index.html`
- Verify: `web/derphole/styles.css`

- [ ] **Step 1: Start a local static server**

Run:

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory web/derphole
```

Expected:

```text
Serving HTTP on 127.0.0.1 port 8765
```

Leave the server running until this task is complete.

- [ ] **Step 2: Open the page in a browser automation session**

Open:

```text
http://127.0.0.1:8765/
```

Expected desktop first-screen content:

```text
derphole
private access without a vpn
github repo
run with npx
move a file
open a tcp tunnel
share your terminal
```

Expected console state:

```text
no missing-element JavaScript errors
```

- [ ] **Step 3: Check desktop layout**

Use a desktop viewport around `1440x1000`.

Expected:

- masthead is compact and readable;
- hero headline does not overlap the action buttons;
- the tools section appears before the model and demo sections;
- product command snippets wrap or fit inside their columns;
- the browser demo is below the product/model content.

- [ ] **Step 4: Check mobile layout**

Use a mobile viewport around `390x844`.

Expected:

- masthead stacks cleanly;
- hero, actions, and tools appear in that order;
- product entries stack without horizontal page scrolling;
- command snippets wrap inside their blocks;
- demo panels stack and all form controls remain reachable.

- [ ] **Step 5: Check dark mode**

Use browser or OS dark color-scheme emulation.

Expected:

- body, panels, buttons, and command blocks keep readable contrast;
- focus outlines remain visible;
- no section disappears into the background grid.

## Task 5: Final Static Checks And Commit

**Files:**
- Verify: `web/derphole/index.html`
- Verify: `web/derphole/styles.css`

- [ ] **Step 1: Run whitespace check**

Run:

```bash
git diff --check -- web/derphole/index.html web/derphole/styles.css
```

Expected: no output.

- [ ] **Step 2: Inspect GitButler diff**

Run:

```bash
but diff
```

Expected:

```text
web/derphole/index.html
web/derphole/styles.css
```

The diff should contain only the homepage redesign. It should not include `.superpowers/`, generated `dist/`, or unrelated files.

- [ ] **Step 3: Commit the implementation**

Run:

```bash
but commit codex/website-product-design-spec -m "web: highlight derphole product family"
```

Expected:

```text
Created commit
```

- [ ] **Step 4: Confirm GitButler branch state from the returned output**

Expected:

```text
codex/website-product-design-spec
docs: design product-focused website
web: highlight derphole product family
```

The branch should contain the existing approved spec commit plus the new implementation commit. No branch push or `origin/main` publication is part of this plan.

## Self-Review Notes

- Spec coverage: Tasks 1 and 2 implement the approved positioning, product hierarchy, GitHub/npx actions, `not a vpn` section, and lower-priority browser demo. Task 3 covers the JavaScript hook preservation requirement. Task 4 covers desktop, mobile, console, and dark-mode visual verification. Task 5 covers whitespace and local GitButler commit hygiene.
- Placeholder scan: This plan contains concrete copy, selectors, commands, expected outputs, and commit messages. It avoids unspecified follow-up work.
- Scope check: The plan is one focused static-site redesign. It does not touch release, packaging, Go code, or browser transfer runtime behavior.
