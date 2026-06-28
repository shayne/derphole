## Design Context

### Users

The primary audience is casual technical users, especially homelab users and developers who are comfortable with terminals, GitHub repos, npm commands, NAT pain, local services, and moving files between machines. They are likely evaluating `derphole` quickly: they want to understand what it does, try the browser demo if useful, and then jump to GitHub or the CLI install path. The website should not behave like a broad SaaS landing page. It should be a simple technical front door with a working browser demo kept intact.

### Brand Personality

The brand should feel hacker, minimal, and restrained. It can acknowledge that "derp" is a little funny, but the interface should stay technically competent rather than cute. The tone should be plain, sharp, and honest: no inflated marketing claims, no decorative networking theater, and no overexplaining what users can already infer from commands and status output.

### Aesthetic Direction

Move away from the current warm, large-type, illustrated-card look. Future UI work should be very simple and much cleaner: sparse, technical, compact, and focused on the GitHub handoff plus the live browser demo. Favor restrained layouts, quiet contrast, precise spacing, and command-first content. The design may borrow from hacker tools, source browsers, terminal manuals, small open-source project pages, and practical network utilities, but it should not become a fake terminal skin or a neon dark-mode dashboard.

Support both light and dark OS themes. Light mode should remain the clearest default for quick repo evaluation. Dark mode should be a restrained low-light variant with tinted dark surfaces, visible borders, and readable command/demo controls rather than glow effects.

The browser demo should remain available on the page, but it should be visually reduced to the clearest possible sender/receiver workflow. The first screen should make `derphole` recognizable, explain the practical job in one short line, expose the GitHub/CLI path, and keep the demo nearby without turning the page into a promotional funnel.

### Design Principles

1. Keep the site as a technical jump-off point. The GitHub repo, install command, and working browser demo are the primary destinations.
2. Prefer sparse, readable UI over visual decoration. Every panel, border, label, and line of copy needs a clear job.
3. Let command examples carry the product story. The audience understands tools through invocation, flags, and behavior.
4. Keep humor dry and restrained. The name can be funny; the product surface should still feel reliable.
5. Maintain baseline accessibility with semantic markup, keyboard-friendly controls, visible focus states, readable contrast, OS theme support, and reduced-motion-safe behavior.
