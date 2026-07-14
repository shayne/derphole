# Custom DERP Servers

A custom DERP route is chosen by the process that creates a token or durable credential. The route then travels inside that value. This matters because the consumer is not reading local relay configuration and hoping it matches; it is following the route the creator actually selected.

Create a one-shot listener with a custom relay:

```sh
DERPHOLE_DERP_SERVER=https://derp.example.com derphole --verbose listen
```

`DERPHOLE_DERP_SERVER` accepts these forms, with an optional explicit port:

- `https://host`
- `https://host/`
- `https://host/derp`

The scheme must be HTTPS, and the server must present a certificate valid for the selected hostname. Userinfo, query strings, fragments, and other paths are rejected. All accepted forms become the canonical `/derp` endpoint; for example, `https://derp.example.com` dials `https://derp.example.com/derp`. An explicit port changes the DERP TCP destination but not the STUN port.

The server must also admit standalone ephemeral DERP clients. Enabling `derper --verify-clients` against local `tailscaled` rejects those clients unless an admission mechanism explicitly allows them: derphole peers carry ephemeral DERP identities, not membership in the operator's local tailnet. DNS, certificates, and open ports can all be correct while admission still closes the door.

## The Token Owns the Route

Set the variable only where the token or credential is created. The resulting custom route is embedded in the one-shot v6 token, `dts2_` derptun server token, or `DT2` client credential. Consumers neither set nor override it. A conflicting consumer environment does not get a vote, which avoids turning a connection capability into a distributed configuration exercise.

When the variable is unset, derphole keeps its existing public behavior and formats: public v5 one-shot tokens, `dts1_` server tokens, and `DT1` client credentials. Those values continue to use the public Tailscale DERP map and STUN infrastructure.

Both peers need a derphole version with custom-token support. Older versions reject the new formats rather than guessing how to route them.

## Relay, STUN, and Direct Paths

Custom mode contacts no public Tailscale DERP or STUN infrastructure. DERP uses the embedded HTTPS host and port. STUN uses the same host on UDP 3478. STUN is fail-soft: if UDP is blocked or the server does not provide STUN, the session stays on its custom relay.

Custom does not mean forced relay. Direct-path discovery and promotion still run unless you pass `--force-relay`. The custom relay is the rendezvous and fallback path; a successful direct promotion can still carry the peer traffic afterward.

The DERP route itself is authoritative. DNS, TCP, TLS, HTTP upgrade, or DERP failure at the embedded server fails the session. There is no fallback to a direct DERP TCP dial, a public relay, or public STUN. That would make the token say one thing while the network quietly did another, which is not a useful security boundary.

## HTTP Proxy Behavior

`HTTPS_PROXY` and `NO_PROXY` govern the DERP TCP connection using Go's standard proxy rules. If a proxy is selected, it must allow a long-lived `CONNECT` tunnel to the embedded host and port. A rejected or broken proxy connection fails closed instead of retrying the custom DERP directly.

The proxy applies only to DERP TCP. STUN and direct-path traffic use UDP and do not traverse the HTTP proxy. A locked-down network may therefore leave the session on DERP, but proxy configuration alone does not set `--force-relay`.

See [DERP Client Runtime](./client-runtime.md#constrained-egress-through-an-http-proxy) for supported proxy URLs, authentication, diagnostics, and resolver details.

## Trust Boundary

Accepting a custom token authorizes an outbound TLS connection to the hostname and port embedded in that token. Inspect the source of a token before using it, especially when the route names a private address or unfamiliar host. TLS certificate and hostname validation still apply; custom is not shorthand for insecure.

The custom relay operator can observe connection metadata such as client source addresses, DERP identities, timing, duration, and byte volume. Peer payload protection remains end-to-end, so the relay does not receive the application plaintext. The route locator itself is part of the token and is not secret.

Use `--verbose` when checking a deployment. Both peers should report `derp-route=custom` and `connected-relay`; `connected-direct` should appear only when direct promotion is allowed and succeeds. If the custom DERP connection fails, fix that route or its proxy policy. There is deliberately no public escape hatch hidden behind the error.
