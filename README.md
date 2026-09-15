# safethrottle

Local TUN gateway that applies asymptotic per-domain outbound rate limits.
Traffic destined for configured domain families (GitHub, YouTube, Substack,
...) is captured via policy routing into a userspace TUN device and paced
against a soft per-minute limit instead of being hard-capped.

Ships one binary, `safethrottle-gateway`, driven entirely by a TOML config
(`config.example.toml` documents the shape). It has two run modes:

- `enable-routing` — installs the split-default policy route and starts
  pacing.
- `disable-routing` — tears the route down, leaving the TUN up.
- `run` — the long-running gateway loop (what a systemd unit should exec).

## Why

Running many Nix builds or parallel agentic work against GitHub, without
being logged in on every single request, overwhelms GitHub's unauthenticated
rate limits fast. Same story hitting yt-dlp against YouTube, or scraping
Substack pages — enough concurrent/bursty traffic and you get hard failures
mid-run. safethrottle sits underneath all of that transparently: instead of
authenticating everywhere or hand-throttling each client, it paces outbound
traffic per domain family at the network layer, so nothing above it has to
know it's being rate-limited at all.

## Usage

```
$ safethrottle-gateway --config config.toml run
```

runs the gateway loop — this is what a systemd unit execs. Routing is
separate from the loop so you can toggle it independently:

```
$ safethrottle-gateway --config config.toml enable-routing
```

installs the split-default policy route and starts pacing; traffic to
configured families (GitHub, YouTube, Substack, ...) now gets captured into
the TUN and paced against each family's soft per-minute limit instead of
being hard-capped. Everything else — unrelated domains, anything not in a
configured family — passes through untouched.

```
$ safethrottle-gateway --config config.toml disable-routing
```

tears the policy route back down, leaving the TUN device up but inert.

### Example: a burst against one family

Say `limit = 10`, `soft_ratio = 0.7`, `soft_pace = 0.7`, on the default 60s
cycle — so the free band covers connections 1–7, soft pacing covers 8–10.
Cycle boundaries are fixed clock ticks (0s, 60s, 120s, ...), not a rolling
window that follows each request.

A client hammering that family in a tight loop — each connection sent the
instant the *previous* one is admitted, so "sent at" here is just the prior
row's "admitted at" — sees:

| # | phase | sent at | window left at send | wait computed | admitted at | count after |
|---|---|---|---|---|---|---|
| 1–7 | free | 0.0s | 60.0s → 60.0s | 0s each | 0.0s | 1 → 7 |
| 8 | soft | 0.0s | 60.0s | (60.0/3)×0.7 = 14.0s | 14.0s | 8 |
| 9 | soft | 14.0s | 46.0s | (46.0/2)×0.7 = 16.1s | 30.1s | 9 |
| 10 | soft | 30.1s | 29.9s | (29.9/1)×0.7 = 20.9s | 51.0s | 10 (limit) |
| 11 | overflow | 51.0s | 9.0s | = window left, 9.0s | 60.0s | 1 (new cycle) |
| 12 | free | 60.0s | 60.0s | 0s | 60.0s | 2 |

Two things this makes clear:

- **Connection 10 isn't sent at "9s in"** — it's sent at 30.1s (right after 9
  is admitted), and at *that* moment there's 29.9s left in the cycle. The
  "9.0s" only shows up later, as what's left in the cycle when connection 11
  is evaluated at 51.0s.
- **Connection 11's wait (9.0s) can never exceed the window (60s)**, because
  in the overflow branch the wait *is* "window left at send", full stop — no
  multiplier, no stacking with prior waits. It's bounded by construction:
  worst case for any overflowing connection is "arrived right after the
  cycle started," which waits the full ~60s; arriving late in a cycle (like
  connection 11 here) waits less, not more. The 60.0s in the "admitted at"
  column is a coincidence of this example (51.0 + 9.0 = 60.0, i.e. the next
  cycle boundary) — it does not mean connection 11 waited a full window, it
  waited the 9.0s that were actually left.

When the boundary hits, the cycle's count resets to 0 for everyone
simultaneously — connection 11 is admitted as count 1 of the new cycle, and
connection 12 (sent right at the same instant) lands in the free band again,
identically to connection 1. Nothing in this sequence is ever rejected;
every connection is eventually admitted, just later.

## Config

`config.example.toml` is the reference — copy it to `config.toml` and adjust.
The two pieces that matter:

- **`[families.*]`** — a name, a list of domain suffixes to match, and a
  `limit` (requests/min). Add a family by adding a TOML table; there's
  nothing else to wire up.
- **`soft_ratio` / `soft_pace`** — control the asymptotic curve. Pacing kicks
  in once traffic crosses `soft_ratio` of a family's limit (e.g. `0.7` = the
  last 30% of budget), and `soft_pace` scales how aggressively requests get
  delayed as the remaining budget shrinks. The limit is never hard-enforced —
  requests just get slower to approach it, which is the whole point: no
  request outright fails because of safethrottle.

The rest (`tun_*`, `route_table_id`, `route_rule_priority`, `uplink_iface`)
is networking plumbing — see the inline comments in
`config.example.toml`.

## Nix

`flake.nix` exposes:

- `packages.${system}.gateway` / `.default` — the `safethrottle-gateway`
  binary (`rustPlatform.buildRustPackage`).
- `overlays.default` — adds `safethrottle-gateway` to `pkgs`.
- `devShells.${system}.default` — cargo/rustc/rust-analyzer.
