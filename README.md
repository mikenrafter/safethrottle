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

## Nix

`flake.nix` exposes:

- `packages.${system}.gateway` / `.default` — the `safethrottle-gateway`
  binary (`rustPlatform.buildRustPackage`).
- `overlays.default` — adds `safethrottle-gateway` to `pkgs`.
- `devShells.${system}.default` — cargo/rustc/rust-analyzer.
