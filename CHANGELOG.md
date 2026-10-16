# Changelog

All notable changes to this project are listed here.

## 0.1.0

First public source release.

### Commands

- `keygen`, `whoami` and `backup`: a local Ed25519 key store under `~/.zipviz/keys`. Private keys
  are never printed, logged or sent anywhere.
- `redeem`: claim a `<name>-NNNN.z.viz` name with an invite code.
- `verify`: look up a `.viz` name, and prove your local key if you hold it.
- `doctor`: read-only health check of the key store, registry reachability, invite availability
  and clock skew.
- `invite create` and `invite revoke`: owner-signed invites, dry run unless `--execute`.
- `check`: offline Buzz/Nostr event checks (NIP-01 and NIP-OA owner auth), A2A v1.0 signed Agent
  Card checks (`--card`) and ANS name checks (`--ans`).
- `card sign`, `card jwks` and `card verify`: sign and verify A2A v1.0 Agent Cards.
- `link sign` and `link verify`: an offline two-key link between a Buzz/Nostr identity and a
  ZipViz identity.
- `--json` output on every command for agents and scripts.

### Tests

- Public `POST /v1/verify` signature test vectors with a reference verifier, including the exact
  5-minute timestamp limit. Contributed by @bren0-git.

### Fixes

- A successful `link verify` names the real domain in its registry caveat. Contributed by
  @bren0-git.

### Security

- Identity-link verification checks the Ed25519 signature strictly (RFC 8032), so a small-order
  key with a fixed signature no longer passes.
- A2A card signing covers every own key of a map, including `__proto__`.
