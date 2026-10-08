# A2A protocol fixture

`a2a.proto` is vendored from the A2A specification source tag `v1.0.1`.
The accompanying `A2A-LICENSE` is the upstream Apache-2.0 license.

`sample-card.json` is copied verbatim from spec §8.5. Its top-level `security` member is not
defined by the proto (which defines `securityRequirements`), so the canonicalizer reports
`/security` as uncovered. `sample-card-proto.json` adapts that member and its value to the
proto's `securityRequirements` → `schemes` → `list` structure.
