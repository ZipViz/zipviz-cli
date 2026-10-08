# draft-narajala-courtney-ansv2-01 fixtures

Source: <https://www.ietf.org/archive/id/draft-narajala-courtney-ansv2-01.txt>

- Published 13 April 2026. Expires 15 October 2026.
- SHA-256 of that text file: `4b2598939d5804adbc69b75b70b68f80c29930623f3999adc2c0edb69740ab4b`

The draft says Appendix A signatures and CSRs are truncated for brevity. These fixtures are the appendix examples, not a cryptographic test vector.

- `a3-event.json` is the Appendix A.3 object.
- `a4-badge.txt` is the Appendix A.4 example, including the placeholder `{ "...same structure as A.3..." }`, which is not valid JSON.
- `a4-truncated.json` is that badge with the A.3 event inlined so it parses. The hashes and signatures are still the draft's truncated strings and must not verify.
