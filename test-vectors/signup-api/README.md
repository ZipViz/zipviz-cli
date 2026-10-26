# Synthetic draft signup fixtures

Source: [Elusor8/zipviz-api at 420f0c2cc79f49ecf1d78414c2ef2bead7900902](https://github.com/Elusor8/zipviz-api/tree/420f0c2cc79f49ecf1d78414c2ef2bead7900902).
These are draft consumer fixtures, not final server acceptance. All keys, names,
emails and owner claims in the fixtures are synthetic. Never use their keys for
an identity or deployment.

The source files below retain the exact bytes downloaded from that commit:

| API source path | SHA-256 |
| --- | --- |
| `test-vectors/signup-v1.json` (stored one directory above) | `9500affd45a4084bf20a3371ffe4209680f406d58b266049590fef2ed2ce432a` |
| `tests/support/signup-fake.ts` | `1009df5fac822cc019007eaa4748bb3c9ec81703784bd2f1d24bc8757f859cdd` |
| `src/signup-codec.js` | `0320b79f10bdf2a1e442c9c3663e8d1c1306fc22051c0473d1d2910a939998a9` |
| `src/jcs.js` | `00572f5b0af4fb8ba96b072db55e2a572158d2f79ff43e32e36c14f487e2d870` |
| `src/bytes.js` | `afcb6c0eb0a854f40320063455d96dc2909f0fecb3fa795fff2c47192c7041d0` |

Adjacent `.d.ts` files are CLI-owned type bridges for the unchanged JavaScript.
`npm run fixtures:signup` compiles the typed fake and copies its helpers to
`tests/fixtures/signup-api`. `npm run fixtures:signup -- --check` compares that
output with the committed generated files; the vector suite runs the same check.
Its separate compiler config matches the source fake's array-index assumptions.
The production CLI keeps `noUncheckedIndexedAccess: true` and imports none of these
fixtures. No server feature flag or operational retention setting is changed.
