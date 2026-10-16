# Contributing to zipviz

Thanks for your interest in the ZipViz command-line client.

## Before you open a pull request

- **Contributor License Agreement.** We can only merge a contribution after its author has signed
  the ZipViz Individual Contributor License Agreement (ICLA). If you contribute as part of your
  job, your employer may also need to sign a Corporate CLA.
- **Security issues are never reported in public.** Do not open an issue or pull request for a
  suspected vulnerability. Follow [SECURITY.md](SECURITY.md) instead.
- **No secrets or personal data.** Never put real keys, tokens, invite codes, email addresses or
  other personal data in code, tests, fixtures, issues or pull requests. Test keys in this
  repository come from published seeds (see [test-vectors/README.md](test-vectors/README.md)).

## Development

Requires Node.js 22 or later.

```sh
npm ci
npm test          # vitest
npm run typecheck # tsc
npm run lint      # eslint
npm run build     # dist/
```

CI runs the same checks plus a full-history secret scan. To run the scanner locally, see
[docs/secret-scanning.md](docs/secret-scanning.md).

## Pull requests

- Keep each pull request to one change, and explain what it changes and why.
- Add or update tests for any change in behavior.
- Open an issue to discuss a new dependency or a new command before writing it.
- CI must pass. A maintainer reviews every pull request, and only maintainers merge.

## Names

The code is licensed under Apache-2.0. As section 6 of that license says, it does not grant
permission to use the ZipViz name or marks. A fork must not present itself as ZipViz or as the
ZipViz registry.
