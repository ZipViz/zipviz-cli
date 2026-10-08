import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { npubEncode } from "../src/buzz/index.js";
import { linkStatement, PROVISIONAL_LINK_EVENT_KIND } from "../src/link/index.js";
import { MAX_INPUT_BYTES } from "../src/check.js";
import { run, USAGE, type Deps } from "../src/main.js";
import { DOMAIN, ISSUED_AT, linkEvent, makeKeys, makeLink } from "./link-helpers.js";

const tempDirs: string[] = [];
const keys = makeKeys();

function setup(stdin: string | Uint8Array = "") {
  const home = mkdtempSync(path.join(tmpdir(), "zipviz-link-test-"));
  tempDirs.push(home);
  const stdout: string[] = [];
  const stderr: string[] = [];
  const deps: Deps = {
    fetch: async () => { throw new Error("unexpected fetch"); },
    stdout: (value) => stdout.push(value),
    stderr: (value) => stderr.push(value),
    zipvizHome: home,
    readStdin: async () => typeof stdin === "string" ? new TextEncoder().encode(stdin) : stdin,
  };
  return {
    home,
    stdout,
    stderr,
    run: (args: string[]) => run(args, deps),
    write: (name: string, value: string | Uint8Array) => {
      const file = path.join(home, name);
      writeFileSync(file, value);
      return file;
    },
  };
}

afterEach(() => {
  for (const directory of tempDirs.splice(0)) rmSync(directory, { recursive: true, force: true });
});

/** Sign the ZipViz side with the CLI, then the Buzz side with a test Nostr key. */
async function signedLink(cli: ReturnType<typeof setup>) {
  expect(await cli.run(["keygen", "--name", "link"])).toBe(0);
  const code = await cli.run([
    "link", "sign", DOMAIN, "--nostr-pubkey", keys.nostrPubkey, "--issued-at", String(ISSUED_AT), "--json",
  ]);
  expect(code).toBe(0);
  const body = JSON.parse(cli.stdout.at(-1)!) as {
    link: Record<string, unknown>;
    nostr_event_template: Record<string, unknown>;
    provisional_kind: number;
  };
  const statement = body.link.statement as string;
  const doc: Record<string, unknown> = { ...body.link, nostr_event: linkEvent(keys, statement) };
  return { ...body, statement, doc };
}

describe("zipviz link sign", () => {
  it("signs the ZipViz side and emits an unsigned Nostr event for the Buzz client", async () => {
    const cli = setup();
    const { link, nostr_event_template, statement, provisional_kind } = await signedLink(cli);
    expect(statement).toBe(linkStatement({
      domain: DOMAIN,
      ed25519Pubkey: link.ed25519_pubkey as string,
      nostrPubkey: keys.nostrPubkey,
      issuedAt: ISSUED_AT,
    }));
    expect(link.nostr_npub).toBe(npubEncode(keys.nostrPubkey));
    expect(link.ed25519_sig).toMatch(/^[0-9a-f]{128}$/);
    expect(nostr_event_template).toEqual({
      pubkey: keys.nostrPubkey,
      created_at: ISSUED_AT,
      kind: PROVISIONAL_LINK_EVENT_KIND,
      tags: [["viz", DOMAIN]],
      content: statement,
    });
    expect(nostr_event_template).not.toHaveProperty("sig");
    expect(provisional_kind).toBe(PROVISIONAL_LINK_EVENT_KIND);
  });

  it("never prints private key material and never accepts a Nostr secret key", async () => {
    const cli = setup();
    expect(await cli.run(["keygen", "--name", "link"])).toBe(0);
    const pem = readFileSync(path.join(cli.home, "keys", `${DOMAIN}.key`), "utf8");
    expect(await cli.run(["link", "sign", DOMAIN, "--nostr-pubkey", keys.nostrPubkey])).toBe(0);
    const printed = [...cli.stdout, ...cli.stderr].join("");
    expect(printed).not.toMatch(/PRIVATE KEY/);
    expect(printed).not.toContain(pem.replace(/\s+/g, ""));
    expect(printed).not.toContain(keys.nostrSecret);

    expect(await cli.run(["link", "sign", DOMAIN, "--nsec", "nsec1xxx"])).toBe(2);
    expect(await cli.run(["link", "sign", DOMAIN, "--nostr-secret", keys.nostrSecret])).toBe(2);
    expect(USAGE).not.toMatch(/nsec|secret key/i);
  });

  it("rejects an npub, a bad hex key and an unknown sub-command", async () => {
    const cli = setup();
    expect(await cli.run(["keygen", "--name", "link"])).toBe(0);
    expect(await cli.run(["link", "sign", DOMAIN, "--nostr-pubkey", npubEncode(keys.nostrPubkey)])).toBe(2);
    expect(await cli.run(["link", "sign", DOMAIN, "--nostr-pubkey", "zz"])).toBe(2);
    expect(await cli.run(["link", "sign", "example.com", "--nostr-pubkey", keys.nostrPubkey])).toBe(2);
    expect(await cli.run(["link", "sign", DOMAIN, "--nostr-pubkey", keys.nostrPubkey, "--issued-at", "soon"])).toBe(2);
    expect(await cli.run(["link", "list"])).toBe(2);
  });

  it("fails cleanly when there is no local key", async () => {
    const cli = setup();
    expect(await cli.run(["link", "sign", DOMAIN, "--nostr-pubkey", keys.nostrPubkey, "--json"])).toBe(1);
    expect(JSON.parse(cli.stdout.at(-1)!)).toMatchObject({ ok: false, error: { code: "E_NO_KEY" } });
  });
});

describe("zipviz link verify", () => {
  it("shows the link as its own line and never as shared authorship", async () => {
    const cli = setup();
    const { doc, statement } = await signedLink(cli);
    const file = cli.write("link.json", JSON.stringify(doc));
    const before = cli.stdout.length;
    expect(await cli.run(["link", "verify", file])).toBe(0);
    const lines = cli.stdout.slice(before).join("").trimEnd().split("\n");
    expect(lines[0]).toBe(`linked to Buzz agent ${npubEncode(keys.nostrPubkey)}`);
    expect(lines[1]).toBe(`zipviz agent ${DOMAIN} (ed25519 ${doc.ed25519_pubkey as string})`);
    expect(lines.join("\n")).toContain("neither identity authors the other's messages");
    expect(lines.join("\n")).not.toContain("signed by agent");
    expect(statement).toContain(DOMAIN);
    expect(lines.join("\n")).toContain(`zipviz verify ${DOMAIN}`);
    expect(lines.join("\n")).toMatch(/NOT compared with the key the registry lists/);
  });

  it("says the ed25519 key was not checked against the registry, even for a throwaway key", async () => {
    // A document naming link.z.viz but signed by a key the registry never saw still has two
    // valid signatures, so the output must not let it read as "this is link.z.viz".
    const rogue = makeLink(makeKeys());
    const cli = setup(JSON.stringify(rogue.doc));
    expect(await cli.run(["link", "verify", "-", "--json"])).toBe(0);
    const body = JSON.parse(cli.stdout.at(-1)!) as { link: Record<string, unknown> };
    expect(body.link).toMatchObject({ valid: true, domain: DOMAIN, registry_checked: false });
    expect(body.link.caveat).toMatch(/NOT compared with the key the registry lists/);

    const humanCli = setup(JSON.stringify(rogue.doc));
    expect(await humanCli.run(["link", "verify", "-"])).toBe(0);
    const human = humanCli.stdout.join("");
    expect(human).toMatch(/NOT compared with the key the registry lists/);
    expect(human).toContain(`zipviz verify ${DOMAIN}`);
    expect(human).toContain("this proves both keys co-signed the statement, nothing more");
  });

  it("rejects a v99 document and a mismatched nostr_npub from the CLI", async () => {
    const { doc } = makeLink(makeKeys());
    const bumped = setup(JSON.stringify({ ...doc, v: 99 }));
    expect(await bumped.run(["link", "verify", "-", "--json"])).toBe(4);
    expect(JSON.parse(bumped.stdout.at(-1)!)).toMatchObject({
      link: { valid: false, reason: "LINK_VERSION_UNSUPPORTED", registry_checked: false },
    });

    const npubCli = setup(JSON.stringify({ ...doc, nostr_npub: npubEncode(keys.nostrPubkey) }));
    expect(await npubCli.run(["link", "verify", "-"])).toBe(4);
    expect(npubCli.stdout.join("")).toContain("link failed: LINK_NPUB_MISMATCH");
  });

  it("reports a failing link as failed, with a stable reason code, over --json and stdin", async () => {
    const cli = setup();
    const { doc } = await signedLink(cli);
    const signature = doc.ed25519_sig as string;
    const broken = { ...doc, ed25519_sig: `${signature.slice(0, -2)}${signature.endsWith("00") ? "11" : "00"}` };
    const file = cli.write("broken.json", JSON.stringify(broken));
    const before = cli.stdout.length;
    expect(await cli.run(["link", "verify", file])).toBe(4);
    const human = cli.stdout.slice(before).join("");
    expect(human).toContain("link failed: LINK_ED25519_SIG_INVALID");
    expect(human).toContain("is NOT linked");
    expect(human).not.toContain("linked to Buzz agent");
    expect(human).toMatch(/NOT compared with the key the registry lists/);

    const jsonCli = setup(JSON.stringify(broken));
    expect(await jsonCli.run(["link", "verify", "-", "--json"])).toBe(4);
    expect(JSON.parse(jsonCli.stdout.at(-1)!)).toMatchObject({
      ok: false,
      command: "link verify",
      link: { valid: false, reason: "LINK_ED25519_SIG_INVALID" },
      ed25519: { valid: false, reason: "LINK_ED25519_SIG_INVALID" },
      nostr: { valid: true },
    });
  });

  it("keeps the 1 MiB input cap and rejects non-JSON input", async () => {
    const cli = setup();
    const file = cli.write("big.json", "x".repeat(MAX_INPUT_BYTES + 1));
    expect(await cli.run(["link", "verify", file, "--json"])).toBe(6);
    expect(JSON.parse(cli.stdout.at(-1)!)).toMatchObject({ error: { code: "E_INPUT_TOO_LARGE" } });

    const stdinCli = setup(new Uint8Array(MAX_INPUT_BYTES + 1));
    expect(await stdinCli.run(["link", "verify", "-", "--json"])).toBe(6);
    expect(JSON.parse(stdinCli.stdout.at(-1)!)).toMatchObject({ error: { code: "E_INPUT_TOO_LARGE" } });

    const badCli = setup("not json");
    expect(await badCli.run(["link", "verify", "-", "--json"])).toBe(6);
    expect(JSON.parse(badCli.stdout.at(-1)!)).toMatchObject({ error: { code: "E_INPUT_NOT_JSON" } });

    const shapeCli = setup("[]");
    expect(await shapeCli.run(["link", "verify", "-", "--json"])).toBe(6);
    expect(JSON.parse(shapeCli.stdout.at(-1)!)).toMatchObject({ error: { code: "E_INPUT_NOT_OBJECT" } });
  });

  it("makes no network calls", async () => {
    const cli = setup();
    const { doc } = await signedLink(cli);
    const file = cli.write("link.json", JSON.stringify(doc));
    expect(await cli.run(["link", "verify", file])).toBe(0);
  });
});
