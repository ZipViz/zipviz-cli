import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { base64urlnopad } from "@scure/base";
import { describe, expect, it, vi } from "vitest";
import {
  canonicalizeCard,
  cardWarnings,
  jwkThumbprint,
  parseJwks,
  parsePublicJwk,
  publicJwkFromPrivate,
  signCard,
  SIG_REASONS,
  verifyCard,
  type JsonObject,
  type JsonValue,
  type PrivateJwk,
  type PublicJwk,
  type SigReason,
} from "../src/a2a/index.js";
import { verifyJws } from "../src/a2a/jws.js";
import { run } from "../src/main.js";

const fetchJsonMock = vi.hoisted(() => vi.fn());

vi.mock("../src/net/fetch.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/net/fetch.js")>()),
  fetchJson: fetchJsonMock,
}));

const encoder = new TextEncoder();
const b64 = (value: Uint8Array) => base64urlnopad.encode(value);
const protectedValue = (value: unknown) => b64(encoder.encode(JSON.stringify(value)));
type TestSignature = { protected: string; signature: string; header?: JsonObject };
const baseCard = (): JsonObject => ({
  name: "Example",
  description: "Card",
  supportedInterfaces: [{ url: "https://agent.example/rpc", protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
  version: "1",
  capabilities: {},
  defaultInputModes: ["text/plain"],
  defaultOutputModes: ["text/plain"],
  skills: [],
});

async function remoteCheck(
  card: JsonObject,
  keys: PublicJwk[],
  failedJwksPath?: string,
): Promise<{ code: number; out: string; err: string }> {
  fetchJsonMock.mockReset();
  fetchJsonMock.mockImplementation(async (address: string) => {
    if (address.endsWith("/.well-known/agent-card.json")) {
      return {
        finalUrl: address,
        text: JSON.stringify(card),
        contentType: "application/a2a+json",
        redirects: [],
      };
    }
    if (new URL(address).pathname === failedJwksPath) throw new Error("remote JWKS fetch failed");
    return {
      finalUrl: address,
      text: JSON.stringify({ keys }),
      contentType: "application/jwk-set+json",
      redirects: [],
    };
  });
  const stdout: string[] = [];
  const stderr: string[] = [];
  const code = await run(["check", "--card", "agent.test", "--json"], {
    fetch: async () => { throw new Error("unexpected registry fetch"); },
    stdout: (text) => stdout.push(text),
    stderr: (text) => stderr.push(text),
    zipvizHome: "/unused",
  });
  return { code, out: stdout.join(""), err: stderr.join("") };
}

function keysFor(kind: "ed25519" | "p256") {
  const pair = kind === "p256"
    ? generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    : generateKeyPairSync("ed25519");
  const privateJwk = pair.privateKey.export({ format: "jwk" }) as PrivateJwk;
  const publicJwk = { ...pair.publicKey.export({ format: "jwk" }), kid: "test-key" } as PublicJwk;
  return { pair, privateJwk, publicJwk };
}

function makeSignature(
  card: JsonObject,
  protectedText: string,
  privateKey: KeyObject,
  extra?: Record<string, unknown>,
): JsonObject {
  const payload = canonicalizeCard(card).canonical;
  const input = `${protectedText}.${b64(encoder.encode(payload))}`;
  const eddsa = privateKey.asymmetricKeyType === "ed25519";
  const signature = eddsa
    ? cryptoSign(null, Buffer.from(input), privateKey)
    : cryptoSign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return {
    ...card,
    signatures: [{ protected: protectedText, signature: b64(signature), ...extra }],
  };
}

function signedWith(
  key: ReturnType<typeof keysFor>,
  alg = key.privateJwk.kty === "OKP" ? "EdDSA" : "ES256",
  header: Record<string, unknown> = { alg, typ: "JOSE", kid: "test-key" },
): JsonObject {
  return makeSignature(baseCard(), protectedValue(header), key.pair.privateKey);
}

function signatureReason(card: JsonObject, keys: PublicJwk[] = []): string | undefined {
  return verifyCard(card, { keys }).signatures[0]?.reason;
}

describe("JWK parsing, thumbprints and signing", () => {
  it("rejects malformed and oversized JWKS values", () => {
    expect(() => parseJwks(null)).toThrow(expect.objectContaining({ reason: "JWKS_INVALID" }));
    expect(() => parseJwks({ keys: Array.from({ length: 33 }, () => ({})) })).toThrow(
      expect.objectContaining({ reason: "JWKS_INVALID" }),
    );
  });

  it("derives the RFC 7638 thumbprint for the RFC 8037 Ed25519 key", () => {
    const jwk = parsePublicJwk({
      kty: "OKP",
      crv: "Ed25519",
      x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    });
    expect(jwkThumbprint(jwk)).toBe("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  });

  it("round-trips EdDSA and ES256 signed cards and produces interoperable JOSE signatures", () => {
    for (const key of [keysFor("ed25519"), keysFor("p256")]) {
      const alg = key.privateJwk.kty === "OKP" ? "EdDSA" : "ES256";
      const signed = signCard(baseCard(), key.privateJwk, { kid: "test-key" });
      const verified = verifyCard(signed, { keys: [key.publicJwk] });
      expect(verified.valid).toBe(true);
      expect(verified.signatures).toMatchObject([{ valid: true, alg, kid: "test-key" }]);
      expect(signed.signatures).toHaveLength(1);
      expect(JSON.parse(Buffer.from(signed.signatures![0]!.protected, "base64url").toString("utf8"))).toEqual({
        alg,
        typ: "JOSE",
        kid: "test-key",
      });
    }
  });

  it("uses the RFC 7638 public-key thumbprint as the default kid", () => {
    const key = keysFor("ed25519");
    const signed = signCard(baseCard(), key.privateJwk, {});
    const header = JSON.parse(Buffer.from(signed.signatures![0]!.protected, "base64url").toString("utf8")) as {
      kid: string;
    };
    expect(header.kid).toBe(jwkThumbprint(key.publicJwk));
  });

  it("verifies the RFC 8037 A.4 Ed25519 JWS vector", () => {
    const header = "eyJhbGciOiJFZERTQSJ9";
    const payload = "RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
    const signature = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
    expect(verifyJws(
      "EdDSA",
      Buffer.from(`${header}.${payload}`),
      base64urlnopad.decode(signature),
      {
      kty: "OKP",
      crv: "Ed25519",
      x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      },
    )).toBe(true);
  });

  it("verifies the RFC 7515 A.3 ES256 JWS vector with raw r||s encoding", () => {
    const header = "eyJhbGciOiJFUzI1NiJ9";
    const payload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    const signature = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    const key = parsePublicJwk({
      kty: "EC",
      crv: "P-256",
      x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    });
    expect(verifyJws("ES256", Buffer.from(`${header}.${payload}`), base64urlnopad.decode(signature), key)).toBe(true);
  });

  it("rejects a non-canonical Ed25519 S scalar", () => {
    const signature = Buffer.from(base64urlnopad.decode(
      "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
    ));
    const order = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
    let scalar = 0n;
    for (let i = 0; i < 32; i++) scalar |= BigInt(signature[32 + i]!) << BigInt(i * 8);
    scalar += order;
    for (let i = 0; i < 32; i++) {
      signature[32 + i] = Number((scalar >> BigInt(i * 8)) & 0xffn);
    }
    expect(verifyJws(
      "EdDSA",
      Buffer.from("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"),
      signature,
      {
        kty: "OKP",
        crv: "Ed25519",
        x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      },
    )).toBe(false);
  });

  it("accepts a high-S ES256 signature as required by JOSE", () => {
    const key = keysFor("p256");
    const signed = signedWith(key);
    const sig = (signed.signatures as TestSignature[])[0]!;
    const signature = Buffer.from(base64urlnopad.decode(sig.signature));
    const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
    const highS = order - s;
    const highBytes = Buffer.from(highS.toString(16).padStart(64, "0"), "hex");
    highBytes.copy(signature, 32);
    const input = Buffer.from(`${sig.protected}.${b64(encoder.encode(canonicalizeCard(baseCard()).canonical))}`);
    expect(verifyJws("ES256", input, signature, key.publicJwk)).toBe(true);
  });

  it("rejects private public-JWK inputs, malformed coordinates, and off-curve points", () => {
    expect(() => parsePublicJwk({ ...keysFor("ed25519").publicJwk, d: "private" })).toThrow(
      expect.objectContaining({ reason: "KEY_INVALID" }),
    );
    expect(() => parsePublicJwk({ kty: "OKP", crv: "Ed25519", x: "A" })).toThrow(
      expect.objectContaining({ reason: "KEY_INVALID" }),
    );
    expect(() => parsePublicJwk({ kty: "EC", crv: "P-256", x: "A".repeat(43), y: "A".repeat(43) })).toThrow(
      expect.objectContaining({ reason: "KEY_INVALID" }),
    );
  });

  it("rejects small-order Ed25519 points and never verifies cards with them", () => {
    const valid = signedWith(keysFor("ed25519"));
    const encodings = [
      Uint8Array.from([1, ...new Uint8Array(31)]),
      Uint8Array.from([0xec, ...new Uint8Array(30).fill(0xff), 0x7f]),
    ];
    for (const encoding of encodings) {
      const smallOrderKey: PublicJwk = {
        kty: "OKP",
        crv: "Ed25519",
        x: b64(encoding),
        kid: "test-key",
      };
      expect(() => parsePublicJwk(smallOrderKey)).toThrow(expect.objectContaining({ reason: "KEY_INVALID" }));
      expect(verifyCard(valid, { keys: [smallOrderKey] }).valid).toBe(false);
    }
  });

  it("checks private/public JWK consistency before signing", () => {
    const key = keysFor("ed25519");
    const broken = { ...key.privateJwk, x: key.privateJwk.x.replace(/^./, key.privateJwk.x[0] === "A" ? "B" : "A") };
    expect(() => publicJwkFromPrivate(broken)).toThrow(expect.objectContaining({ reason: "KEY_INVALID" }));
    expect(() => signCard({ ...baseCard(), url: "https://legacy.example" }, key.privateJwk, {})).toThrow(
      expect.objectContaining({ reason: "CARD_UNCOVERED_FIELDS" }),
    );
  });
});

describe("Agent Card signature verification reasons", () => {
  const ed = keysFor("ed25519");
  const ec = keysFor("p256");

  it("verifies an ES256 JWS using JOSE raw r||s encoding", () => {
    const card = signedWith(ec);
    expect(verifyCard(card, { keys: [ec.publicJwk] }).valid).toBe(true);
  });

  it("accepts absent or case-insensitive JOSE typ and reports unexpected values as warnings", () => {
    const key = keysFor("ed25519");
    const cases = [
      [{ alg: "EdDSA", kid: "test-key" }, undefined],
      [{ alg: "EdDSA", typ: "jose", kid: "test-key" }, undefined],
      [{ alg: "EdDSA", typ: "JWT", kid: "test-key" }, 'typ "JWT" is not JOSE'],
      [{ alg: "EdDSA", typ: 123, kid: "test-key" }, "typ 123 is not JOSE"],
      [{ alg: "EdDSA", typ: "x".repeat(100), kid: "test-key" }, `typ ${JSON.stringify("x".repeat(100)).slice(0, 64)} is not JOSE`],
    ] as const;
    for (const [header, message] of cases) {
      const result = verifyCard(signedWith(key, "EdDSA", header), { keys: [key.publicJwk] });
      expect(result.valid).toBe(true);
      if (message === undefined) {
        expect(result.signatures[0]?.warnings).toBeUndefined();
      } else {
        expect(result.signatures[0]?.warnings).toEqual([{ code: "SIG_TYP_UNEXPECTED", message }]);
      }
    }

    const signed = signedWith(key);
    const signature = (signed.signatures as TestSignature[])[0]!;
    const header = JSON.parse(Buffer.from(signature.protected, "base64url").toString("utf8")) as Record<string, unknown>;
    header.typ = "JWT";
    const tampered = {
      ...signed,
      signatures: [{
        ...signature,
        protected: b64(encoder.encode(JSON.stringify(header))),
      }],
    };
    expect(verifyCard(tampered, { keys: [key.publicJwk] }).signatures[0]).toMatchObject({
      valid: false,
      reason: "SIG_INVALID",
      warnings: [{ code: "SIG_TYP_UNEXPECTED", message: 'typ "JWT" is not JOSE' }],
    });
  });

  it.each([
    ["SIG_ALG_NONE", { alg: "none", typ: "JOSE", kid: "test-key" }, ed],
    ["SIG_ALG_UNSUPPORTED", { alg: "HS256", typ: "JOSE", kid: "test-key" }, ed],
    ["SIG_ALG_UNSUPPORTED", { alg: "Ed25519", typ: "JOSE", kid: "test-key" }, ed],
    ["SIG_CRIT_UNSUPPORTED", { alg: "EdDSA", typ: "JOSE", kid: "test-key", crit: [] }, ed],
    ["SIG_CRIT_UNSUPPORTED", { alg: "EdDSA", typ: "JOSE", kid: "test-key", crit: ["exp"] }, ed],
    ["SIG_CRIT_UNSUPPORTED", { alg: "EdDSA", typ: "JOSE", kid: "test-key", b64: false }, ed],
    ["SIG_KID_MISSING", { alg: "EdDSA", typ: "JOSE" }, ed],
    ["SIG_KID_MISSING", { alg: "EdDSA", typ: "JOSE", kid: "" }, ed],
    ["SIG_KID_MISSING", { alg: "EdDSA", typ: "JOSE", kid: "k".repeat(257) }, ed],
    ["SIG_KEY_ALG_MISMATCH", { alg: "ES256", typ: "JOSE", kid: "test-key" }, ed],
    ["SIG_KEY_ALG_MISMATCH", { alg: "EdDSA", typ: "JOSE", kid: "test-key" }, ec],
    ["SIG_KEY_ALG_MISMATCH", { alg: "EdDSA", typ: "JOSE", kid: "test-key" }, {
      ...ed,
      publicJwk: { ...ed.publicJwk, alg: "ES256" },
    }],
    ["SIG_JKU_INVALID", { alg: "EdDSA", typ: "JOSE", kid: "test-key", jku: "http://agent.example/jwks.json" }, ed],
    ["SIG_JKU_INVALID", { alg: "EdDSA", typ: "JOSE", kid: "test-key", jku: "https://user@agent.example/jwks.json" }, ed],
    ["SIG_JKU_INVALID", { alg: "EdDSA", typ: "JOSE", kid: "test-key", jku: "https://@agent.example/jwks.json" }, ed],
    ["SIG_JKU_INVALID", { alg: "EdDSA", typ: "JOSE", kid: "test-key", jku: "https://agent.example/jwks.json#" }, ed],
  ] as const)("reports %s", (reason, header, key) => {
    const signed = makeSignature(baseCard(), protectedValue(header), key.pair.privateKey);
    expect(signatureReason(signed, [key.publicJwk])).toBe(reason);
  });

  it("rejects malformed protected base64url, JSON, object shape, and UTF-8", () => {
    const key = keysFor("ed25519");
    const invalidUtf8 = b64(new Uint8Array([0xff]));
    for (const protectedText of [
      "e30=",
      "+w",
      "AB",
      "eyJhbGciOiJFZERTQSJ9=",
      invalidUtf8,
      b64(encoder.encode("not json")),
      b64(encoder.encode("[]")),
    ]) {
      const card = makeSignature(baseCard(), protectedText, key.pair.privateKey);
      expect(signatureReason(card, [key.publicJwk])).toBe(
        protectedText === b64(encoder.encode("[]")) || protectedText === b64(encoder.encode("not json"))
          ? "SIG_HEADER_INVALID"
          : "SIG_ENCODING_INVALID",
      );
    }
    expect(signatureReason(
      makeSignature(baseCard(), protectedValue({ alg: "EdDSA", typ: "JOSE", kid: "test-key" }), key.pair.privateKey),
      [],
    )).toBe("SIG_KEY_NOT_FOUND");
  });

  it("rejects bad signature shape, signature bytes, extra members and unprotected-only key ids", () => {
    const key = keysFor("ed25519");
    const goodHeader = protectedValue({ alg: "EdDSA", typ: "JOSE", kid: "test-key" });
    const valid = makeSignature(baseCard(), goodHeader, key.pair.privateKey);
    const short = { ...valid, signatures: [{ protected: goodHeader, signature: b64(new Uint8Array(63)) }] };
    expect(signatureReason(short, [key.publicJwk])).toBe("SIG_MALFORMED");
    const extra = { ...valid, signatures: [{ protected: goodHeader, signature: "AA", extra: true }] };
    expect(signatureReason(extra, [key.publicJwk])).toBe("SIG_MALFORMED");
    const noProtectedKid = makeSignature(baseCard(), protectedValue({ alg: "EdDSA", typ: "JOSE" }), key.pair.privateKey, {
      header: { kid: "test-key" },
    });
    expect(signatureReason(noProtectedKid, [key.publicJwk])).toBe("SIG_KID_MISSING");
    const validSignature = (valid.signatures as TestSignature[])[0]!;
    const changed = { ...valid, signatures: [{ ...validSignature, signature: b64(new Uint8Array(64)) }] };
    expect(signatureReason(changed, [key.publicJwk])).toBe("SIG_INVALID");
  });

  it("ignores unprotected key selection fields and reports them without trusting them", () => {
    const key = keysFor("ed25519");
    const protectedText = protectedValue({ alg: "EdDSA", typ: "JOSE", kid: "test-key" });
    const signed = makeSignature(baseCard(), protectedText, key.pair.privateKey, {
      header: { kid: "attacker", alg: "HS256", jku: "https://evil.example/keys", x5u: "https://evil.example/cert" },
    });
    const result = verifyCard(signed, { keys: [key.publicJwk] });
    expect(result.valid).toBe(true);
    expect(result.signatures[0]?.unprotected_ignored).toEqual(["alg", "jku", "kid", "x5u"]);
  });

  it("returns SIG_INVALID after covered content changes but remains valid after member reordering", () => {
    const key = keysFor("ed25519");
    const signed = signedWith(key);
    const changed = { ...signed, documentationUrl: "https://docs.example" };
    expect(signatureReason(changed, [key.publicJwk])).toBe("SIG_INVALID");
    const reordered = Object.fromEntries(Object.entries(signed).reverse()) as JsonObject;
    expect(verifyCard(reordered, { keys: [key.publicJwk] }).valid).toBe(true);
  });

  it("applies the at-least-one policy, preserves every signature result, and limits signatures to 16", () => {
    const first = signCard(baseCard(), ed.privateJwk, { kid: "old-key" });
    const rotated = signCard(first, ec.privateJwk, { kid: "new-key", append: true });
    const newKey = { ...ec.publicJwk, kid: "new-key" };
    const defaultResult = verifyCard(rotated, { keys: [newKey] });
    expect(defaultResult.valid).toBe(true);
    expect(defaultResult.valid_signatures).toBe(1);
    expect(defaultResult.signatures).toMatchObject([
      { valid: false, reason: "SIG_KEY_NOT_FOUND" },
      { valid: true },
    ]);

    const strictResult = verifyCard(rotated, { keys: [newKey], requireAll: true });
    expect(strictResult.valid).toBe(false);
    expect(strictResult.reason).toBe("CARD_SIGNATURES_INVALID");
    expect(strictResult.valid_signatures).toBe(1);
    expect(strictResult.signatures).toMatchObject(defaultResult.signatures);

    const allFailed = verifyCard(rotated, { keys: [] });
    expect(allFailed.valid).toBe(false);
    expect(allFailed.reason).toBe("CARD_SIGNATURES_INVALID");
    expect(allFailed.valid_signatures).toBe(0);
    expect(allFailed.signatures).toMatchObject([
      { valid: false, reason: "SIG_KEY_NOT_FOUND" },
      { valid: false, reason: "SIG_KEY_NOT_FOUND" },
    ]);

    const original = signedWith(ed);
    const good = (original.signatures as TestSignature[])[0]!;
    const many = { ...first, signatures: Array.from({ length: 17 }, () => good) };
    expect(verifyCard(many, { keys: [ed.publicJwk] }).reason).toBe("CARD_TOO_MANY_SIGNATURES");
    expect(verifyCard(baseCard(), { keys: [] }).reason).toBe("CARD_UNSIGNED");
  });

  it("warns about forged signatures only when at least one signature verifies", () => {
    const validKey = keysFor("ed25519");
    const forgedKey = keysFor("ed25519");
    const first = signCard(baseCard(), validKey.privateJwk, { kid: "valid-key" });
    const appended = signCard(first, forgedKey.privateJwk, { kid: "forged-key", append: true });
    const entries = appended.signatures as TestSignature[];
    const mixed = {
      ...appended,
      signatures: [
        entries[0]!,
        { ...entries[1]!, signature: b64(new Uint8Array(64)) },
      ],
    };
    const expectedWarnings = [{
      code: "CARD_SIGNATURE_FAILED_VERIFICATION",
      reason: "SIG_INVALID",
      message: "signature 2 claiming key forged-key failed verification: SIG_INVALID",
      signature_index: 1,
    }];
    const keys = [
      { ...validKey.publicJwk, kid: "valid-key" },
      { ...forgedKey.publicJwk, kid: "forged-key" },
    ];

    const verified = verifyCard(mixed, { keys });
    expect(verified.valid).toBe(true);
    expect(verified.signatures).toMatchObject([
      { valid: true },
      { valid: false, reason: "SIG_INVALID" },
    ]);
    expect(verified.warnings).toEqual(expectedWarnings);

    const strict = verifyCard(mixed, { keys, requireAll: true });
    expect(strict.valid).toBe(false);
    expect(strict.reason).toBe("CARD_SIGNATURES_INVALID");
    expect(strict.warnings).toEqual(expectedWarnings);

    const missingKeyCard = signCard(first, forgedKey.privateJwk, { kid: "missing-key", append: true });
    const missingKey = verifyCard(missingKeyCard, { keys: [{ ...validKey.publicJwk, kid: "valid-key" }] });
    expect(missingKey.valid).toBe(true);
    expect(missingKey.signatures[1]).toMatchObject({ valid: false, reason: "SIG_KEY_NOT_FOUND" });
    expect(missingKey.warnings).toBeUndefined();

    const allFailed = verifyCard(mixed, { keys: [{ ...forgedKey.publicJwk, kid: "forged-key" }] });
    expect(allFailed.valid_signatures).toBe(0);
    expect(allFailed.warnings).toBeUndefined();
  });

  const warningReasonCases = [
    "SIG_MALFORMED",
    "SIG_ENCODING_INVALID",
    "SIG_HEADER_INVALID",
    "SIG_ALG_NONE",
    "SIG_ALG_UNSUPPORTED",
    "SIG_CRIT_UNSUPPORTED",
    "SIG_KID_MISSING",
    "SIG_JKU_INVALID",
    "SIG_KEY_NOT_FOUND",
    "SIG_KEY_ALG_MISMATCH",
    "SIG_INVALID",
    "KEY_JKU_HOST_NOT_ALLOWED",
  ] as const;

  it("covers every signature reason in the rejected-signature warning table", () => {
    const signatureReasons = warningReasonCases.filter(
      (reason): reason is SigReason => (SIG_REASONS as readonly string[]).includes(reason),
    );
    expect(signatureReasons).toEqual(SIG_REASONS);
    expect(warningReasonCases).toContain("KEY_JKU_HOST_NOT_ALLOWED");
  });

  it.each(warningReasonCases)("warns for rejected signatures except exempt reasons: %s", async (reason) => {
    const validKey = keysFor("ed25519");
    if (reason === "SIG_KEY_NOT_FOUND" || reason === "KEY_JKU_HOST_NOT_ALLOWED") {
      const first = signCard(baseCard(), validKey.privateJwk, {
        kid: "valid-key",
        jku: "https://agent.test/valid-jwks.json",
      });
      const second = signCard(first, validKey.privateJwk, {
        kid: reason === "SIG_KEY_NOT_FOUND" ? "missing-key" : "blocked-key",
        jku: reason === "SIG_KEY_NOT_FOUND"
          ? "https://agent.test/failing-jwks.json"
          : "https://evil.test/blocked-jwks.json",
        append: true,
      });
      const result = await remoteCheck(
        second,
        [{ ...validKey.publicJwk, kid: "valid-key" }],
        reason === "SIG_KEY_NOT_FOUND" ? "/failing-jwks.json" : undefined,
      );
      expect(result.code).toBe(0);
      const verification = JSON.parse(result.out) as {
        signatures: Array<{ valid: boolean; reason?: string }>;
        warnings?: unknown[];
      };
      expect(verification.signatures).toMatchObject([
        { valid: true },
        { valid: false, reason },
      ]);
      expect(verification).not.toHaveProperty("warnings");
      if (reason === "SIG_KEY_NOT_FOUND") {
        expect(fetchJsonMock.mock.calls.map(([url]) => url)).toContain("https://agent.test/failing-jwks.json");
      } else {
        expect(fetchJsonMock.mock.calls.map(([url]) => url)).not.toContain("https://evil.test/blocked-jwks.json");
      }
      return;
    }

    const first = signCard(baseCard(), validKey.privateJwk, { kid: "valid-key" });
    const firstSignature = (first.signatures as TestSignature[])[0]!;
    const keys: PublicJwk[] = [{ ...validKey.publicJwk, kid: "valid-key" }];
    let rejectedSignature: JsonValue;
    let warningKid: string | undefined = "case-key";
    switch (reason) {
      case "SIG_MALFORMED":
        rejectedSignature = { protected: protectedValue({ alg: "EdDSA", kid: "case-key" }) };
        break;
      case "SIG_ENCODING_INVALID":
        rejectedSignature = { protected: protectedValue({ alg: "EdDSA", kid: "case-key" }), signature: "!" };
        break;
      case "SIG_HEADER_INVALID":
        rejectedSignature = { protected: protectedValue([]), signature: "" };
        warningKid = undefined;
        break;
      case "SIG_ALG_NONE":
        rejectedSignature = { protected: protectedValue({ alg: "none", kid: "case-key" }), signature: "" };
        break;
      case "SIG_ALG_UNSUPPORTED":
        rejectedSignature = { protected: protectedValue({ alg: "HS256", kid: "case-key" }), signature: "" };
        break;
      case "SIG_CRIT_UNSUPPORTED":
        rejectedSignature = {
          protected: protectedValue({ alg: "EdDSA", kid: "case-key", crit: [] }),
          signature: "",
        };
        break;
      case "SIG_KID_MISSING":
        rejectedSignature = { protected: protectedValue({ alg: "EdDSA" }), signature: "" };
        warningKid = undefined;
        break;
      case "SIG_JKU_INVALID":
        rejectedSignature = {
          protected: protectedValue({ alg: "EdDSA", kid: "case-key", jku: "http://agent.test/keys.json" }),
          signature: "",
        };
        break;
      case "SIG_KEY_ALG_MISMATCH": {
        rejectedSignature = {
          protected: protectedValue({ alg: "EdDSA", kid: "case-key" }),
          signature: b64(new Uint8Array(64)),
        };
        const incompatibleKey = keysFor("p256");
        keys.push({ ...incompatibleKey.publicJwk, kid: "case-key" });
        break;
      }
      case "SIG_INVALID": {
        const otherCard = signCard(
          { ...baseCard(), description: "different card" },
          validKey.privateJwk,
          { kid: "case-key" },
        );
        rejectedSignature = (otherCard.signatures as TestSignature[])[0]!;
        keys.push({ ...validKey.publicJwk, kid: "case-key" });
        break;
      }
      default:
        throw new Error(`unexpected local signature reason ${reason}`);
    }
    const mixed = {
      ...first,
      signatures: [firstSignature, rejectedSignature],
    };
    const verification = verifyCard(mixed, { keys });
    expect(verification.valid).toBe(true);
    expect(verification.signatures[1]?.reason).toBe(reason);
    expect(verification.warnings).toEqual([{
      code: "CARD_SIGNATURE_FAILED_VERIFICATION",
      reason,
      message: `signature 2${warningKid === undefined ? "" : ` claiming key ${warningKid}`} failed verification: ${reason}`,
      signature_index: 1,
    }]);
  });

  it("uses SIG_MALFORMED for an invalid signature result without a reason", () => {
    expect(cardWarnings([{ index: 0, valid: true }, { index: 1, valid: false }])).toEqual([{
      code: "CARD_SIGNATURE_FAILED_VERIFICATION",
      reason: "SIG_MALFORMED",
      message: "signature 2 failed verification: SIG_MALFORMED",
      signature_index: 1,
    }]);
  });

  it("warns about alg:none and invalid base64url signatures when another signature verifies", () => {
    const validKey = keysFor("ed25519");
    const signed = signCard(baseCard(), validKey.privateJwk, { kid: "valid-key" });
    const validSignature = (signed.signatures as TestSignature[])[0]!;
    const header = (value: unknown) => protectedValue(value);
    const mixed = {
      ...signed,
      signatures: [
        validSignature,
        { protected: header({ alg: "none" }), signature: "" },
        { protected: header({ alg: "EdDSA", kid: "bad-encoding" }), signature: "!" },
      ],
    };

    const result = verifyCard(mixed, { keys: [{ ...validKey.publicJwk, kid: "valid-key" }] });
    expect(result.valid).toBe(true);
    expect(result.signatures).toMatchObject([
      { valid: true },
      { valid: false, reason: "SIG_ALG_NONE" },
      { valid: false, reason: "SIG_ENCODING_INVALID" },
    ]);
    expect(result.warnings).toEqual([
      {
        code: "CARD_SIGNATURE_FAILED_VERIFICATION",
        reason: "SIG_ALG_NONE",
        message: "signature 2 failed verification: SIG_ALG_NONE",
        signature_index: 1,
      },
      {
        code: "CARD_SIGNATURE_FAILED_VERIFICATION",
        reason: "SIG_ENCODING_INVALID",
        message: "signature 3 claiming key bad-encoding failed verification: SIG_ENCODING_INVALID",
        signature_index: 2,
      },
    ]);
  });

  it("refuses an existing signature without --append and supports key rotation append", () => {
    const first = signCard(baseCard(), ed.privateJwk, { kid: "first" });
    expect(() => signCard(first, ec.privateJwk, { kid: "second" })).toThrow(
      expect.objectContaining({ reason: "CARD_ALREADY_SIGNED" }),
    );
    const appended = signCard(first, ec.privateJwk, { kid: "second", append: true });
    const result = verifyCard(appended, {
      keys: [{ ...ed.publicJwk, kid: "first" }, { ...ec.publicJwk, kid: "second" }],
    });
    expect(result.valid).toBe(true);
    expect(result.signatures).toHaveLength(2);
  });

  it("validates jku, public-key selection, and missing key cases", () => {
    const key = keysFor("ed25519");
    const card = signedWith(key, "EdDSA", { alg: "EdDSA", typ: "JOSE", kid: "absent" });
    expect(signatureReason(card, [key.publicJwk])).toBe("SIG_KEY_NOT_FOUND");
    expect(() => signCard(baseCard(), key.privateJwk, { jku: "http://agent.example/keys" })).toThrow(
      expect.objectContaining({ reason: "CARD_SCHEMA_INVALID" }),
    );
  });
});
