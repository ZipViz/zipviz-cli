import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { base64urlnopad } from "@scure/base";
import { KeyError } from "./reasons.js";
import { parsePublicJwk, publicJwkFromPrivate, type PrivateJwk, type PublicJwk } from "./jwk.js";

export type JwsAlgorithm = "EdDSA" | "ES256";

function decode(value: string): Uint8Array {
  try {
    const bytes = base64urlnopad.decode(value);
    if (base64urlnopad.encode(bytes) !== value) throw new Error("invalid base64url");
    return bytes;
  } catch {
    throw new KeyError("KEY_INVALID");
  }
}

function ecPoint(key: PublicJwk): Uint8Array {
  if (key.kty !== "EC") throw new KeyError("KEY_INVALID");
  const x = decode(key.x);
  const y = decode(key.y);
  const point = new Uint8Array(65);
  point[0] = 4;
  point.set(x, 1);
  point.set(y, 33);
  return point;
}

export function verifyJws(
  algorithm: string,
  signingInput: Uint8Array,
  signature: Uint8Array,
  inputKey: PublicJwk,
): boolean {
  try {
    const key = parsePublicJwk(inputKey);
    if (algorithm === "EdDSA" && key.kty === "OKP" && signature.length === 64) {
      return ed25519.verify(signature, signingInput, decode(key.x), { zip215: false });
    }
    if (algorithm === "ES256" && key.kty === "EC" && signature.length === 64) {
      return p256.verify(signature, signingInput, ecPoint(key), { prehash: true, lowS: false });
    }
    return false;
  } catch {
    return false;
  }
}

export function signJws(
  algorithm: JwsAlgorithm,
  signingInput: Uint8Array,
  privateKey: PrivateJwk,
): Uint8Array {
  const publicKey = publicJwkFromPrivate(privateKey);
  if ((algorithm === "EdDSA" && publicKey.kty !== "OKP") ||
    (algorithm === "ES256" && publicKey.kty !== "EC")) throw new KeyError("KEY_INVALID");
  const secret = decode(privateKey.d);
  if (algorithm === "EdDSA") return ed25519.sign(signingInput, secret);
  return p256.sign(signingInput, secret, { prehash: true, lowS: true });
}
