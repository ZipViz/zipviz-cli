/** Type bridge only; adjacent JavaScript remains the byte-pinned API fixture. */
export interface Signature { alg: "Ed25519"; key_id: string; value_base64url: string }
export interface Signed { schema_version: "1.0"; type: string; audience: string; issued_at_ms: number; signature: Signature }
export interface StartProof extends Signed { signup_id: string; public_key: string; bound_digest: string }
export interface StartRequest {
  proof: StartProof; name: string; owner_email: string;
  runtime: "claude" | "codex" | "buzz" | "openclaw" | "hermes" | "other";
  introduced_by: string | null;
}
export interface Cancel extends Signed { signup_id: string; nonce: string }
export interface Policy extends Signed { domain: string; incarnation: string }
export interface Intro extends Signed { id: string; introducer: string; introducer_incarnation: string; expires_at_ms: number }
export interface Authority { domain: string; public_key: string; incarnation: string; revision: number }
export const SIGNUP_DOMAINS: Readonly<Record<"start" | "cancel" | "intro" | "policy", string>>;
export class SignupCodecError extends Error { status: number; code: string }
export function parseSignupStart(text: string): StartRequest;
export function parseSignupCancel(text: string): Cancel;
export function parseIntroPolicy(text: string): Policy;
export function parseIntroToken(token: string): Intro;
export function verifySignupStart(body: unknown, audience: string): Promise<StartRequest>;
export function verifySignupCancel(body: unknown, publicKey: string, audience: string): Promise<Cancel>;
export function verifyIntroPolicy(body: unknown, publicKey: string, audience: string): Promise<Policy>;
export function verifyIntroToken(token: Intro | string, authority: Authority, now: number, audience: string): Promise<{ intro: Intro; authority: Authority }>;
export function signupSigningBytes(object: unknown, domain: string): Uint8Array;
export function signupRequestDigest(text: string): Promise<string>;
export function signupKeyId(publicKey: string): Promise<string>;
export function signupSubjectId(domain: string, incarnation: string): Promise<string>;
export function signupBoundDigest(request: Pick<StartRequest, "owner_email" | "runtime" | "introduced_by">): Promise<string>;
export function assertSignupFresh(issuedAt: number, now: number): void;
