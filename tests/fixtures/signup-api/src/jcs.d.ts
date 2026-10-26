/** Type bridge only; adjacent JavaScript remains the byte-pinned API fixture. */
export function canonicalizeJson(value: unknown): string;
export function parseCanonicalJson(value: string): unknown;
export function isPlainObject(value: unknown): value is Record<string, unknown>;
