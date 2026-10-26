/** Type bridge only; adjacent JavaScript remains the byte-pinned API fixture. */
export function utf8(text: string): Uint8Array;
export function decodeUtf8(bytes: Uint8Array): string | null;
export function concatBytes(...parts: Array<Uint8Array | number>): Uint8Array;
export function toHex(bytes: Uint8Array): string;
export function fromHex(text: string): Uint8Array | null;
export function base64Encode(bytes: Uint8Array): string;
export function base64UrlEncode(bytes: Uint8Array): string;
export function base64Decode(text: string): Uint8Array | null;
export function base64UrlDecode(text: string): Uint8Array | null;
export function sha256(bytes: Uint8Array): Promise<Uint8Array>;
