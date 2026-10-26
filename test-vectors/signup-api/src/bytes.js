// ELU-634 build 3b. Byte, hex and base64 helpers for the ANS proof source.
//
// Every decoder here is strict: it refuses anything that is not the one
// canonical encoding of the bytes it returns. A signed structure that can be
// re-encoded two ways is a structure an attacker can restate, so a lenient
// decode would quietly widen what a signature covers.

const HEX = '0123456789abcdef';
const B64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const encoder = new TextEncoder();

export function utf8(text) {
  return encoder.encode(text);
}

// Fatal decoding: invalid UTF-8 is a refusal, not U+FFFD.
export function decodeUtf8(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

export function concatBytes(...parts) {
  const pieces = parts.map((part) => (typeof part === 'number' ? Uint8Array.of(part) : part));
  const out = new Uint8Array(pieces.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of pieces) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

export function toHex(bytes) {
  let hex = '';
  for (const byte of bytes) hex += HEX[byte >> 4] + HEX[byte & 0x0f];
  return hex;
}

export function fromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let index = 0; index < out.length; index++) {
    out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

// Equal length is not secret (it is the structure, not the value), the bytes are.
export function sameBytes(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) return false;
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index];
  return difference === 0;
}

function encodeBase64(bytes, alphabet, pad) {
  let out = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const remaining = bytes.length - index;
    const a = bytes[index];
    const b = remaining > 1 ? bytes[index + 1] : 0;
    const c = remaining > 2 ? bytes[index + 2] : 0;
    out += alphabet[a >> 2];
    out += alphabet[((a & 0x03) << 4) | (b >> 4)];
    out += remaining > 1 ? alphabet[((b & 0x0f) << 2) | (c >> 6)] : (pad ? '=' : '');
    out += remaining > 2 ? alphabet[c & 0x3f] : (pad ? '=' : '');
  }
  return out;
}

export function base64Encode(bytes) {
  return encodeBase64(bytes, B64_STD, true);
}

export function base64UrlEncode(bytes) {
  return encodeBase64(bytes, B64_URL, false);
}

function decodeBase64(text, alphabet, padded) {
  if (typeof text !== 'string') return null;
  const body = padded ? text.replace(/(={0,2})$/, '') : text;
  if (padded && text.length % 4 !== 0) return null;
  if (padded && text.length - body.length !== (4 - (body.length % 4)) % 4) return null;
  if (!padded && body.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((body.length * 6) / 8));
  let bits = 0;
  let value = 0;
  let offset = 0;
  for (const char of body) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) return null;
    value = (value << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[offset++] = (value >> bits) & 0xff;
    }
  }
  // Trailing bits that are not part of a byte must be zero, so one byte string
  // has exactly one encoding.
  if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) return null;
  return out;
}

export function base64Decode(text) {
  return decodeBase64(text, B64_STD, true);
}

export function base64UrlDecode(text) {
  return decodeBase64(text, B64_URL, false);
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}
