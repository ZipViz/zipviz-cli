const HEX = "0123456789abcdef";

export function concatBytes(...parts: Array<Uint8Array | number>): Uint8Array {
  const pieces = parts.map((part) => typeof part === "number" ? Uint8Array.of(part) : part);
  const out = new Uint8Array(pieces.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of pieces) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += HEX[byte >> 4]! + HEX[byte & 0x0f]!;
  return hex;
}

export function fromHex(hex: string): Uint8Array | undefined {
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) return undefined;
  const out = new Uint8Array(hex.length / 2);
  for (let index = 0; index < out.length; index++) {
    out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}
