export function escapeTerminal(text: string): string {
  return Array.from(text, (character) => {
    const codePoint = character.codePointAt(0)!;
    const shouldEscape = codePoint <= 0x1f || codePoint === 0x7f ||
      (codePoint >= 0x80 && codePoint <= 0x9f) ||
      codePoint === 0x061c || codePoint === 0x200e || codePoint === 0x200f ||
      codePoint === 0x2028 || codePoint === 0x2029 ||
      (codePoint >= 0x202a && codePoint <= 0x202e) ||
      (codePoint >= 0x2066 && codePoint <= 0x2069);
    if (!shouldEscape) return character;
    const hexadecimal = codePoint.toString(16).padStart(codePoint <= 0xff ? 2 : 4, "0");
    return codePoint <= 0xff ? `\\x${hexadecimal}` : `\\u${hexadecimal}`;
  }).join("");
}
