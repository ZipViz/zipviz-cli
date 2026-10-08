import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { concatBytes, toHex } from "../src/ans/bytes.js";
import { inclusionProof, leafHash, merkleRoot, verifyInclusion } from "../src/ans/merkle.js";

function stackRoot(entries: Uint8Array[]): Uint8Array {
  if (entries.length === 0) return sha256(new Uint8Array());
  const stack: Uint8Array[] = [];
  const merge = (): void => {
    const right = stack.pop();
    const left = stack.pop();
    if (!left || !right) throw new Error("unbalanced merkle stack");
    stack.push(sha256(concatBytes(0x01, left, right)));
  };
  for (let index = 0; index < entries.length; index++) {
    stack.push(leafHash(entries[index]!));
    let trailingOnes = 0;
    let shifted = index;
    while (shifted % 2 === 1) {
      trailingOnes++;
      shifted = Math.floor(shifted / 2);
    }
    for (let count = 0; count < trailingOnes; count++) merge();
  }
  while (stack.length > 1) merge();
  return stack[0]!;
}

describe("RFC 9162 SHA-256 inclusion proofs", () => {
  it("hashes the empty tree as SHA-256 of the empty string", () => {
    expect(toHex(merkleRoot([]))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("matches the RFC 9162 stack construction and the §2.1.5 path lengths", () => {
    const seven = Array.from({ length: 7 }, (_, index) => Uint8Array.of(index));
    expect(inclusionProof(seven, 0)).toHaveLength(3);
    expect(inclusionProof(seven, 3)).toHaveLength(3);
    expect(inclusionProof(seven, 4)).toHaveLength(3);
    expect(inclusionProof(seven, 6)).toHaveLength(2);
    for (let size = 0; size <= 17; size++) {
      const entries = Array.from({ length: size }, (_, index) => Uint8Array.of(index, size));
      const root = merkleRoot(entries);
      expect(toHex(root)).toBe(toHex(stackRoot(entries)));
      for (let index = 0; index < size; index++) {
        const proof = inclusionProof(entries, index);
        expect(verifyInclusion(leafHash(entries[index]!), index, size, proof, root)).toBe(true);
        if (proof.length > 0) {
          const tampered = proof.map((node) => new Uint8Array(node));
          tampered[0]![0]! ^= 0xff;
          expect(verifyInclusion(leafHash(entries[index]!), index, size, tampered, root)).toBe(false);
        }
      }
    }
  });

  it("rejects an empty path for a tree larger than one leaf", () => {
    const entries = [Uint8Array.of(1), Uint8Array.of(2)];
    expect(verifyInclusion(leafHash(entries[0]!), 0, 2, [], merkleRoot(entries))).toBe(false);
  });
});
