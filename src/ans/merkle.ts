import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "./bytes.js";

/**
 * Inclusion proofs follow RFC 9162 §2.1 (SHA-256).
 * draft-narajala-courtney-ansv2-01 §4.3 requires a SCITT transparency
 * service, and the cited draft-ietf-scitt-architecture-22 uses the
 * RFC9162_SHA256 verifiable data structure. §9.1 says a COSE receipt has
 * the same verification semantics: LeafHash(E), the audit path, and the
 * leaf index recompute root R.
 *
 * Leaf bytes are the JCS encoding of the lifecycle event (§5.6). The leaf
 * hash is SHA-256(0x00 || those bytes), which is RFC 9162's leaf domain
 * separation. The draft names SHA-256 but does not repeat the 0x00 prefix.
 */
export function leafHash(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(0x00, data));
}

function largestPowerOfTwoLessThan(size: number): number {
  let power = 1;
  while (power * 2 < size) power *= 2;
  return power;
}

export function merkleRoot(entries: Uint8Array[]): Uint8Array {
  const size = entries.length;
  if (size === 0) return sha256(new Uint8Array());
  if (size === 1) return leafHash(entries[0]!);
  const split = largestPowerOfTwoLessThan(size);
  return sha256(concatBytes(0x01, merkleRoot(entries.slice(0, split)), merkleRoot(entries.slice(split))));
}

export function inclusionProof(entries: Uint8Array[], index: number): Uint8Array[] {
  const size = entries.length;
  if (!Number.isSafeInteger(index) || index < 0 || index >= size) {
    throw new RangeError("leaf index is outside the tree");
  }
  if (size === 1) return [];
  const split = largestPowerOfTwoLessThan(size);
  if (index < split) return [...inclusionProof(entries.slice(0, split), index), merkleRoot(entries.slice(split))];
  return [...inclusionProof(entries.slice(split), index - split), merkleRoot(entries.slice(0, split))];
}

function rshift(value: number): number {
  return Math.floor(value / 2);
}

/** RFC 9162 §2.1.3.2. `hash` is the leaf hash, not the raw leaf bytes. */
export function verifyInclusion(
  hash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  path: readonly Uint8Array[],
  root: Uint8Array,
): boolean {
  if (hash.length !== 32 || root.length !== 32 || path.length > 64) return false;
  if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize)) return false;
  if (leafIndex < 0 || treeSize < 1 || leafIndex >= treeSize) return false;
  if (path.some((node) => node.length !== 32)) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let folded = hash;
  for (const sibling of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      folded = sha256(concatBytes(0x01, sibling, folded));
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = rshift(fn);
          sn = rshift(sn);
        }
      }
    } else {
      folded = sha256(concatBytes(0x01, folded, sibling));
    }
    fn = rshift(fn);
    sn = rshift(sn);
  }
  if (sn !== 0 || folded.length !== root.length) return false;
  let difference = 0;
  for (let index = 0; index < folded.length; index++) difference |= folded[index]! ^ root[index]!;
  return difference === 0;
}
