import { base64ToUint8Array, toArrayBuffer } from "../encoding.js";
import type { TLogEntry } from "../bundle.js";

const RFC6962_LEAF_HASH_PREFIX = new Uint8Array([0x00]);
const RFC6962_NODE_HASH_PREFIX = new Uint8Array([0x01]);

export async function verifyMerkleInclusion(
  entry: TLogEntry
): Promise<void> {
  if (!entry.inclusionProof) {
    throw new Error("Missing inclusion proof");
  }

  const inclusionProof = entry.inclusionProof;
  const logIndex = BigInt(inclusionProof.logIndex);
  const treeSize = BigInt(inclusionProof.treeSize);

  if (logIndex < 0n || logIndex >= treeSize) {
    throw new Error(`Invalid log index: ${logIndex}`);
  }

  const { inner, border } = decompInclProof(logIndex, treeSize);

  if (inclusionProof.hashes.length !== inner + border) {
    throw new Error("Invalid hash count in inclusion proof");
  }

  const innerHashes = inclusionProof.hashes
    .slice(0, inner)
    .map((h) => base64ToUint8Array(h));
  const borderHashes = inclusionProof.hashes
    .slice(inner)
    .map((h) => base64ToUint8Array(h));

  const leafHash = await hashLeaf(base64ToUint8Array(entry.canonicalizedBody));

  const calculatedHash = await chainBorderRight(
    await chainInner(leafHash, innerHashes, logIndex),
    borderHashes
  );

  const rootHash = base64ToUint8Array(inclusionProof.rootHash);

  if (!uint8ArrayEqual(calculatedHash, rootHash)) {
    throw new Error("Calculated root hash does not match inclusion proof");
  }
}

function decompInclProof(
  index: bigint,
  size: bigint
): { inner: number; border: number } {
  const inner = innerProofSize(index, size);
  const border = onesCount(index >> BigInt(inner));
  return { inner, border };
}

async function chainInner(
  seed: Uint8Array,
  hashes: Uint8Array[],
  index: bigint
): Promise<Uint8Array> {
  let acc = seed;
  for (let i = 0; i < hashes.length; i++) {
    const h = hashes[i];
    if ((index >> BigInt(i)) & BigInt(1)) {
      acc = await hashChildren(h, acc);
    } else {
      acc = await hashChildren(acc, h);
    }
  }
  return acc;
}

async function chainBorderRight(
  seed: Uint8Array,
  hashes: Uint8Array[]
): Promise<Uint8Array> {
  let acc = seed;
  for (const h of hashes) {
    acc = await hashChildren(h, acc);
  }
  return acc;
}

function innerProofSize(index: bigint, size: bigint): number {
  return bitLength(index ^ (size - BigInt(1)));
}

function onesCount(num: bigint): number {
  return num.toString(2).split("1").length - 1;
}

function bitLength(n: bigint): number {
  if (n === 0n) {
    return 0;
  }
  return n.toString(2).length;
}

async function hashChildren(
  left: Uint8Array,
  right: Uint8Array
): Promise<Uint8Array> {
  const data = new Uint8Array(
    RFC6962_NODE_HASH_PREFIX.length + left.length + right.length
  );
  data.set(RFC6962_NODE_HASH_PREFIX, 0);
  data.set(left, RFC6962_NODE_HASH_PREFIX.length);
  data.set(right, RFC6962_NODE_HASH_PREFIX.length + left.length);

  const hash = await crypto.subtle.digest("SHA-256", toArrayBuffer(data));
  return new Uint8Array(hash);
}

async function hashLeaf(leaf: Uint8Array): Promise<Uint8Array> {
  const data = new Uint8Array(RFC6962_LEAF_HASH_PREFIX.length + leaf.length);
  data.set(RFC6962_LEAF_HASH_PREFIX, 0);
  data.set(leaf, RFC6962_LEAF_HASH_PREFIX.length);

  const hash = await crypto.subtle.digest("SHA-256", toArrayBuffer(data));
  return new Uint8Array(hash);
}

function uint8ArrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}
