/*
 * HashedRekord transparency log entry verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/tlog/hashedrekord.ts
 *
 * Key differences from sigstore-js:
 * - Browser-compatible: uses Uint8Array instead of Buffer for binary data
 * - Direct bundle field comparison instead of SignatureContent abstraction
 */

import { base64ToUint8Array, hexToUint8Array, uint8ArrayEqual } from "../encoding.js";
import type { SigstoreBundle } from "../bundle.js";
import type { RekorEntry } from "./body.js";

interface HashedRekordSpec {
  signature: {
    content: string;
    publicKey: {
      content: string;
    };
  };
  data: {
    hash: {
      algorithm: string;
      value: string;
    };
  };
}

interface HashedRekordEntry extends RekorEntry {
  apiVersion: "0.0.1";
  kind: "hashedrekord";
  spec: HashedRekordSpec;
}

export async function verifyHashedRekordBody(
  entry: RekorEntry,
  bundle: SigstoreBundle
): Promise<void> {
  const hashedRekordEntry = entry as HashedRekordEntry;

  switch (hashedRekordEntry.apiVersion) {
    case "0.0.1":
      return verifyHashedRekordTLogBody(hashedRekordEntry, bundle);
    default:
      throw new Error(
        `Unsupported hashedrekord version: ${hashedRekordEntry.apiVersion}`
      );
  }
}

function verifyHashedRekordTLogBody(
  entry: HashedRekordEntry,
  bundle: SigstoreBundle
): void {
  if (!bundle.messageSignature) {
    throw new Error("Bundle missing messageSignature for hashedrekord entry");
  }

  const tlogSig = entry.spec.signature.content || "";
  const tlogSigBytes = base64ToUint8Array(tlogSig);
  const bundleSigBytes = base64ToUint8Array(bundle.messageSignature.signature);

  if (!uint8ArrayEqual(tlogSigBytes, bundleSigBytes)) {
    throw new Error("Signature mismatch between TLog entry and bundle");
  }

  const tlogDigest = entry.spec.data.hash?.value || "";
  const tlogDigestBytes = hexToUint8Array(tlogDigest);
  const bundleDigestBytes = base64ToUint8Array(
    bundle.messageSignature.messageDigest.digest
  );

  if (!uint8ArrayEqual(tlogDigestBytes, bundleDigestBytes)) {
    throw new Error("Digest mismatch between TLog entry and bundle");
  }

  const tlogCert = entry.spec.signature.publicKey.content || "";
  const tlogCertBytes = base64ToUint8Array(tlogCert);

  let bundleCertBytes: Uint8Array;
  if (bundle.verificationMaterial.certificate) {
    bundleCertBytes = base64ToUint8Array(
      bundle.verificationMaterial.certificate.rawBytes
    );
  } else if (bundle.verificationMaterial.x509CertificateChain) {
    bundleCertBytes = base64ToUint8Array(
      bundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes
    );
  } else {
    throw new Error("Bundle missing certificate");
  }

  if (!uint8ArrayEqual(tlogCertBytes, bundleCertBytes)) {
    throw new Error("Certificate mismatch between TLog entry and bundle");
  }
}
