# Trust Material

This directory contains trust material for Sigstore verification.

## tuf-root.json

**Source**: Extracted from [sigstore-js/packages/tuf/seeds.json](https://github.com/sigstore/sigstore-js/blob/main/packages/tuf/seeds.json)

**Purpose**: Bootstrap TUF (The Update Framework) client with a pinned root of trust for the Sigstore TUF repository.

**Content**: Base64-encoded TUF `root.json` metadata for `https://tuf-repo-cdn.sigstore.dev`
- Type: TUF root metadata (version 13)
- Expires: 2026-01-22
- Contains: 5 root signing keys with threshold signature requirement

**Security**: This file prevents MITM attacks during TUF initialization by embedding the initial root metadata instead of fetching it from the network. The TUF client uses this to verify all subsequent TUF metadata updates.

**Updates**: Should be updated when sigstore-js updates its embedded TUF root. Check the sigstore-js repository for the latest version.

## Trust Material Flow

1. **TUF Bootstrap**: `tuf-root.json` → TUF client initialization
2. **TUF Metadata Updates**: TUF client fetches and verifies latest metadata
3. **Sigstore Trust Material**: TUF delivers `trusted_root.json` (CAs, CT logs, TLogs, TSAs)
4. **Verification**: Sigstore verifier uses the trust material to verify signatures

This matches the sigstore-js architecture: TUF provides always up-to-date trust material rather than using static embedded files that can become outdated.

## Why No Static `trusted_root.json`?

Unlike some implementations, we do **not** embed a static `trusted_root.json` file. Here's why:

- **Outdated Material**: Static trust roots become outdated (e.g., expired certificates, new CAs, rotated keys)
- **Reviewer Issues**: Previous embedded files had incorrect `validFor` dates and mismatched certificate subjects
- **TUF Purpose**: TUF exists specifically to deliver fresh, verified trust material - using it is the correct approach
- **Matches Reference**: sigstore-js uses TUF exclusively, with no static fallback

The CLI always uses TUF to fetch `trusted_root.json`, ensuring correctness and freshness.
