# Attestation Receipts v0.1 (Detached Ed25519)

This document specifies **Agent Futures Attestation Receipts v0.1**.

A receipt is two files:

- `attestation.json` — the receipt payload (JSON)
- `attestation.sig` — a **detached** Ed25519 signature over the canonicalized payload

This format is designed to be:

- simple (no JSON-LD required)
- portable across systems
- verifiable with standard Ed25519 tooling

## 1. Signing input (canonicalization)

The signature is computed over the UTF-8 bytes of the **canonical JSON** string of `attestation.json`.

Canonicalization uses the JSON Canonicalization Scheme (**JCS**, RFC 8785):

- Objects: keys sorted lexicographically (Unicode code points)
- Arrays: order preserved
- No insignificant whitespace
- Strings: JSON escaping rules
- Numbers: RFC8785 / ECMAScript canonical JSON number formatting

**Reference implementation note:** this repo includes a minimal JCS-style canonicalizer in `lib/receiptVerifier.js`. For strict RFC8785 compatibility (especially number edge-cases), replace it with a dedicated JCS library.

### Signing steps

1. Parse `attestation.json` as JSON.
2. Canonicalize via JCS.
3. Compute signature: `Ed25519.sign(canonical_bytes)`.
4. Encode signature as Base64 (standard) or Base64URL.

## 2. Signature file format (`attestation.sig`)

`attestation.sig` is a text file containing:

- Base64 (or Base64URL) encoding of a **64-byte** Ed25519 signature.

No armor headers.

## 3. Payload format (`attestation.json`)

### 3.1 Required top-level fields

- `receipt_version` (string) — MUST equal `"0.1"`
- `id` (string) — unique receipt identifier (recommended `urn:uuid:<uuid>`)
- `issuer` (string) — issuer identifier (recommended DID)
- `subject` (string) — subject identifier (recommended DID)
- `issuanceDate` (string) — ISO-8601 date-time with timezone
- `credentialSubject` (object) — the attested content

### 3.2 Optional top-level fields

- `type` (array of strings) — e.g. `["TaskAttestationReceipt"]`
- `expirationDate` (string) — ISO-8601 date-time with timezone
- `nonce` (string) — random nonce to prevent accidental collisions
- `audience` (string) — intended verifier / relying party
- `schema` (string) — schema URI if desired
- `meta` (object) — issuer-specific metadata (should be stable and deterministic)

### 3.3 `credentialSubject` (recommended fields)

This repo historically uses a task attestation model similar to `schemas/attestation.json`.
For v0.1 receipts, `credentialSubject` SHOULD include:

- `taskType` (string)
- `taskHash` (string) — content-addressed hash of the task input
- `outputHash` (string) — content-addressed hash of the output
- `status` (string) — `completed|partial|failed|disputed`
- `duration_ms` (integer)
- `quality_score` (number 0..1)

## 4. Verification rules (v0.1)

A verifier MUST:

1. Parse `attestation.json` as JSON.
2. Check required fields exist and `receipt_version === "0.1"`.
3. Canonicalize the payload (RFC8785 JCS) and verify detached Ed25519 signature.
4. If `expirationDate` is present, ensure `now <= expirationDate`.

A verifier SHOULD additionally:

- ensure `issuanceDate` is well-formed and not in the far future (policy)
- enforce replay protection if the receipt is used for value transfer
- support revocation checks (see below)

The reference verifier in this repo returns `ok` plus a list of rule hits.

## 5. Replay model

Receipts are bearer artifacts; replay protection is **application-layer**.

For workflows where a receipt can be redeemed (e.g. payment, access, credit), the relying party SHOULD maintain a **replay cache** keyed by `id`.

Recommended policy:

- accept a receipt only once per relying party
- store `id` in a durable store (database) once accepted

The reference verifier supports an optional in-memory/durable `seen` set.

## 6. Revocation model

Revocation is also application-layer, but the format supports a simple model:

- Issuer publishes a revocation list of receipt IDs (`id` values).
- Relying party checks the list at verification time.

Recommended approach:

- issuer exposes `revocations.json` (or an API) containing a list of revoked receipt IDs
- (optional) issuer signs the revocation list using the same Ed25519 key

This repo’s reference verifier accepts a set of revoked IDs.

## 7. Fixtures & reference implementation

- Fixtures: `fixtures/attestation-receipts/cases/*`
- Reference verifier: `lib/receiptVerifier.js`
- CLI:
  - `node scripts/verify-receipt.js --attestation <path> --sig <path> --pubkey <path>`
  - `npm run verify:fixtures`

## 8. Security considerations

- Canonicalization MUST be identical between signer and verifier.
- Avoid floating point / non-canonical number representations in receipts.
- `meta` fields must be deterministic; non-determinism breaks signatures.
- Consider key rotation: use distinct `issuer` identifiers per key.
- Consider binding receipts to an `audience` to reduce cross-context replay.
