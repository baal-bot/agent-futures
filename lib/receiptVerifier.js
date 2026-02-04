const crypto = require('crypto');

/**
 * Minimal RFC 8785 (JCS) style canonicalization for JSON values.
 * - Objects: keys sorted lexicographically (Unicode code points)
 * - Arrays: preserved order
 * - Primitives: encoded using JSON.stringify
 *
 * Notes:
 * - This is sufficient for the fixture set and reference verifier.
 * - If you need full RFC8785 edge-case compatibility (numbers), swap this
 *   for a dedicated JCS implementation.
 */
function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

function b64ToBuf(b64) {
  // accept base64 or base64url
  const norm = b64.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(norm, 'base64');
}

function isIsoDateTime(s) {
  // strict enough for receipts (must parse & must include timezone)
  return typeof s === 'string' && /Z$|[+-]\d\d:\d\d$/.test(s) && !Number.isNaN(Date.parse(s));
}

/**
 * Verify an attestation receipt payload (attestation.json) and detached Ed25519 signature.
 *
 * @param {object} params
 * @param {object} params.attestation - JSON payload
 * @param {string|Buffer} params.signature - base64/base64url string or raw bytes
 * @param {string|Buffer|crypto.KeyObject} params.publicKey - PEM or KeyObject
 * @param {Date|string|number} [params.now] - time for expiry checks
 * @param {Set<string>} [params.seen] - replay cache of receipt ids
 * @param {boolean} [params.markSeen] - if true, add id to seen set on success
 * @param {Set<string>} [params.revoked] - revoked receipt ids
 * @returns {{ok:boolean,hits:Array<{rule:string,ok:boolean,detail?:string}>,canonical:string}}
 */
function verifyReceipt({ attestation, signature, publicKey, now = new Date(), seen, markSeen = false, revoked } = {}) {
  const hits = [];

  // Basic shape
  if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
    hits.push({ rule: 'payload.isObject', ok: false, detail: 'attestation must be a JSON object' });
    return { ok: false, hits, canonical: '' };
  }
  hits.push({ rule: 'payload.isObject', ok: true });

  // Required fields
  const required = ['receipt_version', 'id', 'issuer', 'subject', 'issuanceDate', 'credentialSubject'];
  const missing = required.filter(k => !(k in attestation));
  if (missing.length) {
    hits.push({ rule: 'payload.requiredFields', ok: false, detail: `missing: ${missing.join(', ')}` });
  } else {
    hits.push({ rule: 'payload.requiredFields', ok: true });
  }

  // Version
  if (attestation.receipt_version !== '0.1') {
    hits.push({ rule: 'payload.receipt_version', ok: false, detail: 'must equal "0.1"' });
  } else {
    hits.push({ rule: 'payload.receipt_version', ok: true });
  }

  // Dates
  if (!isIsoDateTime(attestation.issuanceDate)) {
    hits.push({ rule: 'payload.issuanceDate', ok: false, detail: 'must be ISO-8601 date-time with timezone' });
  } else {
    hits.push({ rule: 'payload.issuanceDate', ok: true });
  }

  if ('expirationDate' in attestation) {
    if (!isIsoDateTime(attestation.expirationDate)) {
      hits.push({ rule: 'payload.expirationDate.format', ok: false, detail: 'must be ISO-8601 date-time with timezone' });
    } else {
      hits.push({ rule: 'payload.expirationDate.format', ok: true });
      const tNow = now instanceof Date ? now : new Date(now);
      const tExp = new Date(attestation.expirationDate);
      if (tNow.getTime() > tExp.getTime()) {
        hits.push({ rule: 'payload.expirationDate.notExpired', ok: false, detail: 'receipt is expired' });
      } else {
        hits.push({ rule: 'payload.expirationDate.notExpired', ok: true });
      }
    }
  } else {
    hits.push({ rule: 'payload.expirationDate.optional', ok: true, detail: 'no expirationDate provided' });
  }

  // Revocation
  if (revoked && attestation.id && revoked.has(attestation.id)) {
    hits.push({ rule: 'revocation.notRevoked', ok: false, detail: 'receipt id is revoked' });
  } else {
    hits.push({ rule: 'revocation.notRevoked', ok: true });
  }

  // Replay
  if (seen && attestation.id && seen.has(attestation.id)) {
    hits.push({ rule: 'replay.notSeenBefore', ok: false, detail: 'receipt id already seen' });
  } else {
    hits.push({ rule: 'replay.notSeenBefore', ok: true });
  }

  // Canonicalization & signature
  const canonical = canonicalize(attestation);
  const data = Buffer.from(canonical, 'utf8');

  let sigBuf;
  if (Buffer.isBuffer(signature)) sigBuf = signature;
  else if (typeof signature === 'string') sigBuf = b64ToBuf(signature);
  else sigBuf = Buffer.alloc(0);

  if (sigBuf.length !== 64) {
    hits.push({ rule: 'signature.length', ok: false, detail: `expected 64 bytes Ed25519 signature, got ${sigBuf.length}` });
  } else {
    hits.push({ rule: 'signature.length', ok: true });
  }

  let verified = false;
  try {
    const keyObj = publicKey instanceof crypto.KeyObject ? publicKey : crypto.createPublicKey(publicKey);
    verified = crypto.verify(null, data, keyObj, sigBuf);
  } catch (e) {
    hits.push({ rule: 'signature.verify', ok: false, detail: `verification error: ${e.message}` });
    return { ok: false, hits, canonical };
  }

  hits.push({ rule: 'signature.verify', ok: verified, detail: verified ? undefined : 'invalid signature' });

  const ok = hits.every(h => h.ok);
  if (ok && seen && markSeen && attestation.id) {
    seen.add(attestation.id);
  }

  return { ok, hits, canonical };
}

module.exports = {
  canonicalize,
  verifyReceipt,
};
