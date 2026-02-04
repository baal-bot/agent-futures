#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const { verifyReceipt } = require('../lib/receiptVerifier');

function usage(code = 1) {
  console.error(`Usage:
  verify-receipt --attestation <path> --sig <path> --pubkey <path> [--now <iso>] [--revocations <path>] [--seen <path>] [--mark-seen]

Notes:
  - Signature file should contain base64 (or base64url) Ed25519 signature.
  - Public key should be PEM (SubjectPublicKeyInfo).
`);
  process.exit(code);
}

function arg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return null;
  return process.argv[idx + 1] || null;
}

function hasFlag(name) {
  return process.argv.includes(name);
}

const attPath = arg('--attestation');
const sigPath = arg('--sig');
const pubPath = arg('--pubkey');
if (!attPath || !sigPath || !pubPath) usage(1);

const nowArg = arg('--now');
const revPath = arg('--revocations');
const seenPath = arg('--seen');
const markSeen = hasFlag('--mark-seen');

const attestation = JSON.parse(fs.readFileSync(path.resolve(attPath), 'utf8'));
const signature = fs.readFileSync(path.resolve(sigPath), 'utf8').trim();
const publicKey = fs.readFileSync(path.resolve(pubPath), 'utf8');

let revoked;
if (revPath) {
  const list = JSON.parse(fs.readFileSync(path.resolve(revPath), 'utf8'));
  revoked = new Set(Array.isArray(list) ? list : (list.revoked || []));
}

let seen;
if (seenPath) {
  if (fs.existsSync(seenPath)) {
    const list = JSON.parse(fs.readFileSync(seenPath, 'utf8'));
    seen = new Set(Array.isArray(list) ? list : (list.seen || []));
  } else {
    seen = new Set();
  }
}

const { ok, hits } = verifyReceipt({
  attestation,
  signature,
  publicKey,
  now: nowArg || new Date(),
  revoked,
  seen,
  markSeen,
});

if (seen && seenPath && markSeen) {
  fs.writeFileSync(seenPath, JSON.stringify({ seen: Array.from(seen).sort() }, null, 2));
}

console.log(JSON.stringify({ ok, hits }, null, 2));
process.exit(ok ? 0 : 2);
