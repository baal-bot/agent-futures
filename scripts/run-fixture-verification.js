#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const { verifyReceipt } = require('../lib/receiptVerifier');

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'attestation-receipts', 'cases');

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function readText(p) {
  return fs.readFileSync(p, 'utf8').trim();
}

const cases = fs.readdirSync(FIXTURES).filter(d => fs.statSync(path.join(FIXTURES, d)).isDirectory());

let failed = 0;
for (const c of cases) {
  const dir = path.join(FIXTURES, c);
  const meta = readJson(path.join(dir, 'case.json'));

  const attestation = readJson(path.join(dir, 'attestation.json'));
  const signature = readText(path.join(dir, 'attestation.sig'));
  const publicKey = fs.readFileSync(path.join(dir, meta.publicKey), 'utf8');

  const revoked = meta.revokedIds ? new Set(meta.revokedIds) : undefined;
  const seen = meta.enableReplayCache ? new Set() : undefined;

  // run 1
  const r1 = verifyReceipt({
    attestation,
    signature,
    publicKey,
    now: meta.now || new Date(),
    revoked,
    seen,
    markSeen: meta.enableReplayCache,
  });

  let r2;
  if (meta.secondRun) {
    r2 = verifyReceipt({
      attestation,
      signature,
      publicKey,
      now: meta.now || new Date(),
      revoked,
      seen,
      markSeen: meta.enableReplayCache,
    });
  }

  const ok1 = r1.ok === meta.expect.ok;
  const ok2 = meta.secondRun ? (r2.ok === meta.secondRun.expect.ok) : true;

  if (!ok1 || !ok2) {
    failed++;
    console.error(`\n[FAIL] ${c}`);
    console.error(' expected run1:', meta.expect, ' got:', { ok: r1.ok });
    if (meta.secondRun) console.error(' expected run2:', meta.secondRun.expect, ' got:', { ok: r2.ok });
    console.error(' hits run1:', r1.hits);
    if (meta.secondRun) console.error(' hits run2:', r2.hits);
  } else {
    console.log(`[OK] ${c}`);
  }
}

if (failed) {
  console.error(`\n${failed} fixture case(s) failed`);
  process.exit(1);
}

console.log(`\nAll ${cases.length} fixture case(s) passed`);
