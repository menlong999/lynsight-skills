'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash, X509Certificate } = require('node:crypto');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const https = require('node:https');
const { tmpdir } = require('node:os');
const tls = require('node:tls');
const { join } = require('node:path');
const { test } = require('node:test');
const { httpsJSON, checkCall, scanCredentials, checkScanProof } = require('../scripts/lynsight.cjs');

test('scan proof binds approval to the QR secret and is separate from the claim ticket', () => {
  const first = scanCredentials(Buffer.alloc(32, 1));
  const second = scanCredentials(Buffer.alloc(32, 2));
  assert.equal(new Set([first.id, first.proof, first.ticket]).size, 3);
  assert.doesNotThrow(() => checkScanProof(first.proof, first.proof));
  assert.throws(() => checkScanProof(first.proof, second.proof), /scan_proof_mismatch/);
  assert.throws(() => checkScanProof(first.proof, first.ticket), /scan_proof_mismatch/);
});

test('uses optional arguments declared by the phone without hardcoding operation IDs', () => {
  const manifest = { version: 1, operations: [{
    id: 'new_search', arguments: [{ name: 'days', type: 'integer', required: true }],
  }] };
  assert.deepEqual(checkCall(manifest, 'new_search', { days: 7 }), { id: 'new_search', days: 7 });
  assert.throws(() => checkCall(manifest, 'new_search', { days: '7' }), /invalid_arguments/);
});

test('pinned HTTPS protects credentials and distinguishes pending from denied pairing', async t => {
  const connect = tls.connect;
  t.mock.method(tls, 'connect', options => connect({ ...options, host: '127.0.0.1' }));
  const directory = mkdtempSync(join(tmpdir(), 'lynsight-pin-test-'));
  let server;
  try {
    const keyFile = join(directory, 'key.pem');
    const certFile = join(directory, 'cert.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-nodes', '-subj', '/CN=Lynsight Test', '-days', '1', '-keyout', keyFile, '-out', certFile], { stdio: 'ignore' });
    const cert = readFileSync(certFile);
    const pin = createHash('sha256').update(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    const requests = [];
    let pairingDenied = false;
    server = https.createServer({ key: readFileSync(keyFile), cert, minVersion: 'TLSv1.3' }, (request, response) => {
      requests.push(request.headers.authorization);
      if (request.url === '/v1/pair/proof') {
        response.statusCode = pairingDenied ? 403 : 202;
        response.end(JSON.stringify({ error: pairingDenied ? 'pairing_denied' : 'pairing_pending' }));
      } else {
        response.end('{"ok":true}');
      }
    });
    await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
    const url = `https://192.168.1.8:${server.address().port}`;
    const token = 'synthetic-fixture-credential';
    await assert.rejects(httpsJSON(url, '0'.repeat(64), '/v1/capabilities', { token }), /phone_identity_mismatch/);
    assert.deepEqual(requests, []);
    assert.deepEqual(await httpsJSON(url, pin, '/v1/capabilities', { token }), { ok: true });
    assert.deepEqual(requests, [`Bearer ${token}`]);
    const requestProof = () => httpsJSON(url, pin, '/v1/pair/proof', { method: 'POST', token });
    await assert.rejects(requestProof(), { message: 'pairing_pending' });
    pairingDenied = true;
    await assert.rejects(requestProof(), { message: 'pairing_denied' });
  } finally {
    if (server?.listening) await new Promise(resolve => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  }
});
