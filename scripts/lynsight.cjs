#!/usr/bin/env node
'use strict';

const { execFile, spawnSync } = require('node:child_process');
const { createHash, createHmac, randomBytes, timingSafeEqual } = require('node:crypto');
const { mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { lookup } = require('node:dns/promises');
const https = require('node:https');
const { isIPv4 } = require('node:net');
const { hostname, platform, tmpdir } = require('node:os');
const { join } = require('node:path');
const tls = require('node:tls');

const service = 'lynsight-library.lan.v1';
const account = 'local-client';
const type = '_lynsight._tcp';
const fingerprintPattern = /^[0-9a-f]{64}$/;
const tokenPattern = /^[A-Za-z0-9+/]{43}=$/;

function isPrivateIPv4(host) {
  if (!isIPv4(host)) return false;
  const [a, b] = host.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 169 && b === 254);
}

function localAddress(value) {
  let url;
  try { url = new URL(value); } catch { throw Error('invalid_address'); }
  if (url.protocol !== 'https:' || !isIPv4(url.hostname) || !url.port ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw Error('invalid_address');
  }
  if (!isPrivateIPv4(url.hostname)) throw Error('local_address_required');
  return url;
}

function dialPhone(url, expectedPin, ready) {
  const socket = tls.connect({
    host: url.hostname, port: Number(url.port), minVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1'], rejectUnauthorized: false,
  });
  const failed = () => ready(Error('phone_unreachable'));
  socket.once('error', failed);
  socket.setTimeout(5000, () => socket.destroy(Error('timeout')));
  socket.once('secureConnect', () => {
    socket.removeListener('error', failed);
    try {
      const cert = socket.getPeerX509Certificate();
      const actual = createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
      if ((expectedPin && actual !== expectedPin) ||
          !(Date.parse(cert.validFrom) <= Date.now() && Date.now() < Date.parse(cert.validTo))) {
        throw Error('phone_identity_mismatch');
      }
      socket.setTimeout(0);
      ready(null, socket, actual);
    } catch {
      socket.destroy();
      ready(Error('phone_identity_mismatch'));
    }
  });
}

function httpsJSON(address, pin, path, { method = 'GET', token, payload } = {}) {
  const url = localAddress(address);
  if (!fingerprintPattern.test(pin)) throw Error('invalid_fingerprint');
  const body = payload === undefined ? undefined : JSON.stringify(payload);
  if (body && Buffer.byteLength(body) > 8192) throw Error('invalid_arguments');
  const agent = new https.Agent({ keepAlive: false });
  agent.createConnection = (_, ready) => {
    dialPhone(url, pin, (error, socket) => ready(error, socket));
  };
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      path, method, agent,
      headers: {
        Accept: 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    }, response => {
      let size = 0;
      const pieces = [];
      response.on('data', piece => {
        size += piece.length;
        if (size > 128 * 1024) request.destroy(Error('response_too_large'));
        else pieces.push(piece);
      });
      response.on('error', reject);
      response.on('end', () => {
        let result;
        try { result = JSON.parse(Buffer.concat(pieces).toString('utf8')); }
        catch { return reject(Error('invalid_phone_response')); }
        if (response.statusCode !== 200) {
          const code = result?.error;
          return reject(Error(typeof code === 'string' && /^[a-z_]{1,40}$/.test(code) ? code : 'request_failed'));
        }
        resolve(result);
      });
    });
    request.setTimeout(20000, () => request.destroy(Error('request_timeout')));
    request.on('error', reject);
    request.on('close', () => agent.destroy());
    request.end(body);
  });
}

const windowsVault = String.raw`
$ErrorActionPreference = 'Stop'
$p = Join-Path $env:LOCALAPPDATA 'LynsightLibrary'
$f = Join-Path $p 'credential.v1'
$inputValue = [Console]::In.ReadToEnd()
if ($inputValue.Length -eq 0) {
  if (Test-Path -LiteralPath $f) {
    $secret = Get-Content -LiteralPath $f -Raw | ConvertTo-SecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try { [Console]::Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
  }
} else {
  [void][IO.Directory]::CreateDirectory($p)
  $secret = ConvertTo-SecureString -String $inputValue -AsPlainText -Force
  $encoded = ConvertFrom-SecureString -SecureString $secret
  $temp = Join-Path $p ([Guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [IO.File]::WriteAllText($temp, $encoded)
    if ([IO.File]::Exists($f)) { [IO.File]::Replace($temp, $f, $null) }
    else { [IO.File]::Move($temp, $f) }
  } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}
`;

function vault(value) {
  const options = { encoding: 'utf8', timeout: 10000, windowsHide: true };
  if (platform() === 'darwin') {
    if (value !== undefined) {
      const result = spawnSync('/usr/bin/security', ['-i'], {
        ...options, input: `add-generic-password -U -s ${service} -a ${account} -w ${value}\n`,
      });
      if (result.status !== 0 || vault() !== value) throw Error('credential_store_unavailable');
      return;
    }
    const result = spawnSync('/usr/bin/security', ['find-generic-password', '-s', service, '-a', account, '-w'], options);
    if (result.status === 44) return '';
    if (result.status !== 0) throw Error('credential_store_unavailable');
    return result.stdout.trim();
  }
  if (platform() === 'win32') {
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', windowsVault], {
      ...options, input: value ?? '',
    });
    if (result.status !== 0) throw Error('credential_store_unavailable');
    return result.stdout.trim();
  }
  throw Error('unsupported_platform');
}

function state() {
  const value = vault();
  return value ? JSON.parse(Buffer.from(value, 'base64').toString('utf8')) : {};
}

function save(value) { vault(Buffer.from(JSON.stringify(value), 'utf8').toString('base64')); }

function browseCommand(args) {
  return new Promise(resolve => {
    const program = '/usr/bin/dns-sd';
    const process = execFile(program, args, { timeout: 2500, windowsHide: true }, (_, output) => resolve(output ?? ''));
    process.stdin?.end();
  });
}

async function discover() {
  if (platform() === 'win32') return discoverWithBonjour();
  const browse = await browseCommand(['-B', type, 'local.']);
  const names = [...new Set(browse.match(/\bLynsight-[0-9a-f]{12}\b/g) ?? [])].slice(0, 8);
  const found = await Promise.all(names.map(async name => {
    try {
      const detail = await browseCommand(['-L', name, type, 'local.']);
      const match = detail.match(/can be reached at ([^\s:]+):(\d+)/i);
      if (!match) return null;
      const addresses = await lookup(match[1], { family: 4, all: true });
      const selected = addresses.find(entry => isPrivateIPv4(entry.address));
      if (!selected) return null;
      return { name, address: localAddress(`https://${selected.address}:${match[2]}`).origin };
    } catch { return null; }
  }));
  return found.filter(Boolean);
}

async function discoverWithBonjour() {
  const { Bonjour } = require('./pairing-vendor.cjs');
  const found = new Map();
  let failed = false;
  const bonjour = new Bonjour(undefined, () => { failed = true; });
  bonjour.server.mdns.on('error', () => { failed = true; });
  const browser = bonjour.find({ type: 'lynsight', protocol: 'tcp' }, service => {
    const { name, port } = service;
    if (!/^Lynsight-[0-9a-f]{12}$/.test(name) || !port || found.has(name) || found.size >= 8) return;
    found.set(name, (async () => {
      try {
        let address = service.addresses?.find(isPrivateIPv4);
        if (!address && typeof service.host === 'string' && /\.local\.?$/i.test(service.host)) {
          const resolved = await lookup(service.host, { family: 4, all: true });
          address = resolved.find(entry => isPrivateIPv4(entry.address))?.address;
        }
        return address ? { name, address: localAddress(`https://${address}:${port}`).origin } : null;
      } catch { return null; }
    })());
  });
  await new Promise(resolve => setTimeout(resolve, 3000));
  browser.stop();
  bonjour.destroy();
  const phones = (await Promise.all(found.values())).filter(Boolean);
  if (failed && phones.length === 0) throw Error('discovery_unavailable');
  return phones;
}

function checkCall(manifest, id, args) {
  if (manifest?.version !== 1 || !Array.isArray(manifest.operations)) throw Error('unsupported_capabilities');
  if (!args || typeof args !== 'object' || Array.isArray(args) || Object.hasOwn(args, 'id')) throw Error('invalid_arguments');
  const operation = manifest.operations.find(value => value.id === id);
  if (!operation || !Array.isArray(operation.arguments) || !/^[a-z][a-z0-9_]{0,40}$/.test(id)) throw Error('unsupported_operation');
  const declared = new Map(operation.arguments.map(argument => [argument.name, argument]));
  for (const [name, value] of Object.entries(args)) {
    const argument = declared.get(name);
    if (!argument || (argument.type === 'integer' ? !Number.isSafeInteger(value) : typeof value !== argument.type) ||
        (argument.values && !argument.values.includes(value))) throw Error('invalid_arguments');
  }
  for (const argument of declared.values()) {
    if (argument.required && !Object.hasOwn(args, argument.name)) throw Error('invalid_arguments');
  }
  return { id, ...args };
}

function scanCredentials(secret) {
  const derive = label => createHmac('sha256', secret).update(label).digest('base64');
  return {
    id: createHash('sha256').update(secret).digest('base64'),
    proof: derive('lynsight-server-v1'),
    ticket: derive('lynsight-claim-v1'),
  };
}

function checkScanProof(expected, actual) {
  if (!tokenPattern.test(expected) || !tokenPattern.test(actual) ||
      !timingSafeEqual(Buffer.from(expected, 'base64'), Buffer.from(actual, 'base64'))) {
    throw Error('scan_proof_mismatch');
  }
}

function probePhone(address) {
  return new Promise((resolve, reject) => {
    // This handshake observes a candidate certificate and sends no request or credential.
    dialPhone(localAddress(address), undefined, (error, socket, fingerprint) => {
      if (error) return reject(error);
      socket.destroy();
      resolve(fingerprint);
    });
  });
}

async function startScanPairing(saved, selectedAddress) {
  const phones = selectedAddress ? [{ address: selectedAddress }] : await discover();
  if (phones.length !== 1) throw Error(phones.length ? 'choose_phone' : 'phone_unreachable');
  const address = localAddress(phones[0].address).origin;
  const pin = await probePhone(address);
  const secret = randomBytes(32);
  const { id, proof, ticket } = scanCredentials(secret);
  const expires = Math.floor(Date.now() / 1000) + 120;
  const payload = 'lynsight-scan-v1:' + JSON.stringify({
    version: 1, pin, secret: secret.toString('base64'), name: (hostname() || '电脑').slice(0, 64), expires,
  });
  const { qrcode } = require('./pairing-vendor.cjs');
  qrcode.stringToBytes = qrcode.stringToBytesFuncs['UTF-8'];
  const qr = qrcode(0, 'M');
  qr.addData(payload, 'Byte');
  qr.make();
  const directory = mkdtempSync(join(tmpdir(), 'lynsight-scan-'));
  const file = join(directory, 'pairing-qr.gif');
  const clean = () => rmSync(directory, { recursive: true, force: true });
  const terminate = signal => { clean(); process.exit(signal === 'SIGINT' ? 130 : 143); };
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, terminate);
  try {
    const image = qr.createDataURL(8, 32).split(',')[1];
    writeFileSync(file, Buffer.from(image, 'base64'), { mode: 0o600 });
    const waiting = { ...saved, pending: { address, pin, ticket, scan: { id, proof, expires } } };
    save(waiting);
    console.error('配对二维码已生成：' + file);
    while (Date.now() < expires * 1000) {
      try { return await finishPairing(waiting); }
      catch (error) { if (error.message !== 'pairing_pending') throw error; }
      await new Promise(resolve => setTimeout(resolve, 1500));
    }
    throw Error('pairing_expired');
  } finally {
    for (const signal of ['SIGINT', 'SIGTERM']) process.removeListener(signal, terminate);
    clean();
  }
}

async function finishPairing(saved) {
  const pending = saved.pending;
  if (!pending || !tokenPattern.test(pending.ticket)) throw Error('pairing_required');
  if (pending.scan) {
    if (pending.scan.expires * 1000 <= Date.now()) throw Error('pairing_expired');
    const approval = await httpsJSON(pending.address, pending.pin, '/v1/pair/proof', {
      method: 'POST', token: pending.scan.id,
    });
    checkScanProof(pending.scan.proof, approval.proof);
  }
  const result = await httpsJSON(pending.address, pending.pin, '/v1/pair/claim', { method: 'POST', token: pending.ticket });
  if (!tokenPattern.test(result.token)) throw Error('invalid_phone_response');
  save({ active: { address: pending.address, pin: pending.pin, token: result.token } });
  return { paired: true };
}

async function run([action, ...args]) {
  if (action === 'discover') return { phones: await discover() };
  const saved = state();
  if (action === 'pair-scan') return startScanPairing(saved, args[0]);
  if (action === 'pair') {
    const [address, fingerprint] = args;
    const pin = (fingerprint ?? '').toLowerCase().replace(/[\s:]/g, '');
    const name = (hostname() || '电脑').slice(0, 64);
    const result = await httpsJSON(address, pin, '/v1/pair', { method: 'POST', payload: { name } });
    if (!/^[0-9]{6}$/.test(result.code) || !tokenPattern.test(result.ticket)) throw Error('invalid_phone_response');
    save({ ...saved, pending: { address: localAddress(address).origin, pin, ticket: result.ticket } });
    return { code: result.code, next: '在 iPhone 核对配对码并允许后，执行 finish。' };
  }
  if (action === 'finish') return finishPairing(saved);
  if (action !== 'capabilities' && action !== 'call') throw Error('unknown_command');
  const phone = saved.active;
  if (!phone || !tokenPattern.test(phone.token)) throw Error('pairing_required');
  const manualAddress = action === 'capabilities' && args[0] ? localAddress(args[0]).origin : null;
  let address = manualAddress ?? phone.address;
  const fetchCapabilities = () => httpsJSON(address, phone.pin, '/v1/capabilities', { token: phone.token });
  let manifest;
  try { manifest = await fetchCapabilities(); }
  catch (error) {
    if (manualAddress || !['phone_unreachable', 'ECONNRESET', 'request_timeout'].includes(error.message)) throw error;
    const found = (await discover()).find(value => value.name === `Lynsight-${phone.pin.slice(0, 12)}`);
    if (!found || found.address === address) throw error;
    address = found.address;
    manifest = await fetchCapabilities();
  }
  if (address !== phone.address) save({ ...saved, active: { ...phone, address } });
  if (action === 'capabilities') {
    if (manifest?.version !== 1 || !Array.isArray(manifest.operations)) throw Error('unsupported_capabilities');
    return manifest;
  }
  const [id, serialized = '{}'] = args;
  const payload = checkCall(manifest, id, JSON.parse(serialized));
  return httpsJSON(address, phone.pin, '/v1/call', { method: 'POST', token: phone.token, payload });
}

if (require.main === module) {
  run(process.argv.slice(2)).then(
    result => console.log(JSON.stringify(result)),
    error => {
      const code = error?.message;
      console.log(JSON.stringify({ error: typeof code === 'string' && /^[A-Za-z_]{1,40}$/.test(code) ? code : 'client_error' }));
      process.exitCode = 1;
    },
  );
}

module.exports = { httpsJSON, checkCall, scanCredentials, checkScanProof, discoverWithBonjour };
