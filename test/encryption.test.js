import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeys, encryptContent, decryptContent, encode, init, errors } from '../src/index.js';

const legacy = JSON.parse(readFileSync(new URL('./fixtures/legacy-v1.json', import.meta.url), 'utf8'));
const sample = { text: 'hello', n: 42, nested: { ok: true } };

const rsa = await generateKeys();
const ec = await generateKeys({ kty: 'EC', crv: 'P-384' });
const x25519 = await generateKeys({ kty: 'OKP' });

test('round-trips every key type and returns a compact JWE by default', async () => {
  for (const { public_key, private_key } of [rsa, ec, x25519]) {
    const jwe = await encryptContent(public_key, sample);
    assert.equal(typeof jwe, 'string');
    assert.equal(jwe.split('.').length, 5);
    const header = JSON.parse(Buffer.from(jwe.split('.')[0], 'base64url'));
    const { epk, ...rest } = header;
    assert.deepEqual(rest, { alg: public_key.alg, enc: 'A256GCM', kid: public_key.kid });
    assert.equal(epk !== undefined, public_key.alg.startsWith('ECDH'), 'ECDH adds an ephemeral public key');
    assert.deepEqual(await decryptContent(private_key, jwe), sample);
  }
});

test('handles every JSON value, including falsy ones 1.x rejected', async () => {
  for (const value of [0, false, '', null, [], 'plain string', [1, { a: 'b' }], 'üñí©ødé ✓']) {
    const jwe = await encryptContent(rsa.public_key, value);
    assert.deepEqual(await decryptContent(rsa.private_key, jwe), value);
  }
  await assert.rejects(encryptContent(rsa.public_key, undefined), /Missing payload/);
  await assert.rejects(encryptContent(rsa.public_key, () => {}), /not JSON-serializable/);
});

test('raw bytes round-trip with { raw: true }', async () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 255]);
  const jwe = await encryptContent(rsa.public_key, bytes);
  assert.deepEqual(await decryptContent(rsa.private_key, jwe, { raw: true }), bytes);
});

test('complete: true exposes the protected header', async () => {
  const jwe = await encryptContent(ec.public_key, sample, { header: { cty: 'application/json' } });
  const { payload, protectedHeader } = await decryptContent(ec.private_key, jwe, { complete: true });
  assert.deepEqual(payload, sample);
  assert.equal(protectedHeader.cty, 'application/json');
  assert.equal(protectedHeader.kid, ec.public_key.kid);
});

test('JSON format and multi-recipient encryption', async () => {
  const single = await encryptContent(rsa.public_key, sample, { format: 'json' });
  assert.equal(single.recipients.length, 1);
  assert.deepEqual(await decryptContent(rsa.private_key, single), sample);

  const multi = await encryptContent([rsa.public_key, ec.public_key, x25519.public_key], sample);
  assert.equal(multi.recipients.length, 3);
  for (const { private_key } of [rsa, ec, x25519]) assert.deepEqual(await decryptContent(private_key, multi), sample);
  await assert.rejects(encryptContent([rsa.public_key, ec.public_key], sample, { format: 'compact' }), /single recipient/);
});

test('custom algorithms', async () => {
  const jwe = await encryptContent(ec.public_key, sample, { alg: 'ECDH-ES+A256KW', enc: 'A128CBC-HS256' });
  assert.deepEqual(await decryptContent(ec.private_key, jwe), sample);
  const legacyRsa = { ...rsa.public_key };
  delete legacyRsa.alg;
  const oaep512 = await encryptContent(legacyRsa, sample, { alg: 'RSA-OAEP-512' });
  const priv = { ...rsa.private_key };
  delete priv.alg;
  assert.deepEqual(await decryptContent(priv, oaep512), sample);
  // decryptor can narrow the accepted algorithms
  await assert.rejects(decryptContent(priv, oaep512, { algorithms: ['RSA-OAEP-256'] }), { code: 'ERR_JOSE_ALG_NOT_ALLOWED' });
});

test('base64url-encoded keys and payloads (1.x flags and auto-detection)', async () => {
  const encodedKeys = await generateKeys({ encoded: true, padded: true });
  const a = await encryptContent(encodedKeys.public_key, sample, true);
  const b = await encryptContent(encodedKeys.public_key, sample);
  assert.deepEqual(await decryptContent(encodedKeys.private_key, a), sample);
  assert.deepEqual(await decryptContent(encode(encodedKeys.private_key), b), sample);
  assert.deepEqual(await decryptContent(encodedKeys.private_key, encode(b), true), sample);
  assert.deepEqual(await decryptContent(encodedKeys.private_key, encode(b), { encoded: true }), sample);
});

test('decrypts ciphertexts produced by easy-jose 1.x (node-jose)', async () => {
  init(); // 1.x code calls init(); it is now a no-op
  assert.deepEqual(await decryptContent(legacy.rsa.private_key, legacy.rsa.jwe), sample);
  assert.deepEqual(await decryptContent(legacy.rsa.private_key, legacy.rsa.jweB64, true), sample);
  assert.equal(await decryptContent(legacy.encodedKey.private_key, legacy.encodedKey.jwe), 'plain string');
  // 1.x public keys (no alg/use) still encrypt — now with RSA-OAEP-256 / A256GCM
  const jwe = await encryptContent(legacy.rsa.public_key, sample);
  assert.deepEqual(await decryptContent(legacy.rsa.private_key, jwe), sample);
  // 1.x base64url+padded public key string
  const jwe2 = await encryptContent(legacy.encodedKey.public_key, sample, true);
  assert.deepEqual(await decryptContent(legacy.encodedKey.private_key, jwe2), sample);
});

test('wrong key, tampering and key misuse are rejected', async () => {
  const jwe = await encryptContent(rsa.public_key, sample);
  const other = await generateKeys();
  await assert.rejects(decryptContent(other.private_key, jwe), errors.JOSEError);
  await assert.rejects(decryptContent(ec.private_key, jwe), errors.JOSEError);

  const parts = jwe.split('.');
  const ct = Buffer.from(parts[3], 'base64url');
  ct[0] ^= 1;
  parts[3] = ct.toString('base64url');
  await assert.rejects(decryptContent(rsa.private_key, parts.join('.')), { code: 'ERR_JWE_DECRYPTION_FAILED' });

  await assert.rejects(decryptContent(rsa.public_key, jwe), /requires a private key/);
  const signing = await generateKeys({ use: 'sig' });
  await assert.rejects(encryptContent(signing.public_key, sample), /"use": "sig"/);
  await assert.rejects(encryptContent(rsa.public_key, sample, { alg: 'RSA-OAEP-512' }), { code: 'ERR_JOSE_ALG_NOT_ALLOWED' });
  const ed = await generateKeys({ kty: 'OKP', use: 'sig' });
  const edNoUse = { ...ed.public_key };
  delete edNoUse.use;
  delete edNoUse.alg;
  await assert.rejects(encryptContent(edNoUse, sample), { code: 'ERR_JOSE_NOT_SUPPORTED' });
});

test('input validation', async () => {
  await assert.rejects(encryptContent(undefined, sample), /Missing key/);
  await assert.rejects(encryptContent('garbage', sample), /neither PEM nor/);
  await assert.rejects(encryptContent(new Uint8Array(32), sample), /Symmetric secrets/);
  await assert.rejects(decryptContent(rsa.private_key, undefined), /Missing encrypted payload/);
  await assert.rejects(decryptContent(rsa.private_key, 42), /compact JWE string or a JWE JSON object/);
  await assert.rejects(encryptContent(rsa.public_key, sample, { format: 'xml' }), /format must be/);
});

test('accepts CryptoKey and Node KeyObject inputs', async () => {
  const crypto = await import('node:crypto');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwe = await encryptContent(publicKey, sample);
  assert.equal(JSON.parse(Buffer.from(jwe.split('.')[0], 'base64url')).alg, 'RSA-OAEP-256');
  assert.deepEqual(await decryptContent(privateKey, jwe), sample);

  const pair = await crypto.webcrypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384' },
    false,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  );
  const jwe2 = await encryptContent(pair.publicKey, sample);
  assert.equal(JSON.parse(Buffer.from(jwe2.split('.')[0], 'base64url')).alg, 'RSA-OAEP-384');
  assert.deepEqual(await decryptContent(pair.privateKey, jwe2), sample);
});
