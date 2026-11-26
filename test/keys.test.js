import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeys, getKeyId, toPem, fromPem, decode, encryptContent, decryptContent } from '../src/index.js';

test('generateKeys() defaults to RSA-2048 encryption keys with kid/use/alg', async () => {
  const { public_key, private_key } = await generateKeys();
  assert.equal(public_key.kty, 'RSA');
  assert.equal(public_key.alg, 'RSA-OAEP-256');
  assert.equal(public_key.use, 'enc');
  assert.equal(typeof public_key.kid, 'string');
  assert.equal(public_key.kid, private_key.kid);
  assert.equal(public_key.d, undefined, 'public key must not contain private material');
  assert.equal(typeof private_key.d, 'string');
  assert.equal(Buffer.from(public_key.n, 'base64url').length, 256);
  assert.equal(await getKeyId(public_key), public_key.kid, 'kid is the RFC 7638 thumbprint');
  assert.equal(await getKeyId(private_key), public_key.kid);
});

test('generateKeys() supports EC curves, OKP and signing keys', async () => {
  const cases = [
    [{ kty: 'EC' }, { crv: 'P-256', alg: 'ECDH-ES+A256KW' }],
    [{ kty: 'EC', crv: 'P-521' }, { crv: 'P-521', alg: 'ECDH-ES+A256KW' }],
    [{ kty: 'EC', size: 384 }, { crv: 'P-384', alg: 'ECDH-ES+A256KW' }],
    [{ kty: 'OKP' }, { crv: 'X25519', alg: 'ECDH-ES+A256KW' }],
    [{ use: 'sig' }, { kty: 'RSA', alg: 'RS256' }],
    [{ use: 'sig', alg: 'PS384' }, { kty: 'RSA', alg: 'PS384' }],
    [{ kty: 'EC', use: 'sig', crv: 'P-384' }, { crv: 'P-384', alg: 'ES384' }],
    [{ kty: 'OKP', use: 'sig' }, { crv: 'Ed25519', alg: 'EdDSA' }],
  ];
  for (const [options, expected] of cases) {
    const { public_key } = await generateKeys(options);
    for (const [k, v] of Object.entries(expected)) assert.equal(public_key[k], v, `${JSON.stringify(options)} → ${k}`);
  }
});

test('generateKeys() keeps the 1.x positional signature', async () => {
  const { public_key, private_key } = await generateKeys('RSA', 2048, true, true);
  assert.equal(typeof public_key, 'string');
  assert.equal(public_key.length % 4, 0, 'padded');
  assert.equal(decode(public_key).kid, private_key.kid);
  const ec = await generateKeys('EC', 'P-384');
  assert.equal(ec.public_key.crv, 'P-384');
});

test('generateKeys() rejects invalid parameters with clear errors', async () => {
  await assert.rejects(generateKeys('EC', 4096), /EC keys take a curve/);
  await assert.rejects(generateKeys({ size: 1024 }), /at least 2048/);
  await assert.rejects(generateKeys({ kty: 'oct' }), /Unsupported key type/);
  await assert.rejects(generateKeys({ kty: 'OKP', crv: 'Ed25519' }), /X25519/);
  await assert.rejects(generateKeys({ kty: 'OKP', use: 'sig', crv: 'X25519' }), /Ed25519/);
  await assert.rejects(generateKeys({ use: 'both' }), /use must be/);
  await assert.rejects(generateKeys({ alg: 'RS256' }), { code: 'ERR_JOSE_ALG_NOT_ALLOWED' });
});

test('toPem() / fromPem() round-trip and interoperate with node:crypto PEMs', async () => {
  const { public_key, private_key } = await generateKeys();
  const pubPem = await toPem(public_key);
  const privPem = await toPem(private_key);
  assert.match(pubPem, /^-----BEGIN PUBLIC KEY-----/);
  assert.match(privPem, /^-----BEGIN PRIVATE KEY-----/);
  const back = await fromPem(pubPem, { use: 'enc' });
  assert.equal(back.n, public_key.n);
  assert.equal(back.kid, public_key.kid);
  assert.equal(back.use, 'enc');

  const crypto = await import('node:crypto');
  const pair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-384',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const ecJwk = await fromPem(pair.publicKey);
  assert.equal(ecJwk.crv, 'P-384');
  const jwe = await encryptContent(pair.publicKey, { pem: true });
  assert.deepEqual(await decryptContent(pair.privateKey, jwe), { pem: true });
});

test('fromPem() explains unsupported PKCS#1 keys', async () => {
  const crypto = await import('node:crypto');
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  await assert.rejects(fromPem(privateKey), /RSA PRIVATE KEY.*openssl pkcs8/s);
  await assert.rejects(fromPem('not a pem'), /Not a valid PEM/);
});
