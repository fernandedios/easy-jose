import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, CompactSign } from 'jose';
import { generateKeys, signContent, verifyContent, signJwt, verifyJwt, toPem, errors } from '../src/index.js';

const rsa = await generateKeys({ use: 'sig' });
const ec = await generateKeys({ kty: 'EC', use: 'sig' });
const ed = await generateKeys({ kty: 'OKP', use: 'sig' });
const sample = { hello: 'world', n: 1 };

test('signContent / verifyContent round-trip for RSA, EC and Ed25519', async () => {
  for (const { public_key, private_key } of [rsa, ec, ed]) {
    const jws = await signContent(private_key, sample);
    assert.equal(jws.split('.').length, 3);
    assert.deepEqual(await verifyContent(public_key, jws), sample);
    const { protectedHeader } = await verifyContent(public_key, jws, { complete: true });
    assert.deepEqual(protectedHeader, { alg: public_key.alg, kid: public_key.kid });
  }
  assert.equal(await verifyContent(rsa.public_key, await signContent(rsa.private_key, 0)), 0);
});

test('verification rejects tampering, wrong keys and misuse', async () => {
  const jws = await signContent(ec.private_key, sample);
  const [h, , s] = jws.split('.');
  const forged = [h, Buffer.from(JSON.stringify({ hello: 'mallory' })).toString('base64url'), s].join('.');
  await assert.rejects(verifyContent(ec.public_key, forged), { code: 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' });
  const other = await generateKeys({ kty: 'EC', use: 'sig' });
  await assert.rejects(verifyContent(other.public_key, jws), { code: 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' });
  await assert.rejects(verifyContent(rsa.public_key, jws), errors.JOSEError);
  await assert.rejects(signContent(rsa.public_key, sample), /requires a private key/);
  const encKeys = await generateKeys();
  await assert.rejects(signContent(encKeys.private_key, sample), /"use": "enc"/);
});

test('blocks algorithm-confusion and alg:none attacks', async () => {
  // HS256 token whose HMAC secret is the RSA public key's JSON — the classic confusion attack.
  const secret = new TextEncoder().encode(JSON.stringify(rsa.public_key));
  const hs = await new CompactSign(new TextEncoder().encode('{"admin":true}')).setProtectedHeader({ alg: 'HS256' }).sign(secret);
  await assert.rejects(verifyContent(rsa.public_key, hs), { code: 'ERR_JOSE_ALG_NOT_ALLOWED' });
  const hsJwt = await new SignJWT({ admin: true }).setProtectedHeader({ alg: 'HS256' }).sign(secret);
  await assert.rejects(verifyJwt(rsa.public_key, hsJwt), { code: 'ERR_JOSE_ALG_NOT_ALLOWED' });

  const none = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from('{"admin":true}').toString('base64url')}.`;
  await assert.rejects(verifyContent(rsa.public_key, none), errors.JOSEError);
  await assert.rejects(verifyJwt(rsa.public_key, none), errors.JOSEError);

  // A key bound to RS256 does not accept PS256 even though both are RSA.
  const ps = await signContent({ ...rsa.private_key, alg: undefined }, sample, { alg: 'PS256' });
  await assert.rejects(verifyContent(rsa.public_key, ps), { code: 'ERR_JOSE_ALG_NOT_ALLOWED' });
});

test('signJwt / verifyJwt with registered claims', async () => {
  for (const { public_key, private_key } of [rsa, ec, ed]) {
    const token = await signJwt(private_key, { role: 'admin' }, { issuer: 'easy-jose', audience: 'api', subject: 'user-1', jwtId: 'abc' });
    const claims = await verifyJwt(public_key, token, { issuer: 'easy-jose', audience: 'api' });
    assert.equal(claims.role, 'admin');
    assert.equal(claims.sub, 'user-1');
    assert.equal(claims.jti, 'abc');
    assert.equal(claims.exp - claims.iat, 3600, 'default lifetime is one hour');
    const { protectedHeader } = await verifyJwt(public_key, token, { complete: true });
    assert.equal(protectedHeader.typ, 'JWT');
    assert.equal(protectedHeader.kid, public_key.kid);
    await assert.rejects(verifyJwt(public_key, token, { audience: 'other' }), { code: 'ERR_JWT_CLAIM_VALIDATION_FAILED' });
    await assert.rejects(verifyJwt(public_key, token, { issuer: 'someone-else' }), { code: 'ERR_JWT_CLAIM_VALIDATION_FAILED' });
  }
});

test('JWT lifetimes: expiresIn, exp claim, no expiry, notBefore', async () => {
  const now = Math.floor(Date.now() / 1000);
  const t1 = await verifyJwt(ed.public_key, await signJwt(ed.private_key, {}, { expiresIn: 90 }));
  assert.equal(t1.exp - t1.iat, 90, 'numbers are seconds from now');
  const t2 = await verifyJwt(ed.public_key, await signJwt(ed.private_key, {}, { expiresIn: '2h' }));
  assert.equal(t2.exp - t2.iat, 7200);
  const t3 = await verifyJwt(ed.public_key, await signJwt(ed.private_key, {}, { expiresIn: null }));
  assert.equal(t3.exp, undefined);
  const t4 = await verifyJwt(ed.public_key, await signJwt(ed.private_key, { exp: now + 30 }));
  assert.equal(t4.exp, now + 30, 'explicit exp claim is kept');

  const expired = await signJwt(ed.private_key, { exp: now - 60 });
  await assert.rejects(verifyJwt(ed.public_key, expired), errors.JWTExpired);
  assert.ok(await verifyJwt(ed.public_key, expired, { clockTolerance: 120 }));

  const future = await signJwt(ed.private_key, {}, { notBefore: '10m' });
  await assert.rejects(verifyJwt(ed.public_key, future), { code: 'ERR_JWT_CLAIM_VALIDATION_FAILED' });
  await assert.rejects(signJwt(ed.private_key, 'not-an-object'), /claims must be an object/);
});

test('PEM and KeyObject keys work for signing', async () => {
  const token = await signJwt(await toPem(ec.private_key), { a: 1 });
  assert.equal((await verifyJwt(await toPem(ec.public_key), token)).a, 1);
  const crypto = await import('node:crypto');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jws = await signContent(privateKey, sample);
  assert.deepEqual(await verifyContent(publicKey, jws), sample);
});
