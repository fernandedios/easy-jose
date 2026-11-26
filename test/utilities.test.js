import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { encode, decode, convertToU8A, convertU8A } from '../src/index.js';
import easyJose from '../src/index.js';

const legacy = JSON.parse(readFileSync(new URL('./fixtures/legacy-v1.json', import.meta.url), 'utf8'));

test('encode() output is byte-identical to 1.x', () => {
  assert.equal(encode(legacy.encode.sample), legacy.encode.encoded);
  assert.deepEqual(decode(legacy.encode.encoded), legacy.encode.sample);
});

test('decode() accepts padding and standard base64 characters', () => {
  assert.equal(encode('??>'), 'Ij8_PiI');
  assert.equal(encode('??>', true), 'Ij8_PiI=');
  assert.equal(decode('Ij8_PiI='), '??>');
  assert.equal(decode('Ij8/PiI='), '??>');
  assert.deepEqual(decode(legacy.encode.standardBase64), legacy.encode.sample);
  assert.throws(() => decode(42), /expects a string/);
});

test('convertToU8A / convertU8A round-trip', () => {
  const data = { text: 'hello ✓' };
  const u8a = convertToU8A(data);
  assert.ok(u8a instanceof Uint8Array);
  assert.deepEqual(convertU8A(u8a), data);
});

test('default export exposes the full API (1.x style usage)', () => {
  for (const name of ['init', 'generateKeys', 'encryptContent', 'decryptContent', 'signContent', 'verifyContent', 'signJwt', 'verifyJwt', 'toPem', 'fromPem', 'getKeyId', 'encode', 'decode', 'convertToU8A', 'convertU8A']) {
    assert.equal(typeof easyJose[name], 'function', name);
  }
  assert.equal(typeof easyJose.errors.JOSEError, 'function');
});
