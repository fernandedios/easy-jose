easy-jose
=========

[![CI](https://github.com/fernandedios/easy-jose/actions/workflows/ci.yml/badge.svg)](https://github.com/fernandedios/easy-jose/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/easy-jose.svg)](https://www.npmjs.com/package/easy-jose)

> JavaScript Object Signing and Encryption, without the ceremony.

Encrypt (JWE), sign (JWS) and issue JWTs with a few function calls. `easy-jose` picks safe
algorithms, binds keys to a purpose, and accepts keys in whatever form you have them — JWK,
base64url-encoded JWK, PEM, `CryptoKey` or Node `KeyObject`.

Built on [`jose`](https://github.com/panva/jose) (Web Crypto). It uses no Node-specific APIs, so it
should also run in Deno, Bun, browsers and edge runtimes; CI currently tests Node.js 22, 24 and 26.

> **Upgrading from 1.x?** Existing code keeps working and 1.x ciphertexts still decrypt. See
> [Migrating from 1.x](#migrating-from-1x) for the few behaviour changes.

Contents
--------

- [Install](#install)
- [Quick start](#quick-start)
- [Keys](#keys) · [Encryption](#encryption-jwe) · [Signing](#signing-jws) · [JWTs](#jwts) · [Utilities](#utilities) · [Errors](#errors)
- [Defaults and security notes](#defaults-and-security-notes)
- [Migrating from 1.x](#migrating-from-1x)
- [Development](#development)

Install
-------

```bash
npm install easy-jose
```

Requires Node.js 22.12 or later. The package is an ES module with bundled TypeScript types; CommonJS
code can still `require('easy-jose')`.

Quick start
-----------

```js
import { generateKeys, encryptContent, decryptContent } from 'easy-jose';

const { public_key, private_key } = await generateKeys();

const encrypted = await encryptContent(public_key, { txt: 'hello' });
// 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoi…' (compact JWE)

const decrypted = await decryptContent(private_key, encrypted);
// { txt: 'hello' }
```

CommonJS, in the same style as 1.x:

```js
const easyJose = require('easy-jose');

const { public_key, private_key } = await easyJose.generateKeys();
const encrypted = await easyJose.encryptContent(public_key, { txt: 'hello' });
```

Keys
----

### `generateKeys(options?)`

Returns `{ public_key, private_key }` as JWK objects. Each key carries a `kid` (its RFC 7638
thumbprint), a `use` (`"enc"` or `"sig"`) and the `alg` it is bound to.

| Option    | Default                | Notes |
|-----------|------------------------|-------|
| `kty`     | `"RSA"`                | `"RSA"`, `"EC"` or `"OKP"` |
| `use`     | `"enc"`                | `"enc"` for encryption, `"sig"` for signing |
| `size`    | `2048`                 | RSA modulus bits (minimum 2048). For EC, `256` / `384` / `521` select a curve |
| `crv`     | `"P-256"` / `"X25519"` / `"Ed25519"` | EC: `P-256`, `P-384`, `P-521`. OKP: `X25519` (enc) or `Ed25519` (sig) |
| `alg`     | see [defaults](#defaults-and-security-notes) | Bind a different algorithm, e.g. `"PS256"`, `"RSA-OAEP-512"` |
| `kid`     | thumbprint             | Custom key ID |
| `encoded` | `false`                | Return `public_key` as a base64url string |
| `padded`  | `false`                | Add `=` padding to the encoded public key |

```js
await generateKeys();                                   // RSA-2048, RSA-OAEP-256
await generateKeys({ kty: 'EC', crv: 'P-384' });        // ECDH-ES+A256KW on P-384
await generateKeys({ kty: 'OKP' });                     // X25519
await generateKeys({ use: 'sig' });                     // RSA-2048, RS256
await generateKeys({ kty: 'EC', use: 'sig' });          // ES256
await generateKeys({ kty: 'OKP', use: 'sig' });         // Ed25519 (EdDSA)
await generateKeys('RSA', 4096, true, true);            // 1.x positional form still works
```

Keep `private_key` secret. `public_key` contains no private material and is safe to share.

### Accepted key formats

Every function that takes a key accepts any of:

- a **JWK object** (from `generateKeys()` or elsewhere; keys without `alg`/`use` work too)
- a **base64url-encoded JWK string**, detected automatically
- a **PEM string**: SPKI `PUBLIC KEY`, PKCS#8 `PRIVATE KEY` or an X.509 `CERTIFICATE`
- a Web Crypto **`CryptoKey`** or a Node **`KeyObject`**

Passing a private JWK where a public key is expected (to encrypt or verify) is fine; only the public
half is used.

### `toPem(key)` / `fromPem(pem, { use?, alg? })`

```js
const pem = await toPem(public_key);          // '-----BEGIN PUBLIC KEY-----…'
const privatePem = await toPem(private_key);  // '-----BEGIN PRIVATE KEY-----…' (PKCS#8)
const jwk = await fromPem(pem, { use: 'enc' });
```

PKCS#1 (`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`) PEMs must first be converted to PKCS#8:
`openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pkcs8.pem`.

### `getKeyId(key)`

Returns the RFC 7638 SHA-256 thumbprint of a JWK, which is useful for keys created elsewhere.

Encryption (JWE)
----------------

### `encryptContent(publicKey, payload, options?)`

Encrypts any JSON-serialisable value (objects, arrays, strings, numbers, `false`, `null`, …) or a raw
`Uint8Array`. Returns a **compact JWE string**.

| Option   | Default | Notes |
|----------|---------|-------|
| `alg`    | key's `alg`, else `RSA-OAEP-256` / `ECDH-ES+A256KW` | Key-management algorithm |
| `enc`    | `"A256GCM"` | Content encryption (`A128GCM`, `A256CBC-HS512`, …) |
| `format` | `"compact"` | `"json"` returns a General JSON JWE object |
| `header` | —       | Extra protected-header parameters, e.g. `{ cty: 'application/json' }` |

**Multiple recipients.** Pass an array of public keys. The result is a General JSON JWE that any of
the matching private keys can decrypt:

```js
const jwe = await encryptContent([alice.public_key, bob.public_key], { secret: 42 });
await decryptContent(bob.private_key, jwe); // { secret: 42 }
```

### `decryptContent(privateKey, payload, options?)`

Decrypts compact JWE strings and Flattened or General JSON JWE objects, including everything
produced by easy-jose 1.x / node-jose.

| Option              | Notes |
|---------------------|-------|
| `encoded`           | The payload is base64url-encoded JSON (the 1.x `isPayloadEncoded` flag) |
| `raw`               | Return the plaintext as a `Uint8Array` instead of parsing JSON |
| `complete`          | Return `{ payload, protectedHeader }` |
| `algorithms`        | Allow-list of key-management algorithms |
| `contentAlgorithms` | Allow-list of content-encryption algorithms |

```js
const { payload, protectedHeader } = await decryptContent(private_key, jwe, { complete: true });
console.log(protectedHeader.kid); // which key was used
```

Signing (JWS)
-------------

Create keys with `use: 'sig'`.

```js
import { generateKeys, signContent, verifyContent } from 'easy-jose';

const { public_key, private_key } = await generateKeys({ kty: 'OKP', use: 'sig' });

const jws = await signContent(private_key, { order: 1234, total: 99.5 });
const data = await verifyContent(public_key, jws); // { order: 1234, total: 99.5 }
```

- `signContent(privateKey, payload, { alg?, header? })` returns a compact JWS string.
- `verifyContent(publicKey, jws, { algorithms?, raw?, complete? })` returns the payload. It throws if
  the signature is invalid or the algorithm doesn't fit the key.

JWTs
----

```js
import { generateKeys, signJwt, verifyJwt } from 'easy-jose';

const { public_key, private_key } = await generateKeys({ kty: 'EC', use: 'sig' });

const token = await signJwt(private_key, { role: 'admin' }, {
  subject: 'user-123',
  issuer: 'https://auth.example.com',
  audience: 'api',
  expiresIn: '2h',
});

const claims = await verifyJwt(public_key, token, {
  issuer: 'https://auth.example.com',
  audience: 'api',
});
// { role: 'admin', sub: 'user-123', iss: '…', aud: 'api', iat: …, exp: … }
```

**`signJwt(privateKey, claims, options?)`**: `iat` is always set. Tokens **expire after 1 hour** unless
you pass `expiresIn` or include an `exp` claim. Use `expiresIn: null` for a token with no expiry.

| Option      | Notes |
|-------------|-------|
| `expiresIn` | Seconds from now (`900`), a duration string (`"15m"`, `"2h"`, `"7 days"`), a `Date`, or `null` |
| `notBefore` | Same formats as `expiresIn` |
| `issuer`, `subject`, `audience`, `jwtId` | Set `iss`, `sub`, `aud`, `jti` |
| `alg`, `header` | As for `signContent` |

**`verifyJwt(publicKey, token, options?)`** checks the signature, `exp` and `nbf`, and returns the claims.

| Option           | Notes |
|------------------|-------|
| `issuer`, `audience`, `subject` | Required values (`issuer` and `audience` may be arrays) |
| `maxTokenAge`    | Reject tokens issued longer ago than this, e.g. `"10m"` |
| `clockTolerance` | Allowed clock skew, e.g. `"30s"` or `30` |
| `requiredClaims` | Claim names that must be present |
| `algorithms`     | Allow-list; defaults to the algorithms valid for the key |
| `complete`       | Return `{ payload, protectedHeader }` |

To keep claims private, encrypt the token: `encryptContent(recipientKey, token)`.

Utilities
---------

The 1.x helpers are unchanged (and their output is byte-identical):

```js
import { encode, decode, convertToU8A, convertU8A } from 'easy-jose';

const encoded = encode({ a: 1 });        // base64url of the JSON: 'eyJhIjoxfQ'
const padded = encode({ a: 1 }, true);   // 'eyJhIjoxfQ=='
decode(encoded);                         // { a: 1 } (padded or standard base64 also accepted)

const bytes = convertToU8A({ a: 1 });    // UTF-8 JSON as a Uint8Array
convertU8A(bytes);                       // { a: 1 }
```

Errors
------

Failures throw:

- **`TypeError`** for bad input: a missing key or payload, an unsupported key format, a signing key
  used for encryption, and so on.
- **`jose` errors** for cryptographic failures. These are re-exported as `errors` and carry a `.code`.

```js
import { verifyJwt, errors } from 'easy-jose';

try {
  await verifyJwt(public_key, token);
} catch (err) {
  if (err instanceof errors.JWTExpired) { /* refresh */ }
  else if (err.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') { /* forged or wrong key */ }
  else throw err;
}
```

Common codes: `ERR_JWE_DECRYPTION_FAILED`, `ERR_JWS_SIGNATURE_VERIFICATION_FAILED`, `ERR_JWT_EXPIRED`,
`ERR_JWT_CLAIM_VALIDATION_FAILED`, `ERR_JOSE_ALG_NOT_ALLOWED`, `ERR_JOSE_NOT_SUPPORTED`.

Defaults and security notes
---------------------------

| Key | Encryption (`use: 'enc'`) | Signing (`use: 'sig'`) |
|-----|---------------------------|------------------------|
| RSA (2048+ bits) | `RSA-OAEP-256` + `A256GCM` | `RS256` (`PS256`/`384`/`512`, `RS384`/`512` via `alg`) |
| EC P-256 / P-384 / P-521 | `ECDH-ES+A256KW` + `A256GCM` | `ES256` / `ES384` / `ES512` |
| OKP | `X25519`, `ECDH-ES+A256KW` + `A256GCM` | `Ed25519` (`EdDSA`) |

- **Keys are bound to a purpose.** A key marked `use: "sig"` cannot encrypt, and a key with an `alg`
  rejects every other algorithm, both when creating tokens and when reading them.
- **The token header can't pick an unsafe algorithm.** Verification only accepts algorithms that are
  valid for the key you pass. This blocks `alg: "none"` and the RSA-public-key-as-HMAC-secret confusion
  attack (both are covered by tests).
- **No shared state.** Each call uses only the key you pass, with no global keystore.
- **No symmetric secrets.** `easy-jose` only works with asymmetric key pairs. For HMAC (`HS256`) or
  direct (`dir`) encryption, use `jose` directly.
- **Legacy algorithms.** For compatibility, `RSA-OAEP` (SHA-1) and `A128CBC-HS256` are accepted when
  *decrypting*, because 1.x produced them. They are never used for new ciphertexts unless you ask. To
  refuse them, pass `algorithms` / `contentAlgorithms` to `decryptContent()`.

Migrating from 1.x
------------------

Most 1.x code runs unchanged: `init()`, `generateKeys(kty, size, isEncoded, isPadded)`,
`encryptContent(key, payload, isKeyEncoded)`, `decryptContent(key, payload, isPayloadEncoded)` and the
utilities all keep their signatures. The differences:

| 1.x | 2.x |
|-----|-----|
| `encryptContent()` returned a General JSON object | Returns a compact JWE **string**. Pass `{ format: 'json' }` for an object. `decryptContent()` accepts both, so stored 1.x ciphertexts keep working |
| `RSA-OAEP` + `A128CBC-HS256` | `RSA-OAEP-256` + `A256GCM` for new ciphertexts. Any JOSE library decrypting your output must support these. All mainstream ones do, and easy-jose 1.x itself decrypts 2.x output (compact and JSON), so services can upgrade one at a time |
| Keys had only `kid` | Keys also carry `use` and `alg` and are rejected for other purposes. 1.x keys (no `use`/`alg`) are accepted |
| `init()` created a global keystore | `init()` does nothing; you can delete the call |
| `getKeystore()` | Removed: there is no keystore |
| `generateKeys('EC', 4096)` (threw) | `generateKeys({ kty: 'EC', crv: 'P-384' })` or `generateKeys('EC', 'P-384')` |
| RSA keys under 2048 bits | Rejected |
| Payloads `0`, `false`, `''`, `null` rejected | Accepted |
| Errors were `new Error(originalError)` | The original `jose` error (with `.code`), or a `TypeError` |
| Node.js ≥ 8, CommonJS | Node.js ≥ 22.12, ESM (CommonJS `require` still works) |

Development
-----------

```bash
npm install
npm test            # node:test suite, including 1.x compatibility fixtures
npm run typecheck   # validates the TypeScript declarations
```

There is no build step: `src/index.js` is the published code and `src/index.d.ts` the types.
`test/fixtures/legacy-v1.json` holds ciphertexts made with easy-jose 1.0.5 so compatibility stays tested.
Those keys exist for testing only.

Thanks
------

easy-jose © 2018–2026, Fernan de Dios. Released under the [MIT License](LICENSE.MD).

> [fernandedios.com](https://fernandedios.com) &nbsp;&middot;&nbsp;
> GitHub [@fernandedios](https://github.com/fernandedios) &nbsp;&middot;&nbsp;
> Twitter [@fernan_de_dios](https://twitter.com/fernan_de_dios)
