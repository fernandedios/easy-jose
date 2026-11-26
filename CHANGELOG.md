# Changelog

## 2.0.0 — 2026-11-26

A ground-up modernization. The 1.x function names and calling style still work, and ciphertexts
produced by 1.x can still be decrypted, but the output format and a few edge behaviours changed —
see **Migrating from 1.x** in the README.

### Changed
- Rebuilt on [`jose`](https://github.com/panva/jose) v6 (Web Crypto) instead of `node-jose` 0.11.
  One runtime dependency (zero transitive) instead of four (18 installed packages, 7 flagged by `npm audit`, 4 of them high severity),
  and RSA-2048 key generation went from a ~1.75 s median to ~37 ms on Node 22.
- Native ES module with TypeScript declarations; `require('easy-jose')` works on Node.js ≥ 22.12.
- No global keystore. `init()` is now a no-op kept for compatibility.
- `encryptContent()` returns a **compact JWE string** by default (`format: 'json'` returns a General JSON object).
- Safer defaults: `RSA-OAEP-256` / `ECDH-ES+A256KW` key management with `A256GCM` content encryption.
- Generated JWKs now include `kid` (RFC 7638 thumbprint), `use` and `alg`; keys are refused for the
  wrong purpose or algorithm.
- Options are passed as an object; the 1.x boolean flags (`isEncoded`, `isPadded`, `isKeyEncoded`,
  `isPayloadEncoded`) are still accepted.
- Errors are the original `jose` errors (with `.code`) or `TypeError`s for bad input, instead of
  re-wrapped `Error("Error: …")` strings.

### Added
- EC (`P-256`, `P-384`, `P-521`) and OKP (`X25519`, `Ed25519`) keys.
- Signing: `signContent()` / `verifyContent()` (compact JWS).
- JWTs: `signJwt()` / `verifyJwt()` with expiry (1 hour by default), `iss` / `aud` / `sub` / `jti` / `nbf`
  and verification options.
- Multi-recipient encryption: pass an array of public keys.
- Keys can be JWK objects, base64url-encoded JWKs (auto-detected), PEM strings, `CryptoKey`s or Node `KeyObject`s.
- `toPem()`, `fromPem()` and `getKeyId()`.
- `raw` (bytes in/out) and `complete` (return the protected header) options.
- `errors` re-exported from `jose` for `instanceof` checks.

### Fixed
- Keys no longer accumulate in a shared keystore across calls, and decryption only tries the key you pass.
- Falsy payloads (`0`, `false`, `''`, `null`) can be encrypted.
- The README example `generateKeys('EC', 4096)` (which threw) is replaced with working curve options.
- `npm test` works on every platform (1.x used a POSIX/Windows `export || SET` hack).

### Removed
- `getKeystore()` — there is no keystore to return.
- Babel build output (`lib/`), Travis CI config, and the `es6-promise`, `fast-text-encoding` and
  `urlsafe-base64` dependencies.
- RSA keys smaller than 2048 bits.

## 1.0.5 — 2018-03-28
- Last release on `node-jose`.
