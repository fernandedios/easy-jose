/**
 * easy-jose — straightforward JOSE (JWE / JWS / JWT) helpers built on `jose`.
 *
 * Everything here uses the Web Crypto API through `jose`, so the module runs
 * in Node.js, Deno, Bun, browsers and edge runtimes without polyfills.
 */
import {
  CompactEncrypt,
  CompactSign,
  GeneralEncrypt,
  SignJWT,
  base64url,
  calculateJwkThumbprint,
  compactDecrypt,
  compactVerify,
  errors,
  exportJWK,
  exportPKCS8,
  exportSPKI,
  flattenedDecrypt,
  generalDecrypt,
  generateKeyPair,
  importJWK,
  importPKCS8,
  importSPKI,
  importX509,
  jwtVerify,
} from 'jose';

export { errors };

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---------------------------------------------------------------------------
// Algorithm tables
// ---------------------------------------------------------------------------

const RSA_ENC_ALGS = ['RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512', 'RSA-OAEP'];
const ECDH_ALGS = ['ECDH-ES+A256KW', 'ECDH-ES+A192KW', 'ECDH-ES+A128KW', 'ECDH-ES'];
const RSA_SIG_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
const EC_SIG_ALG = { 'P-256': 'ES256', 'P-384': 'ES384', 'P-521': 'ES512' };
const EC_CURVE_FOR_BITS = { 256: 'P-256', 384: 'P-384', 521: 'P-521' };
const ECDH_CURVES = ['X25519', 'X448'];
const EDDSA_CURVES = ['Ed25519'];
const EDDSA_ALGS = ['EdDSA', 'Ed25519'];

const DEFAULT_CONTENT_ENC = 'A256GCM';
const DEFAULT_RSA_SIZE = 2048;
const DEFAULT_JWT_LIFETIME = '1h';

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const isPlainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Uint8Array);

const isCryptoKey = (value) => typeof CryptoKey !== 'undefined' && value instanceof CryptoKey;

// Node.js KeyObject (duck-typed so this file never imports node:crypto).
const isKeyObject = (value) =>
  value !== null &&
  typeof value === 'object' &&
  typeof value.type === 'string' &&
  typeof value.export === 'function' &&
  'asymmetricKeyType' in value;

const usageLabel = (usage) => (usage === 'enc' ? 'encryption' : 'signing');

// Options may be passed as a boolean for 1.x compatibility (isKeyEncoded / isPayloadEncoded).
const normalizeOptions = (options) => {
  if (typeof options === 'boolean') return { encoded: options };
  if (options === undefined || options === null) return {};
  if (!isPlainObject(options)) throw new TypeError('options must be an object');
  return { ...options };
};

const assertPayload = (payload) => {
  if (payload === undefined) throw new TypeError('Missing payload');
};

const toBytes = (payload) => {
  if (payload instanceof Uint8Array) return payload;
  const json = JSON.stringify(payload);
  if (json === undefined) throw new TypeError('Payload is not JSON-serializable');
  return encoder.encode(json);
};

const fromBytes = (bytes, raw) => (raw ? bytes : JSON.parse(decoder.decode(bytes)));

const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
const toPublicJwk = (jwk) => {
  const pub = { ...jwk };
  for (const member of PRIVATE_MEMBERS) delete pub[member];
  return pub;
};

const isPrivateJwk = (jwk) => typeof jwk.d === 'string';

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

/** Algorithms a JWK may legitimately be used with, for one usage. */
const allowedAlgorithms = (jwk, usage) => {
  if (usage === 'enc') {
    if (jwk.kty === 'RSA') return RSA_ENC_ALGS;
    if (jwk.kty === 'EC') return ECDH_ALGS;
    if (jwk.kty === 'OKP' && ECDH_CURVES.includes(jwk.crv)) return ECDH_ALGS;
    return [];
  }
  if (jwk.kty === 'RSA') return RSA_SIG_ALGS;
  if (jwk.kty === 'EC' && EC_SIG_ALG[jwk.crv]) return [EC_SIG_ALG[jwk.crv]];
  if (jwk.kty === 'OKP' && EDDSA_CURVES.includes(jwk.crv)) return EDDSA_ALGS;
  return [];
};

const algorithmsForJwk = (jwk, usage) => (jwk.alg ? [jwk.alg] : allowedAlgorithms(jwk, usage));

/** Throw unless `alg` is acceptable for this JWK and usage. */
const assertCompatible = (jwk, alg, usage) => {
  if (jwk.use && jwk.use !== usage) {
    throw new TypeError(`This key is marked "use": "${jwk.use}" and cannot be used for ${usageLabel(usage)}`);
  }
  if (jwk.alg && jwk.alg !== alg) {
    throw new errors.JOSEAlgNotAllowed(`Key is bound to "${jwk.alg}" but "${alg}" was requested`);
  }
  const allowed = allowedAlgorithms(jwk, usage);
  if (allowed.length === 0) {
    throw new errors.JOSENotSupported(`A ${jwk.kty}${jwk.crv ? ` ${jwk.crv}` : ''} key cannot be used for ${usageLabel(usage)}`);
  }
  if (!allowed.includes(alg)) {
    throw new errors.JOSEAlgNotAllowed(`"${alg}" is not a valid ${usageLabel(usage)} algorithm for a ${jwk.kty} key`);
  }
};

/** Pick a sensible algorithm for a key object (CryptoKey or Node KeyObject). */
const deduceAlgorithm = (key, usage) => {
  if (isCryptoKey(key)) {
    const { name, namedCurve, hash } = key.algorithm;
    const bits = hash?.name?.replace('SHA-', '');
    switch (name) {
      case 'RSA-OAEP':
        return bits === '1' ? 'RSA-OAEP' : `RSA-OAEP-${bits}`;
      case 'RSASSA-PKCS1-v1_5':
        return `RS${bits}`;
      case 'RSA-PSS':
        return `PS${bits}`;
      case 'ECDSA':
        return EC_SIG_ALG[namedCurve];
      case 'ECDH':
      case 'X25519':
        return 'ECDH-ES+A256KW';
      case 'Ed25519':
        return 'EdDSA';
      default:
        return undefined;
    }
  }
  if (isKeyObject(key)) {
    switch (key.asymmetricKeyType) {
      case 'rsa':
        return usage === 'enc' ? 'RSA-OAEP-256' : 'RS256';
      case 'ec':
        return usage === 'enc' ? 'ECDH-ES+A256KW' : EC_SIG_ALG[curveOfKeyObject(key)];
      case 'x25519':
      case 'x448':
        return 'ECDH-ES+A256KW';
      case 'ed25519':
        return 'EdDSA';
      default:
        return undefined;
    }
  }
  return undefined;
};

const NODE_CURVE_NAMES = { prime256v1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521' };
const curveOfKeyObject = (key) => {
  const curve = key.asymmetricKeyDetails?.namedCurve;
  return NODE_CURVE_NAMES[curve] ?? curve;
};

const PEM_IMPORTERS = {
  'PUBLIC KEY': importSPKI,
  'PRIVATE KEY': importPKCS8,
  CERTIFICATE: importX509,
};

const PEM_CANDIDATES = {
  enc: ['RSA-OAEP-256', 'ECDH-ES+A256KW'],
  sig: ['RS256', 'ES256', 'ES384', 'ES512', 'EdDSA'],
};

/** Convert a PEM string into a JWK, trying the given algorithms until one fits the key type. */
const pemToJwk = async (pem, candidates) => {
  const label = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(pem)?.[1];
  const importer = PEM_IMPORTERS[label];
  if (!importer) {
    throw new TypeError(
      label
        ? `Unsupported PEM type "${label}". Use SPKI ("PUBLIC KEY"), PKCS#8 ("PRIVATE KEY") or an X.509 certificate; ` +
            'convert PKCS#1/SEC1 keys with `openssl pkcs8 -topk8 -nocrypt -in key.pem` or `openssl pkey -pubout`'
        : 'Not a valid PEM string',
    );
  }
  let lastError;
  for (const alg of candidates) {
    try {
      const key = await importer(pem, alg, { extractable: true });
      return await exportJWK(key);
    } catch (err) {
      lastError = err;
    }
  }
  throw new TypeError(`Could not import PEM key: ${lastError?.message ?? 'unsupported key type'}`, { cause: lastError });
};

/**
 * Normalise any supported key input into either `{ jwk }` or `{ key }`.
 * Accepted: JWK object, base64url-encoded JWK string, PEM string, CryptoKey, Node KeyObject.
 */
const normalizeKey = async (input, usage, alg) => {
  if (input === undefined || input === null || input === '') throw new TypeError('Missing key');
  if (isCryptoKey(input) || isKeyObject(input)) return { key: input };
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('-----BEGIN')) {
      return { jwk: await pemToJwk(trimmed, alg ? [alg] : PEM_CANDIDATES[usage]) };
    }
    let jwk;
    try {
      jwk = decode(trimmed);
    } catch (err) {
      throw new TypeError('Key string is neither PEM nor a base64url-encoded JWK', { cause: err });
    }
    if (!isPlainObject(jwk) || typeof jwk.kty !== 'string') throw new TypeError('Encoded key is not a JWK');
    return { jwk };
  }
  if (input instanceof Uint8Array) {
    throw new TypeError('Symmetric secrets are not supported; use an asymmetric key pair from generateKeys()');
  }
  if (isPlainObject(input) && typeof input.kty === 'string') return { jwk: { ...input } };
  throw new TypeError('Unsupported key: expected a JWK, base64url-encoded JWK, PEM string, CryptoKey or KeyObject');
};

const defaultAlgorithm = (jwk, usage) => {
  const [first] = allowedAlgorithms(jwk, usage);
  if (!first) {
    throw new errors.JOSENotSupported(`A ${jwk.kty}${jwk.crv ? ` ${jwk.crv}` : ''} key cannot be used for ${usageLabel(usage)}`);
  }
  return first;
};

/**
 * Resolve a key for an operation where *we* choose the algorithm (encrypt, sign).
 * `needPrivate` — signing requires the private half; encryption uses the public half.
 */
const resolveOutgoingKey = async (input, usage, requestedAlg, needPrivate) => {
  const normalized = await normalizeKey(input, usage, requestedAlg);
  if (normalized.key) {
    const alg = requestedAlg ?? deduceAlgorithm(normalized.key, usage);
    if (!alg) throw new TypeError('Cannot infer an algorithm for this key; pass options.alg');
    return { key: normalized.key, alg, kid: undefined };
  }
  const { jwk } = normalized;
  const alg = requestedAlg ?? jwk.alg ?? defaultAlgorithm(jwk, usage);
  assertCompatible(jwk, alg, usage);
  if (needPrivate && !isPrivateJwk(jwk)) throw new TypeError(`${usageLabel(usage)} requires a private key`);
  const material = needPrivate ? jwk : toPublicJwk(jwk);
  return { key: await importJWK(material, alg), alg, kid: jwk.kid };
};

/**
 * Build a jose key-resolver for an operation where the *token header* names the algorithm
 * (decrypt, verify). The header algorithm is checked against the key before import.
 */
const incomingKeyResolver = async (input, usage, needPrivate) => {
  const normalized = await normalizeKey(input, usage);
  if (normalized.key) return { resolver: () => normalized.key, jwk: undefined };
  const { jwk } = normalized;
  if (needPrivate && !isPrivateJwk(jwk)) throw new TypeError('Decryption requires a private key');
  const material = needPrivate ? jwk : toPublicJwk(jwk);
  const cache = new Map();
  const resolver = (protectedHeader, token) => {
    const alg = protectedHeader?.alg ?? token?.header?.alg ?? token?.unprotected?.alg;
    if (typeof alg !== 'string') throw new errors.JOSEInvalid('Token header is missing "alg"');
    assertCompatible(jwk, alg, usage);
    if (!cache.has(alg)) cache.set(alg, importJWK(material, alg));
    return cache.get(alg);
  };
  return { resolver, jwk };
};

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

const normalizeGenerateArgs = (args) => {
  if (args.length === 0 || (args.length === 1 && (args[0] === undefined || isPlainObject(args[0])))) {
    return { ...args[0] };
  }
  // 1.x positional form: generateKeys(kty, size, isEncoded, isPadded)
  const [kty, size, encoded, padded] = args;
  const options = { kty, encoded, padded };
  if (typeof size === 'string') options.crv = size;
  else if (size !== undefined) options.size = size;
  return options;
};

/**
 * Generate an asymmetric key pair as JWKs.
 *
 * generateKeys()                                   // RSA-2048 for encryption
 * generateKeys({ kty: 'EC', crv: 'P-384' })
 * generateKeys({ kty: 'OKP', use: 'sig' })         // Ed25519 signing keys
 * generateKeys('RSA', 4096, true, true)            // 1.x positional form still works
 */
export async function generateKeys(...args) {
  const options = normalizeGenerateArgs(args);
  const use = options.use ?? 'enc';
  if (use !== 'enc' && use !== 'sig') throw new TypeError('use must be "enc" or "sig"');
  const kty = String(options.kty ?? 'RSA').toUpperCase();
  const genOptions = { extractable: true };
  let alg = options.alg;

  if (kty === 'RSA') {
    const size = options.size ?? DEFAULT_RSA_SIZE;
    if (!Number.isInteger(size) || size < 2048) throw new TypeError('RSA key size must be an integer of at least 2048 bits');
    genOptions.modulusLength = size;
    alg ??= use === 'enc' ? 'RSA-OAEP-256' : 'RS256';
  } else if (kty === 'EC') {
    const crv = options.crv ?? (options.size !== undefined ? EC_CURVE_FOR_BITS[options.size] : 'P-256');
    if (!EC_SIG_ALG[crv]) {
      throw new TypeError(`EC keys take a curve ("P-256", "P-384" or "P-521"), got ${JSON.stringify(options.crv ?? options.size)}`);
    }
    if (use === 'enc') {
      alg ??= 'ECDH-ES+A256KW';
      genOptions.crv = crv;
    } else {
      alg ??= EC_SIG_ALG[crv];
    }
    if (use === 'sig' && alg !== EC_SIG_ALG[crv]) throw new TypeError(`Curve ${crv} signs with ${EC_SIG_ALG[crv]}, not ${alg}`);
  } else if (kty === 'OKP') {
    const crv = options.crv ?? (use === 'enc' ? 'X25519' : 'Ed25519');
    if (use === 'enc' && !ECDH_CURVES.includes(crv)) throw new TypeError(`OKP encryption keys use X25519 or X448, got ${crv}`);
    if (use === 'sig' && !EDDSA_CURVES.includes(crv)) throw new TypeError(`OKP signing keys use Ed25519, got ${crv}`);
    alg ??= use === 'enc' ? 'ECDH-ES+A256KW' : 'EdDSA';
    genOptions.crv = crv;
  } else {
    throw new TypeError(`Unsupported key type "${options.kty}"; use "RSA", "EC" or "OKP"`);
  }

  const { publicKey, privateKey } = await generateKeyPair(alg, genOptions);
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  const kid = options.kid ?? (await calculateJwkThumbprint(publicJwk));
  assertCompatible({ ...publicJwk, use }, alg, use);

  const meta = { kid, use, alg };
  let public_key = { ...publicJwk, ...meta };
  const private_key = { ...privateJwk, ...meta };
  if (options.encoded) public_key = encode(public_key, Boolean(options.padded));
  return { public_key, private_key };
}

/** RFC 7638 JWK thumbprint (SHA-256), suitable as a stable `kid`. */
export async function getKeyId(key) {
  const { jwk } = await normalizeKey(key, 'enc');
  if (!jwk) throw new TypeError('getKeyId expects a JWK, encoded JWK or PEM string');
  return calculateJwkThumbprint(toPublicJwk(jwk));
}

/** Export a key (JWK, encoded JWK, CryptoKey or KeyObject) as PEM: SPKI for public keys, PKCS#8 for private keys. */
export async function toPem(key) {
  const normalized = await normalizeKey(key, 'enc');
  let keyLike = normalized.key;
  if (!keyLike) {
    const { jwk } = normalized;
    const usage = jwk.use ?? (jwk.kty === 'OKP' && EDDSA_CURVES.includes(jwk.crv) ? 'sig' : 'enc');
    const alg = jwk.alg ?? defaultAlgorithm(jwk, usage);
    keyLike = await importJWK(jwk, alg, { extractable: true });
  }
  return keyLike.type === 'private' ? exportPKCS8(keyLike) : exportSPKI(keyLike);
}

/**
 * Import a PEM string (SPKI public key, PKCS#8 private key or X.509 certificate) as a JWK.
 * Pass `use` / `alg` to bind the resulting JWK; `kid` is set to the RFC 7638 thumbprint.
 */
export async function fromPem(pem, options = {}) {
  if (typeof pem !== 'string') throw new TypeError('fromPem expects a PEM string');
  const { alg, use } = options;
  const candidates = alg ? [alg] : use ? PEM_CANDIDATES[use] : [...PEM_CANDIDATES.enc, ...PEM_CANDIDATES.sig];
  if (!candidates) throw new TypeError('use must be "enc" or "sig"');
  const jwk = await pemToJwk(pem.trim(), candidates);
  const result = { ...jwk, kid: await calculateJwkThumbprint(toPublicJwk(jwk)) };
  if (use) result.use = use;
  if (alg) result.alg = alg;
  if (use && alg) assertCompatible(result, alg, use);
  return result;
}

// ---------------------------------------------------------------------------
// Encryption (JWE)
// ---------------------------------------------------------------------------

/**
 * Encrypt any JSON-serialisable value (or raw Uint8Array) to one or more public keys.
 * Returns a compact JWE string by default, or a General JSON JWE object with `format: 'json'`
 * (always used when encrypting to several recipients).
 *
 * The third argument may be a boolean for 1.x compatibility (key is base64url-encoded);
 * encoded keys are also detected automatically.
 */
export async function encryptContent(public_key, payload, options) {
  const opts = normalizeOptions(options);
  assertPayload(payload);
  const plaintext = toBytes(payload);
  const keys = Array.isArray(public_key) ? public_key : [public_key];
  if (keys.length === 0) throw new TypeError('Missing key');
  const format = opts.format ?? (keys.length > 1 ? 'json' : 'compact');
  if (format !== 'compact' && format !== 'json') throw new TypeError('format must be "compact" or "json"');
  if (format === 'compact' && keys.length > 1) throw new TypeError('Compact JWE supports a single recipient; use format: "json"');
  const enc = opts.enc ?? DEFAULT_CONTENT_ENC;

  const recipients = await Promise.all(keys.map((key) => resolveOutgoingKey(key, 'enc', opts.alg, false)));

  if (format === 'compact') {
    const [{ key, alg, kid }] = recipients;
    const header = { ...opts.header, alg, enc, ...(kid && { kid }) };
    return new CompactEncrypt(plaintext).setProtectedHeader(header).encrypt(key);
  }

  if (recipients.length > 1 && recipients.some(({ alg }) => alg === 'ECDH-ES')) {
    throw new TypeError('ECDH-ES (direct key agreement) cannot be used with multiple recipients');
  }
  const jwe = new GeneralEncrypt(plaintext).setProtectedHeader({ ...opts.header, enc });
  for (const { key, alg, kid } of recipients) {
    jwe.addRecipient(key).setUnprotectedHeader({ alg, ...(kid && { kid }) });
  }
  return jwe.encrypt();
}

/**
 * Decrypt a JWE produced by encryptContent() — or by easy-jose 1.x / node-jose.
 * Accepts compact strings and Flattened or General JSON objects.
 *
 * Options: `encoded` (payload is base64url-encoded JSON, as in 1.x), `raw` (return bytes),
 * `complete` (return `{ payload, protectedHeader }`). A boolean third argument means `encoded`.
 */
export async function decryptContent(private_key, payload, options) {
  const opts = normalizeOptions(options);
  if (payload === undefined || payload === null || payload === '') throw new TypeError('Missing encrypted payload');
  const jwe = opts.encoded ? decode(payload) : payload;
  const { resolver } = await incomingKeyResolver(private_key, 'enc', true);
  const decryptOptions = {};
  if (opts.algorithms) decryptOptions.keyManagementAlgorithms = opts.algorithms;
  if (opts.contentAlgorithms) decryptOptions.contentEncryptionAlgorithms = opts.contentAlgorithms;

  let result;
  if (typeof jwe === 'string') result = await compactDecrypt(jwe, resolver, decryptOptions);
  else if (isPlainObject(jwe) && Array.isArray(jwe.recipients)) result = await generalDecrypt(jwe, resolver, decryptOptions);
  else if (isPlainObject(jwe)) result = await flattenedDecrypt(jwe, resolver, decryptOptions);
  else throw new TypeError('Encrypted payload must be a compact JWE string or a JWE JSON object');

  const value = fromBytes(result.plaintext, opts.raw);
  return opts.complete ? { payload: value, protectedHeader: result.protectedHeader } : value;
}

// ---------------------------------------------------------------------------
// Signing (JWS)
// ---------------------------------------------------------------------------

/** Sign any JSON-serialisable value (or raw Uint8Array) and return a compact JWS string. */
export async function signContent(private_key, payload, options = {}) {
  const opts = normalizeOptions(options);
  assertPayload(payload);
  const { key, alg, kid } = await resolveOutgoingKey(private_key, 'sig', opts.alg, true);
  const header = { ...opts.header, alg, ...(kid && { kid }) };
  return new CompactSign(toBytes(payload)).setProtectedHeader(header).sign(key);
}

/**
 * Verify a compact JWS and return its payload. Only algorithms valid for the key are accepted
 * (narrow further with `algorithms`). `complete: true` also returns the protected header.
 */
export async function verifyContent(public_key, jws, options = {}) {
  const opts = normalizeOptions(options);
  if (typeof jws !== 'string' || jws === '') throw new TypeError('Missing signed payload');
  const { resolver, jwk } = await incomingKeyResolver(public_key, 'sig', false);
  const algorithms = opts.algorithms ?? (jwk ? algorithmsForJwk(jwk, 'sig') : undefined);
  const result = await compactVerify(jws, resolver, algorithms ? { algorithms } : {});
  const value = fromBytes(result.payload, opts.raw);
  return opts.complete ? { payload: value, protectedHeader: result.protectedHeader } : value;
}

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

// Relative durations: numbers are seconds from now; strings use jose's syntax ("2h", "30m", "7 days").
const relativeTime = (value) => (typeof value === 'number' ? `${value}s` : value);

/**
 * Create a signed JWT. Tokens expire after 1 hour unless `expiresIn` (or an `exp` claim) says
 * otherwise; pass `expiresIn: null` for a token without expiry.
 */
export async function signJwt(private_key, claims = {}, options = {}) {
  if (!isPlainObject(claims)) throw new TypeError('JWT claims must be an object');
  const opts = normalizeOptions(options);
  const { key, alg, kid } = await resolveOutgoingKey(private_key, 'sig', opts.alg, true);
  const jwt = new SignJWT(claims).setProtectedHeader({ typ: 'JWT', ...opts.header, alg, ...(kid && { kid }) });

  if (claims.iat === undefined) jwt.setIssuedAt();
  const expiresIn = opts.expiresIn === undefined && claims.exp === undefined ? DEFAULT_JWT_LIFETIME : opts.expiresIn;
  if (expiresIn !== undefined && expiresIn !== null) jwt.setExpirationTime(relativeTime(expiresIn));
  if (opts.notBefore !== undefined) jwt.setNotBefore(relativeTime(opts.notBefore));
  if (opts.issuer !== undefined) jwt.setIssuer(opts.issuer);
  if (opts.subject !== undefined) jwt.setSubject(opts.subject);
  if (opts.audience !== undefined) jwt.setAudience(opts.audience);
  if (opts.jwtId !== undefined) jwt.setJti(opts.jwtId);
  return jwt.sign(key);
}

/**
 * Verify a JWT's signature and claims (exp / nbf always; iss / aud / sub / maxTokenAge when given)
 * and return its claims. `complete: true` also returns the protected header.
 */
export async function verifyJwt(public_key, token, options = {}) {
  const opts = normalizeOptions(options);
  if (typeof token !== 'string' || token === '') throw new TypeError('Missing token');
  const { resolver, jwk } = await incomingKeyResolver(public_key, 'sig', false);
  const { complete, ...verifyOptions } = opts;
  verifyOptions.algorithms ??= jwk ? algorithmsForJwk(jwk, 'sig') : undefined;
  if (verifyOptions.algorithms === undefined) delete verifyOptions.algorithms;
  const result = await jwtVerify(token, resolver, verifyOptions);
  return complete ? { payload: result.payload, protectedHeader: result.protectedHeader } : result.payload;
}

// ---------------------------------------------------------------------------
// Utilities (unchanged behaviour from 1.x, now runtime-agnostic)
// ---------------------------------------------------------------------------

/** base64url-encode the JSON form of a value. `padded` appends "=" padding for legacy consumers. */
export function encode(payload, padded = false) {
  let encoded = base64url.encode(encoder.encode(JSON.stringify(payload)));
  if (padded) while (encoded.length % 4 !== 0) encoded += '=';
  return encoded;
}

/** Reverse of encode(). Accepts padded input and standard base64 characters too. */
export function decode(payload) {
  if (typeof payload !== 'string') throw new TypeError('decode expects a string');
  const normalized = payload.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return JSON.parse(decoder.decode(base64url.decode(normalized)));
}

/** JSON-serialise a value into UTF-8 bytes. */
export function convertToU8A(payload) {
  return encoder.encode(JSON.stringify(payload));
}

/** Parse UTF-8 JSON bytes back into a value. */
export function convertU8A(u8a) {
  return JSON.parse(decoder.decode(u8a));
}

/**
 * @deprecated No longer needed — easy-jose 2 keeps no global keystore. Kept so 1.x code runs unchanged.
 */
export function init() {}

export default {
  init,
  generateKeys,
  getKeyId,
  toPem,
  fromPem,
  encryptContent,
  decryptContent,
  signContent,
  verifyContent,
  signJwt,
  verifyJwt,
  encode,
  decode,
  convertToU8A,
  convertU8A,
  errors,
};
