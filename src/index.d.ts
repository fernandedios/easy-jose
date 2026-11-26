import type { JWK, JWTPayload, JWEHeaderParameters, JWSHeaderParameters, GeneralJWE, FlattenedJWE } from 'jose';
import { errors } from 'jose';

export { errors };
export type { JWK, JWTPayload };

/** Any value JSON.stringify can serialise, or raw bytes. */
export type Payload = unknown;

/** Node.js `KeyObject` (structural, so this package does not require @types/node). */
export interface KeyObjectLike {
  readonly type: 'public' | 'private' | 'secret';
  readonly asymmetricKeyType?: string;
  export(...args: any[]): unknown;
}

/** A key in any supported form: JWK object, base64url-encoded JWK, PEM string, CryptoKey or Node KeyObject. */
export type KeyInput = JWK | string | CryptoKey | KeyObjectLike;

export type KeyUse = 'enc' | 'sig';

export interface GenerateKeysOptions {
  /** Key type. Default `"RSA"`. */
  kty?: 'RSA' | 'EC' | 'OKP';
  /** `"enc"` (default) for encryption keys, `"sig"` for signing keys. */
  use?: KeyUse;
  /** RSA modulus length in bits (default 2048, minimum 2048). For EC, 256 / 384 / 521 map to a curve. */
  size?: number;
  /** Curve: `"P-256"` (default), `"P-384"`, `"P-521"` for EC; `"X25519"` / `"Ed25519"` for OKP. */
  crv?: 'P-256' | 'P-384' | 'P-521' | 'X25519' | 'X448' | 'Ed25519';
  /** Override the algorithm bound to the key (e.g. `"PS256"`, `"RSA-OAEP-512"`). */
  alg?: string;
  /** Key ID. Defaults to the RFC 7638 thumbprint. */
  kid?: string;
  /** Return `public_key` as a base64url-encoded string. */
  encoded?: boolean;
  /** Add `=` padding to the encoded public key. */
  padded?: boolean;
}

export interface KeyPair<P = JWK> {
  public_key: P;
  private_key: JWK;
}

export function generateKeys(options: GenerateKeysOptions & { encoded: true }): Promise<KeyPair<string>>;
export function generateKeys(options?: GenerateKeysOptions): Promise<KeyPair<JWK>>;
/** 1.x positional form. */
export function generateKeys(kty: 'RSA' | 'EC' | 'OKP', size?: number | string, isEncoded?: false, isPadded?: boolean): Promise<KeyPair<JWK>>;
export function generateKeys(kty: 'RSA' | 'EC' | 'OKP', size: number | string | undefined, isEncoded: true, isPadded?: boolean): Promise<KeyPair<string>>;

export function getKeyId(key: JWK | string): Promise<string>;
export function toPem(key: KeyInput): Promise<string>;
export function fromPem(pem: string, options?: { use?: KeyUse; alg?: string }): Promise<JWK>;

export interface EncryptOptions {
  /** Key-management algorithm. Defaults to the key's `alg`, else RSA-OAEP-256 / ECDH-ES+A256KW. */
  alg?: string;
  /** Content encryption. Default `"A256GCM"`. */
  enc?: string;
  /** `"compact"` (default for one recipient) or `"json"` (General JSON; always used for several). */
  format?: 'compact' | 'json';
  /** Extra protected-header parameters (e.g. `cty`, `typ`). */
  header?: JWEHeaderParameters;
  /** 1.x compatibility flag; encoded keys are detected automatically. */
  encoded?: boolean;
}

export function encryptContent(publicKey: KeyInput, payload: Payload, options?: EncryptOptions & { format?: 'compact' }): Promise<string>;
export function encryptContent(publicKey: KeyInput | KeyInput[], payload: Payload, options: EncryptOptions & { format: 'json' }): Promise<GeneralJWE>;
export function encryptContent(publicKey: KeyInput[], payload: Payload, options?: EncryptOptions): Promise<GeneralJWE>;
/** 1.x form: third argument is `isKeyEncoded`. */
export function encryptContent(publicKey: KeyInput, payload: Payload, isKeyEncoded: boolean): Promise<string>;

export interface DecryptOptions {
  /** Payload is base64url-encoded JSON (1.x `isPayloadEncoded`). */
  encoded?: boolean;
  /** Return the plaintext bytes instead of parsing JSON. */
  raw?: boolean;
  /** Return `{ payload, protectedHeader }`. */
  complete?: boolean;
  /** Allowed key-management algorithms. */
  algorithms?: string[];
  /** Allowed content-encryption algorithms. */
  contentAlgorithms?: string[];
}

export interface DecryptResult<T> {
  payload: T;
  protectedHeader: JWEHeaderParameters | undefined;
}

export type EncryptedPayload = string | GeneralJWE | FlattenedJWE;

export function decryptContent(privateKey: KeyInput, payload: EncryptedPayload, options: DecryptOptions & { raw: true; complete: true }): Promise<DecryptResult<Uint8Array>>;
export function decryptContent(privateKey: KeyInput, payload: EncryptedPayload, options: DecryptOptions & { raw: true }): Promise<Uint8Array>;
export function decryptContent<T = any>(privateKey: KeyInput, payload: EncryptedPayload, options: DecryptOptions & { complete: true }): Promise<DecryptResult<T>>;
export function decryptContent<T = any>(privateKey: KeyInput, payload: EncryptedPayload, options?: DecryptOptions | boolean): Promise<T>;

export interface SignOptions {
  /** Signature algorithm. Defaults to the key's `alg`, else RS256 / ES256-512 / EdDSA. */
  alg?: string;
  /** Extra protected-header parameters. */
  header?: JWSHeaderParameters;
}

export interface VerifyOptions {
  /** Allowed algorithms. Defaults to those valid for the key (its `alg` if it has one). */
  algorithms?: string[];
  raw?: boolean;
  complete?: boolean;
}

export interface VerifyResult<T> {
  payload: T;
  protectedHeader: JWSHeaderParameters;
}

export function signContent(privateKey: KeyInput, payload: Payload, options?: SignOptions): Promise<string>;
export function verifyContent(publicKey: KeyInput, jws: string, options: VerifyOptions & { raw: true; complete: true }): Promise<VerifyResult<Uint8Array>>;
export function verifyContent(publicKey: KeyInput, jws: string, options: VerifyOptions & { raw: true }): Promise<Uint8Array>;
export function verifyContent<T = any>(publicKey: KeyInput, jws: string, options: VerifyOptions & { complete: true }): Promise<VerifyResult<T>>;
export function verifyContent<T = any>(publicKey: KeyInput, jws: string, options?: VerifyOptions): Promise<T>;

/** Seconds from now, or a jose duration string such as `"2h"`, `"30m"`, `"7 days"`. */
export type Duration = number | string;

export interface SignJwtOptions extends SignOptions {
  /** Lifetime. Default `"1h"`; `null` for no expiry. Ignored if the claims already contain `exp`. */
  expiresIn?: Duration | Date | null;
  notBefore?: Duration | Date;
  issuer?: string;
  subject?: string;
  audience?: string | string[];
  jwtId?: string;
}

export interface VerifyJwtOptions {
  algorithms?: string[];
  issuer?: string | string[];
  audience?: string | string[];
  subject?: string;
  /** Reject tokens older than this (`iat`-based), e.g. `"10m"`. */
  maxTokenAge?: string | number;
  /** Allowed clock skew, e.g. `"30s"` or seconds. */
  clockTolerance?: string | number;
  /** Claims that must be present. */
  requiredClaims?: string[];
  /** Expected `typ` header. */
  typ?: string;
  /** Evaluate time claims against this date instead of now. */
  currentDate?: Date;
  complete?: boolean;
}

export function signJwt(privateKey: KeyInput, claims?: JWTPayload, options?: SignJwtOptions): Promise<string>;
export function verifyJwt<T extends JWTPayload = JWTPayload>(publicKey: KeyInput, token: string, options: VerifyJwtOptions & { complete: true }): Promise<VerifyResult<T>>;
export function verifyJwt<T extends JWTPayload = JWTPayload>(publicKey: KeyInput, token: string, options?: VerifyJwtOptions): Promise<T>;

export function encode(payload: unknown, padded?: boolean): string;
export function decode<T = any>(payload: string): T;
export function convertToU8A(payload: unknown): Uint8Array;
export function convertU8A<T = any>(u8a: Uint8Array): T;

/** @deprecated No-op since 2.0 — there is no global keystore any more. */
export function init(): void;

declare const easyJose: {
  init: typeof init;
  generateKeys: typeof generateKeys;
  getKeyId: typeof getKeyId;
  toPem: typeof toPem;
  fromPem: typeof fromPem;
  encryptContent: typeof encryptContent;
  decryptContent: typeof decryptContent;
  signContent: typeof signContent;
  verifyContent: typeof verifyContent;
  signJwt: typeof signJwt;
  verifyJwt: typeof verifyJwt;
  encode: typeof encode;
  decode: typeof decode;
  convertToU8A: typeof convertToU8A;
  convertU8A: typeof convertU8A;
  errors: typeof errors;
};
export default easyJose;
