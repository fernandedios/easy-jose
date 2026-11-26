// Compile-only check of the public type declarations (run with `npm run typecheck`).
import easyJose, { generateKeys, encryptContent, decryptContent, signJwt, verifyJwt, toPem, errors, type JWK } from 'easy-jose';

async function main() {
  const { public_key, private_key } = await generateKeys();
  const jwkPub: JWK = public_key;
  const compact: string = await encryptContent(jwkPub, { a: 1 });
  const general = await encryptContent([public_key, public_key], 'x');
  const recipients: number = general.recipients.length;
  const value = await decryptContent<{ a: number }>(private_key, compact);
  const n: number = value.a;
  const bytes: Uint8Array = await decryptContent(private_key, compact, { raw: true });
  const full = await decryptContent(private_key, compact, { complete: true });
  void full.protectedHeader;

  const encoded = await generateKeys({ encoded: true });
  const s: string = encoded.public_key;
  const legacy = await generateKeys('RSA', 2048, true, true);
  const s2: string = legacy.public_key;
  await encryptContent(s2, { a: 1 }, true);

  const sig = await generateKeys({ kty: 'OKP', use: 'sig' });
  const token = await signJwt(sig.private_key, { role: 'admin' }, { expiresIn: '2h', audience: 'api' });
  const claims = await verifyJwt<{ role: string }>(sig.public_key, token, { audience: 'api' });
  const role: string = claims.role;
  const pem: string = await toPem(sig.public_key);
  easyJose.init();

  try {
    await verifyJwt(sig.public_key, token);
  } catch (err) {
    if (err instanceof errors.JWTExpired) console.log(err.code);
  }
  return [recipients, n, bytes, s, role, pem];
}
void main;
