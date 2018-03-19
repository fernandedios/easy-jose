const jose = require('jose');
const URLSafeBase64 = require('urlsafe-base64');

const easyJose = (kty = 'RSA', size = 2048) => {
  const keystore = jose.JWK.createKeyStore();

  async function generateKeys(isEncoded = false, isPadded = false) {
    try {
      const keys = await keystore.generate(kty, size);

      // we only encode public key
      if (isEncoded) {
        let public_key = URLSafeBase64.encode(Buffer.from(JSON.stringify(result.toJSON()), 'utf8'));

        // for compatibility with other base64 encoders like python's
        if (isPadded) {
          while (public_key.length % 4 !== 0) {
            public_key += "=";
          }
        }
      }

      // return both public and private keys
      return { public_key, private_key: result.toJSON(true) };
    }
    catch (err) throw new Error(err);
  }

  async function encryptContent(public_key, payload, isEncoded) {
    if (!payload) throw new Error('Missing encrypted payload');
    
    let key = public_key;
    // is public key base64 encoded
    if (isEncoded) {
      key = JSON.parse(URLSafeBase64.decode(public_key).toString('utf8'));
    }

    try {
      const prepare = await jose.JWK.asKey(key);
      const data = await jose.JWE.createEncrypt(key)
        .update(JSON.stringify(payload))
        .final();

      return data;
    }
    catch (err) throw new Error(err);
  }

  function getKeystore() {
    return keystore;
  }
};

module.exports = easyJose;
