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

      return { public_key, private_key: result.toJSON(true) };
    }
    catch (err) throw new Error(err);
  }

  function getKeystore() {
    return keystore;
  }
};

module.exports = easyJose;
