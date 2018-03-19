'use strict';

require('fast-text-encoding');
const jose = require('node-jose');
const URLSafeBase64 = require('urlsafe-base64');

if (typeof Promise === "undefined") {
  require("es6-promise").polyfill();
}

let keystore;

const init = () => {
  keystore = jose.JWK.createKeyStore();
};

const getKeystore = () => {
  return keystore;
};

const generateKeys = async (kty = 'RSA', size = 2048, isEncoded = false, isPadded = false) => {
  return keystore.generate(kty, size).then(result => {
    let public_key = result.toJSON();
    if (isEncoded) {
      public_key = encode(result.toJSON());
      if (isPadded) {
        while (public_key.length % 4 !== 0) {
          public_key += "=";
        }
      }
    }

    // return both public and private keys
    return { public_key, private_key: result.toJSON(true) };
  });
};

const encryptContent = async (public_key, payload, isKeyEncoded = false) => {
  if (!payload) throw new Error('Missing encrypted payload');

  let key = public_key;
  // is public key base64 encoded
  if (isKeyEncoded) {
    key = decode(public_key);
  }

  try {
    const prepare = await jose.JWK.asKey(key);
    const data = await jose.JWE.createEncrypt(key).update(JSON.stringify(payload)).final();

    return data;
  } catch (err) {
    throw new Error(err);
  }
};

const decryptContent = async (private_key, payload, isPayloadEncoded = false) => {
  if (!payload) throw new Error('Missing encrypted payload');

  let enc = payload;
  // is payload base64 encoded
  if (isPayloadEncoded) {
    enc = decode(payload);
  }

  try {
    const add = await keystore.add(private_key);
    const data = await jose.JWE.createDecrypt(keystore).decrypt(enc);
    return convertU8AToString(data.payload);
  } catch (err) {
    throw new Error(err);
  }
};

const encode = payload => {
  return URLSafeBase64.encode(Buffer.from(JSON.stringify(payload), 'utf8'));
};

const decode = payload => {
  return JSON.parse(URLSafeBase64.decode(payload).toString('utf8'));
};

const convertU8AToString = u8a => {
  return JSON.parse(new TextDecoder("utf-8").decode(u8a));
};

module.exports = {
  init,
  getKeystore,
  generateKeys,
  encryptContent,
  decryptContent,
  encode,
  decode,
  convertU8AToString
};
