// CommonJS consumers: require() of the ESM package (Node >= 22.12).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const easyJose = require('easy-jose');

test('require("easy-jose") works with the 1.x calling style', async () => {
  easyJose.init();
  const { public_key, private_key } = await easyJose.generateKeys();
  const encrypted = await easyJose.encryptContent(public_key, { txt: 'hello' });
  assert.deepEqual(await easyJose.decryptContent(private_key, encrypted), { txt: 'hello' });
  assert.equal(typeof easyJose.default.signJwt, 'function');
});
