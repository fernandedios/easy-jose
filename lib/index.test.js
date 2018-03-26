const expect = require('expect');
const easyJose = require('./');
const somedata = {
  text: 'hello'
};

beforeEach(() => {
  easyJose.init();
});

describe('easyJose functionality', () => {
  it('should return a keystore using getKeystore', () => {
    expect(easyJose.getKeystore()).toBeDefined();
  });

  it('should return a public and private key using generateKeys', async () => {
    const keys = await easyJose.generateKeys();
    expect(keys).toHaveProperty('public_key');
    expect(keys).toHaveProperty('private_key');
  });

  it('should encrypt data using encryptContent', async () => {
    const { public_key } = await easyJose.generateKeys();
    const result = await easyJose.encryptContent(public_key, somedata);
    expect(result).not.toEqual(somedata);
  });

  it('should decrypt data using decryptContent', async () => {
    const { public_key, private_key } = await easyJose.generateKeys();
    const encrypted = await easyJose.encryptContent(public_key, somedata);
    const result = await easyJose.decryptContent(private_key, encrypted);
    expect(result).toEqual(somedata);
  });
});
