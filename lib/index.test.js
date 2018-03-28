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

describe('easyJose utilities', () => {
  it('should base64 encode data using encode', () => {
    const encoded = easyJose.encode(somedata);
    expect(encoded).not.toEqual(somedata);
  });

  it('should decode a base64 encoded string using decode', () => {
    const encoded = easyJose.encode(somedata);
    const decoded = easyJose.decode(encoded);
    expect(decoded).toEqual(somedata);
  });

  it('should encode object to array buffer using convertToU8A', () => {
    const u8a = easyJose.convertToU8A(somedata);
    expect(u8a).not.toEqual(somedata);
  });

  it('should decode an array buffer using convertU8A', () => {
    const u8a = easyJose.convertToU8A(somedata);
    const decoded = easyJose.convertU8A(u8a);
    expect(decoded).toEqual(somedata);
  })
});
