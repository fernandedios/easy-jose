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

  it('should return a public and private key using generateKeys', (done) => {
    easyJose.generateKeys().then((keys) => {
      expect(keys).toHaveProperty('public_key');
      expect(keys).toHaveProperty('private_key');
      done();
    });
  });

  it('should encrypt data using encryptContent', (done) => {
    easyJose.generateKeys().then(({ public_key }) => {
      easyJose.encryptContent(public_key, somedata).then((result) => {
        expect(result).not.toEqual(somedata);
        done();
      });
    });
  });

  it('should decrypt data using decryptContent', (done) => {
    easyJose.generateKeys().then(({ public_key, private_key }) => {
      easyJose.encryptContent(public_key, somedata).then((encrypted) => {
        easyJose.decryptContent(private_key, encrypted).then((result) => {
          expect(result).toEqual(somedata);
          done();
        });
      });
    });
  });
});
