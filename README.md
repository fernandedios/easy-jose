easy-jose
=========

[![Status](https://travis-ci.org/fernandedios/easy-jose.svg?branch=master)](https://travis-ci.org/fernandedios/easy-jose)
[![npm version](https://img.shields.io/npm/v/easy-jose.png)](https://npmjs.org/package/easy-jose "View this project on npm")

> Javascript Object Signing and Encryption standard

Straightforward encryption/decryption utility based on [node-jose] by Cisco

Getting Started
------------

Install via NPM

```bash
$ npm install --save easy-jose

```

Basic Usage
------------

Require the library, then initialize.

```js
const easyJose = require('easy-jose');
easyJose.init();

```

### Generating Keys: generateKeys()
Returns an object with public_key and private_key

Optional Arguments:
- kty: key type, default is "RSA"
- size: size in bits, default is 2048
- isEncoded: boolean, base64 encode the public key, default is false
- isPadded: boolean, add padding to base64 encoding, default is false

Example:
```js
const keys = easyJose.generateKeys("EC", 4096);

```

### Encrypting Content: encryptContent()

Required Arguments:
- public_key
- payload: data to encrypt

Optional Argument
- isKeyEncoded: boolean, tell easyJose if you're using a base64 encoded public_key

Example:
```js
const encrypted = easyJose.encryptContent(public_key, payload);

```

### Decrypting Content: decryptContent()

Required Arguments:
- private_key
- payload: data to decrypt

Optional Argument
- isPayloadEncoded: boolean, tell easyJose if you're using a base64 encoded payload

Example:
```js
const decrypted = easyJose.decryptContent(private_key, encrypted);

```


### Example Implementation

```js
const easyJose = require('easy-jose');
const somedata = {
  txt: 'hello'
};

(async () => {
  easyJose.init();
  const { private_key, public_key } = await easyJose.generateKeys();
  console.log(private_key);
  console.log(public_key);

  const encrypted = await easyJose.encryptContent(public_key, somedata);
  console.log(encrypted);

  const decrypted = await easyJose.decryptContent(private_key, encrypted);
  console.log(decrypted);
})();
```

Utilities
------------

### Base64 Encoder

```js
const encoded = easyJose.encode(raw);

```

### Base64 Decoder

```js
const decoded = easyJose.decode(base64EncodedString);

```

### Array Buffer converter

```js
const u8a = easyJose.convertToU8A(data);

```

### Array Buffer Decoder

```js
const data = easyJose.convertU8A(arrayBufferData);

```

Thanks
------

easy-jose* © 2018, Fernan de Dios. Released under the [MIT License].<br>

> [fernandedios.com](http://fernandedios.com) &nbsp;&middot;&nbsp;
> GitHub [@fernandedios](https://github.com/fernandedios) &nbsp;&middot;&nbsp;
> Twitter [@fernan_de_dios](https://twitter.com/fernan_de_dios)

[MIT License]: http://mit-license.org/
[node-jose]: https://github.com/cisco/node-jose
