easy-jose
=========

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

### Example Code

```js
const easyJose = require('easy-jose');
const somedata = {
  txt: 'hello'
};

(async () => {
  easyJose.init();
  const { private_key, public_key } = await easyJose.generateKeys();
  console.log(keys);

  const encrypted = await easyJose.encryptContent(public_key, somedata);
  console.log(encrypted);

  const decrypted = await easyJose.decryptContent(private_key, encrypted);
  console.log(decrypted);
})();
```


Thanks
------

easy-jose* © 2018, Fernan de Dios. Released under the [MIT License].<br>

> [fernandedios.com](http://fernandedios.com) &nbsp;&middot;&nbsp;
> GitHub [@fernandedios](https://github.com/fernandedios) &nbsp;&middot;&nbsp;
> Twitter [@fernan_de_dios](https://twitter.com/fernan_de_dios)

[MIT License]: http://mit-license.org/
[node-jose]: https://github.com/cisco/node-jose
