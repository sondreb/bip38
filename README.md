# bip38-network

[![build status](https://secure.travis-ci.org/bitcoinjs/bip38.svg)](http://travis-ci.org/bitcoinjs/bip38)
[![Coverage Status](https://img.shields.io/coveralls/cryptocoinjs/bip38.svg)](https://coveralls.io/r/cryptocoinjs/bip38)
[![Version](http://img.shields.io/npm/v/bip38.svg)](https://www.npmjs.org/package/bip38)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

A JavaScript component that adheres to the [BIP38](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) standard to secure your crypto currency private keys. Fully compliant with Node.js and the browser (via Browserify).

**bip38-network** is a fork of the original **bip38**, with added support for alternative networks (bip38 only supports bitcoin main network) and relies on an async library for scrypt, making it more performant.

## Performance:

**Intel Core i7-8700K**
- bip38: ~8700ms
- bip38-network: ~430ms

## Why?
BIP38 is a standard process to encrypt Bitcoin and crypto currency private keys that is imprevious to brute force attacks thus protecting the user.

## Backwards compatibility

The 2.0.2 release that adds support for different networks, is available and is compatible with the existing bip38 package. While the latest (3+) version contains breaking changes and only supports async usage.

Installation (compatibility package):

```sh
npm install bip38-network@2.0.2
```

## Package Info
- homepage: [http://cryptocoinjs.com/modules/currency/bip38/](http://cryptocoinjs.com/modules/currency/bip38/)
- github: [https://github.com/cryptocoinjs/bip38](https://github.com/cryptocoinjs/bip38)
- tests: [https://github.com/cryptocoinjs/bip38/tree/master/test](https://github.com/cryptocoinjs/bip38/tree/master/test)
- issues: [https://github.com/cryptocoinjs/bip38/issues](https://github.com/cryptocoinjs/bip38/issues)
- license: **MIT**
- versioning: [http://semver-ftw.org](http://semver-ftw.org)


## Usage

### Installation

    npm install bip38-network


### API
### encrypt(buffer, compressed, passphrase[, progressCallback, scryptParams])

``` javascript
var bip38 = require('bip38-network')
var wif = require('wif')

var myWifString = '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'
var decoded = wif.decode(myWifString)

bip38.encryptAsync(decoded.privateKey, decoded.compressed, 'TestingOneTwoThree', (encryptedKey) => {
console.log(encryptedKey)
})

// => '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg'
```


### decrypt(encryptedKey, passphrase[, progressCallback, scryptParams])

``` javascript
var bip38 = require('bip38')
var wif = require('wif')

var encryptedKey = '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg'
bip38.decryptAsync(encryptedKey, 'TestingOneTwoThree', function (decryptedKey) {
  console.log(decryptedKey)
})

console.log(wif.encode(0x80, decryptedKey.privateKey, decryptedKey.compressed))
// => '5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR'
```


# References
- https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
- https://github.com/pointbiz/bitaddress.org/issues/56 (Safari 6.05 issue)
- https://github.com/casascius/Bitcoin-Address-Utility/tree/master/Model
- https://github.com/nomorecoin/python-bip38-testing/blob/master/bip38.py
- https://github.com/pointbiz/bitaddress.org/blob/master/src/ninja.key.js

