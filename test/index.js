/* global describe, it */

var assert = require('assert')
var wif = require('wif')
var bip38 = require('../')
var bs58check = require('bs58check')
var fixtures = require('./fixtures')

describe('bip38', function () {
  this.timeout(200000)

  describe('decrypt (async)', function () {
    fixtures.valid.forEach(function (f) {
      it('should decrypt ' + f.description, function () {
        bip38.decryptAsync(f.bip38, f.passphrase, (result) => {
          var prefix = f.network ? f.network.private : 0x80
          assert.strictEqual(wif.encode(prefix, result.privateKey, result.compressed), f.wif)
        }, null, f.network)
      })
    })

    fixtures.invalid.decrypt.forEach(function (f) {
      it('should throw ' + f.description, function () {
        assert.throws(function () {
          bip38.decryptAsync(f.bip38, f.passphrase, (out) => {
          })
        }, new RegExp(f.description, 'i'))
      })
    })

    fixtures.invalid.verify.forEach(function (f) {
      it('should throw because ' + f.description, function () {
        assert.throws(function () {
          bip38.decryptAsync(f.base58, 'foobar', (out) => {
          })
        }, new RegExp(f.exception))
      })
    })
  })

  describe('encrypt (async)', function () {
    fixtures.valid.forEach(function (f) {
      if (f.decryptOnly) return

      it('should encrypt ' + f.description, function () {
        var buffer = bs58check.decode(f.wif)

        bip38.encryptAsync(buffer.slice(1, 33), !!buffer[33], f.passphrase, (out) => {
          assert.strictEqual(out, f.bip38)
        }, null, f.network)
      })
    })
  })

  describe('verify', function () {
    fixtures.valid.forEach(function (f) {
      it('should return true for ' + f.bip38, function () {
        assert(bip38.verify(f.bip38))
      })
    })

    fixtures.invalid.verify.forEach(function (f) {
      it('should return false for ' + f.description, function () {
        assert(!bip38.verify(f.base58))
      })
    })
  })
})
