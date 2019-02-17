var aes = require('browserify-aes')
var assert = require('assert')
var Buffer = require('safe-buffer').Buffer
var bs58check = require('bs58check')
var createHash = require('create-hash')
var scryptAsync = require('scrypt-async')
var xor = require('buffer-xor/inplace')
var ecurve = require('ecurve')
var curve = ecurve.getCurveByName('secp256k1')
var BigInteger = require('bigi')

// constants
var SCRYPT_PARAMS = {
  N: 16384, // specified by BIP38
  r: 8,
  p: 8
}

var NETWORK_PARAMS = {
  private: 0x80,
  public: 0x00
}

var NULL = Buffer.alloc(0)

function hash160 (buffer) {
  return createHash('rmd160').update(
    createHash('sha256').update(buffer).digest()
  ).digest()
}

function hash256 (buffer) {
  return createHash('sha256').update(
    createHash('sha256').update(buffer).digest()
  ).digest()
}

function getAddress (d, compressed, networkParams) {
  var Q = curve.G.multiply(d).getEncoded(compressed)
  var hash = hash160(Q)
  var payload = Buffer.allocUnsafe(21)
  payload.writeUInt8(networkParams.public, 0)
  hash.copy(payload, 1)

  return bs58check.encode(payload)
}

function encryptRawAsync (buffer, compressed, passphrase, progressCallback, scryptParams, networkParams) {
  if (buffer.length !== 32) throw new Error('Invalid private key length')
  scryptParams = scryptParams || SCRYPT_PARAMS
  networkParams = networkParams || NETWORK_PARAMS

  var d = BigInteger.fromBuffer(buffer)
  var address = getAddress(d, compressed, networkParams)
  var secret = Buffer.from(passphrase, 'utf8')
  var salt = hash256(address).slice(0, 4)

  var scryptOptions = {
    N: scryptParams.N,
    r: scryptParams.r,
    p: scryptParams.p,
    dkLen: 64
  }

  scryptAsync(secret, salt, scryptOptions, (out) => {
    var buff = Buffer.from(out)
    var derivedHalf1 = buff.slice(0, 32)
    var derivedHalf2 = buff.slice(32, 64)
    var xorBuf = xor(derivedHalf1, buffer)
    var cipher = aes.createCipheriv('aes-256-ecb', derivedHalf2, NULL)
    cipher.setAutoPadding(false)
    cipher.end(xorBuf)

    var cipherText = cipher.read()

    // 0x01 | 0x42 | flagByte | salt (4) | cipherText (32)
    var result = Buffer.allocUnsafe(7 + 32)
    result.writeUInt8(0x01, 0)
    result.writeUInt8(0x42, 1)
    result.writeUInt8(compressed ? 0xe0 : 0xc0, 2)
    salt.copy(result, 3)
    cipherText.copy(result, 7)

    progressCallback(result)
  })
}

function encryptAsync (buffer, compressed, passphrase, progressCallback, scryptParams, networkParams) {
  encryptRawAsync(buffer, compressed, passphrase, (out) => {
    var result = bs58check.encode(out)
    progressCallback(result)
  }, scryptParams, networkParams)
}

// some of the techniques borrowed from: https://github.com/pointbiz/bitaddress.org
function decryptRawAsync (buffer, passphrase, progressCallback, scryptParams, networkParams) {
  // 39 bytes: 2 bytes prefix, 37 bytes payload
  if (buffer.length !== 39) throw new Error('Invalid BIP38 data length')
  if (buffer.readUInt8(0) !== 0x01) throw new Error('Invalid BIP38 prefix')
  scryptParams = scryptParams || SCRYPT_PARAMS
  networkParams = networkParams || NETWORK_PARAMS

  // check if BIP38 EC multiply
  var type = buffer.readUInt8(1)
  if (type === 0x43) return decryptECMultAsync(buffer, passphrase, progressCallback, scryptParams)
  if (type !== 0x42) throw new Error('Invalid BIP38 type')

  passphrase = Buffer.from(passphrase, 'utf8')

  var flagByte = buffer.readUInt8(2)
  var compressed = flagByte === 0xe0
  if (!compressed && flagByte !== 0xc0) throw new Error('Invalid BIP38 compression flag')

  var salt = buffer.slice(3, 7)

  var scryptOptions = {
    N: scryptParams.N,
    r: scryptParams.r,
    p: scryptParams.p,
    dkLen: 64
  }

  scryptAsync(passphrase, salt, scryptOptions, (out) => {
    var buff = Buffer.from(out)
    var derivedHalf1 = buff.slice(0, 32)
    var derivedHalf2 = buff.slice(32, 64)
    var privKeyBuf = buffer.slice(7, 7 + 32)
    var decipher = aes.createDecipheriv('aes-256-ecb', derivedHalf2, NULL)
    decipher.setAutoPadding(false)
    decipher.end(privKeyBuf)

    var plainText = decipher.read()
    var privateKey = xor(derivedHalf1, plainText)

    // verify salt matches address
    var d = BigInteger.fromBuffer(privateKey)
    var address = getAddress(d, compressed, networkParams)
    var checksum = hash256(address).slice(0, 4)
    assert.deepStrictEqual(salt, checksum)

    var ret = {
      privateKey: privateKey,
      compressed: compressed
    }

    progressCallback(ret)
  })
}

function decryptAsync (string, passphrase, progressCallback, scryptParams, networkParams) {
  return decryptRawAsync(bs58check.decode(string), passphrase, progressCallback, scryptParams, networkParams)
}

function decryptECMultAsync (buffer, passphrase, progressCallback, scryptParams) {
  passphrase = Buffer.from(passphrase, 'utf8')
  buffer = buffer.slice(1) // FIXME: we can avoid this
  scryptParams = scryptParams || SCRYPT_PARAMS

  var flag = buffer.readUInt8(1)
  var compressed = (flag & 0x20) !== 0
  var hasLotSeq = (flag & 0x04) !== 0

  assert.strictEqual((flag & 0x24), flag, 'Invalid private key.')

  var addressHash = buffer.slice(2, 6)
  var ownerEntropy = buffer.slice(6, 14)
  var ownerSalt

  // 4 bytes ownerSalt if 4 bytes lot/sequence
  if (hasLotSeq) {
    ownerSalt = ownerEntropy.slice(0, 4)

  // else, 8 bytes ownerSalt
  } else {
    ownerSalt = ownerEntropy
  }

  var encryptedPart1 = buffer.slice(14, 22) // First 8 bytes
  var encryptedPart2 = buffer.slice(22, 38) // 16 bytes

  var scryptOptions = {
    N: scryptParams.N,
    r: scryptParams.r,
    p: scryptParams.p,
    dkLen: 32
  }

  scryptAsync(passphrase, ownerSalt, scryptOptions, (out) => {
    var preFactor = Buffer.from(out)

    var passFactor
    if (hasLotSeq) {
      var hashTarget = Buffer.concat([preFactor, ownerEntropy])
      passFactor = hash256(hashTarget)
    } else {
      passFactor = preFactor
    }

    var passInt = BigInteger.fromBuffer(passFactor)
    var passPoint = curve.G.multiply(passInt).getEncoded(true)

    var scryptOptionsBPass = {
      N: 1024,
      r: 1,
      p: 1,
      dkLen: 64
    }

    scryptAsync(passPoint, Buffer.concat([addressHash, ownerEntropy]), scryptOptionsBPass, (out) => {
      var seedBPass = Buffer.from(out)

      var derivedHalf1 = seedBPass.slice(0, 32)
      var derivedHalf2 = seedBPass.slice(32, 64)

      var decipher = aes.createDecipheriv('aes-256-ecb', derivedHalf2, Buffer.alloc(0))
      decipher.setAutoPadding(false)
      decipher.end(encryptedPart2)

      var decryptedPart2 = decipher.read()
      var tmp = xor(decryptedPart2, derivedHalf1.slice(16, 32))
      var seedBPart2 = tmp.slice(8, 16)

      var decipher2 = aes.createDecipheriv('aes-256-ecb', derivedHalf2, Buffer.alloc(0))
      decipher2.setAutoPadding(false)
      decipher2.write(encryptedPart1) // first 8 bytes
      decipher2.end(tmp.slice(0, 8)) // last 8 bytes

      var seedBPart1 = xor(decipher2.read(), derivedHalf1.slice(0, 16))
      var seedB = Buffer.concat([seedBPart1, seedBPart2], 24)
      var factorB = BigInteger.fromBuffer(hash256(seedB))

      // d = passFactor * factorB (mod n)
      var d = passInt.multiply(factorB).mod(curve.n)

      var result = {
        privateKey: d.toBuffer(32),
        compressed: compressed
      }

      progressCallback(result)
    })
  })
}

function verify (string) {
  var decoded = bs58check.decodeUnsafe(string)
  if (!decoded) return false

  if (decoded.length !== 39) return false
  if (decoded.readUInt8(0) !== 0x01) return false

  var type = decoded.readUInt8(1)
  var flag = decoded.readUInt8(2)

  // encrypted WIF
  if (type === 0x42) {
    if (flag !== 0xc0 && flag !== 0xe0) return false

  // EC mult
  } else if (type === 0x43) {
    if ((flag & ~0x24)) return false
  } else {
    return false
  }

  return true
}

module.exports = {
  decryptAsync: decryptAsync,
  decryptRawAsync: decryptRawAsync,
  decryptECMultAsync: decryptECMultAsync,
  encryptAsync: encryptAsync,
  encryptRawAsync: encryptRawAsync,
  verify: verify
}
