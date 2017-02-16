const arguguard = require('arguguard')
const Amorph = require('amorph')
const crypto = require('crypto')
const EC = require('elliptic').ec
const rlp = require('rlp')
const _keccak256 = require('js-sha3').keccak_256
const IVError = require('./errors/IV')
const amorphBufferPlugin = require('amorph-buffer')
const chai = require('chai')
const chaiAmorph = require('chai-amorph')

Amorph.loadPlugin(amorphBufferPlugin)
Amorph.ready()

chai.use(chaiAmorph)
chai.should()

const ec = new EC('secp256k1')

function hash(prehash) {
  arguguard('keccak256', [Amorph], arguments)
  return prehash.as('uint8Array', (uint8Array) => {
    return Amorph.crossConverter.convert(_keccak256(uint8Array), 'hex', 'uint8Array')
  })
}

function random(bytes) {
  arguguard('random', ['number'], arguments)
  return new Amorph(crypto.randomBytes(bytes), 'buffer')
}

function getBilateralKey(privateKey, publicKey) {
  arguguard('getBilateralKey', [Amorph, Amorph], arguments)
  const derived = privateKey.as('buffer', (privateKeyBuffer) => {
    const ecKeypair = ec.keyFromPrivate(privateKeyBuffer)
    const ecPublicKey = ec.keyFromPublic(publicKey.to('buffer')).getPublic()
    const derived = ecKeypair.derive(ecPublicKey)
    return derived.toBuffer()
  })

  return hash(derived).as('array', (bilateralKeyArray) => {
    return bilateralKeyArray.slice(16)
  })
}

function encrypt(plaintext, key, iv, isPadded) {
  arguguard('encrypt', [Amorph, Amorph, Amorph, 'boolean'], arguments)
  if (iv.to('array').length !== 16) {
    throw new IVError(`IV should be 16 bytes, received ${iv.to('array').length}`)
  }
  const cipher = crypto.createCipheriv('aes-128-cbc', key.to('buffer'), iv.to('buffer'))
  cipher.setAutoPadding(isPadded)
  const encryptedBuffer = Buffer.concat([
    cipher.update(plaintext.to('buffer'), 'buffer'),
    cipher.final('buffer')
  ])
  return new Amorph(encryptedBuffer, 'buffer')
}

function decrypt(ciphertext, key, iv, isPadded) {
  arguguard('decrypt', [Amorph, Amorph, Amorph, 'boolean'], arguments)
  const decipher = crypto.createDecipheriv('aes-128-cbc', key.to('buffer'), iv.to('buffer'))
  decipher.setAutoPadding(isPadded)
  const plaintextBuffer = Buffer.concat([
    decipher.update(ciphertext.to('buffer'), 'buffer'),
    decipher.final('buffer')
  ])
  return new Amorph(plaintextBuffer, 'buffer')
}

function encapsulate(plaintext, key, isPadded) {
  arguguard('encapsulate', [Amorph, Amorph, 'boolean'], arguments)
  const iv = random(16)
  const ciphertext = encrypt(plaintext, key, iv, isPadded)
  return new Amorph(iv.to('array').concat(ciphertext.to('array')), 'array')
}

function unencapsulate(encapsulated, key, isPadded) {
  arguguard('unencapsulate', [Amorph, Amorph, 'boolean'], arguments)

  const iv = encapsulated.as('array', (encapsulatedArray) => {
    return encapsulatedArray.slice(0, 16)
  })

  const ciphertext = encapsulated.as('array', (encapsulatedArray) => {
    return encapsulatedArray.slice(16)
  })

  return decrypt(ciphertext, key, iv, isPadded)
}


module.exports = {
  random,
  encrypt,
  decrypt,
  encapsulate,
  unencapsulate,
  getBilateralKey,
  hash
}
