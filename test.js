const utils = require('./')
const Amorph = require('amorph')
const EccKeypair = require('ecc-keypair')
const IvError = require('./errors/Iv')

describe('safecomm utils', () => {

  const message = new Amorph('hello world!', 'ascii')
  const multiaddress = new Amorph('047f0000011104d2', 'hex')
  let threadKey
  let alice
  let bob
  let charlie
  let bilateralKeyAliceBob
  let bilateralKeyAliceCharlie
  let bilateralKeyBobAlice
  let bilateralKeyCharlieAlice
  let encapsulatedThreadKey
  let multiaddressIv
  let messageIv

  it('random should generate correctly', () => {
    utils.random(4).should.be.instanceof(Amorph)
    utils.random(8).to('array').should.have.length(8)
  })

  it('should generate group key', () => {
    threadKey = utils.random(16)
  })

  it('should create keypairs', () => {
    alice = EccKeypair.generate()
    bob = EccKeypair.generate()
    charlie = EccKeypair.generate()
  })

  it('should encrypt and decrypt (padded)', () => {
    const tempMessage = utils.random(32)
    const tempIv = utils.random(16)
    const ciphertext = utils.encrypt(tempMessage, threadKey, tempIv, true)
    utils.decrypt(ciphertext, threadKey, tempIv, true).should.amorphEqual(tempMessage)
  })

  it('should encrypt and decrypt (unpadded)', () => {
    const tempMessage = utils.random(32)
    const tempIv = utils.random(16)
    const ciphertext = utils.encrypt(tempMessage, threadKey, tempIv, false)
    utils.decrypt(ciphertext, threadKey, tempIv, false).should.amorphEqual(tempMessage)
  })

  it('encrypt should throw IVError with wrong-sized IV', () => {
    (() => {
      utils.encrypt(message, threadKey, utils.random(0), true)
    }).should.throw(IvError);
    (() => {
      utils.encrypt(message, threadKey, utils.random(32), true)
    }).should.throw(IvError)
  })

  it('should get bilateral keys', () => {
    bilateralKeyAliceBob = utils.getBilateralKey(alice.privateKey, bob.publicKey)
    bilateralKeyAliceCharlie = utils.getBilateralKey(alice.privateKey, charlie.publicKey)
    bilateralKeyBobAlice = utils.getBilateralKey(bob.privateKey, alice.publicKey)
    bilateralKeyCharlieAlice = utils.getBilateralKey(charlie.privateKey, alice.publicKey)
  })

  it('bilateralKeys should be mirrors', () => {
    bilateralKeyAliceBob.should.amorphEqual(bilateralKeyBobAlice)
    bilateralKeyAliceCharlie.should.amorphEqual(bilateralKeyCharlieAlice)
  })

  it('should encapsulate thread key', () => {
    encapsulatedThreadKey = utils.encapsulate(threadKey, bilateralKeyAliceBob, false)
  })

  it('encapsulatedThreadKey should have length 32', () => {
    encapsulatedThreadKey.to('array').should.have.length(32)
  })

  it('should be able to unenecapsulate encapsulatedThreadKey to threadKey', () => {
    utils.unencapsulate(encapsulatedThreadKey, bilateralKeyBobAlice, false).should.amorphEqual(threadKey)
  })

})
