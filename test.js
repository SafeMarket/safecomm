const utils = require('./')
const CouldNotDecryptError = require('./errors/CouldNotDecrypt')
const TypeByteError = require('./errors/TypeByte')
const MessageTooLongError = require('./errors/MessageTooLong')
const Amorph = require('amorph')
const EccKeypair = require('ecc-keypair')
const crypto = require('crypto')
const chai = require('chai')
const chaiAmorph = require('chai-amorph')
const keccak256 = require('keccak256-amorph')

chai.use(chaiAmorph)
chai.should()

function random(bytes) {
  return new Amorph(crypto.randomBytes(bytes), 'buffer')
}

describe('safecomm utils', () => {

  const threadKey = random(16)
  const threadIv = random(16)
  const message = new Amorph('hello world!', 'ascii')
  const messageNonce = random(16)
  const messageIv = random(16)
  const noncedThreadKeyHash = keccak256(threadKey.as('array', (array) => {
    return array.concat(messageNonce.to('array'))
  }))
  const alice = EccKeypair.generate()
  const bob = EccKeypair.generate()
  const charlie = EccKeypair.generate()
  let bilateralKeyAliceBob
  let bilateralKeyAliceCharlie
  let bilateralKeyBobAlice
  let bilateralKeyCharlieAlice

  it('should get bilateral keys', () => {
    bilateralKeyAliceBob = utils.deriveBilateralKey(alice.privateKey, bob.publicKey)
    bilateralKeyAliceCharlie = utils.deriveBilateralKey(alice.privateKey, charlie.publicKey)
    bilateralKeyBobAlice = utils.deriveBilateralKey(bob.privateKey, alice.publicKey)
    bilateralKeyCharlieAlice = utils.deriveBilateralKey(charlie.privateKey, alice.publicKey)
  })

  it('bilateralKeys should be mirrors', () => {
    bilateralKeyAliceBob.should.amorphEqual(bilateralKeyBobAlice)
    bilateralKeyAliceCharlie.should.amorphEqual(bilateralKeyCharlieAlice)
  })

  it('should marshal new threadDocument', () => {
    threadDocument = utils.marshalThreadDocument(
      threadKey,
      threadIv,
      alice.privateKey,
      alice.publicKeyCompressed,
      bob.publicKeyCompressed
    )
  })

  it('should correctly unmarsal threadDocument', () => {
    unmarshalledThreadDocument = utils.unmarshalDocument(threadDocument)
    unmarshalledThreadDocument.should.have.keys(['type', 'publicKey', 'iv', 'ciphertext'])
    unmarshalledThreadDocument.type.should.equal('thread')
    unmarshalledThreadDocument.publicKey.should.amorphEqual(alice.publicKeyCompressed)
    unmarshalledThreadDocument.iv.should.amorphEqual(threadIv)
  })

  it('bob should be able to decrypt ciphertext', () => {
    utils.decryptThreadDocumentCiphertext(
      unmarshalledThreadDocument.ciphertext,
      bob.privateKey,
      unmarshalledThreadDocument.publicKey,
      unmarshalledThreadDocument.iv
    ).should.amorphEqual(threadKey)
  })

  it('charlie should NOT be able to decrypt ciphertext', () => {
    ;(() => {utils.decryptThreadDocumentCiphertext(
      unmarshalledThreadDocument.ciphertext,
      charlie.privateKey,
      unmarshalledThreadDocument.publicKey,
      unmarshalledThreadDocument.iv
    )}).should.throw(CouldNotDecryptError)
  })

  it('should be able to unmarshal messageDocument', () => {
    messageDocument = utils.marshalMessageDocument(message, messageNonce, threadKey, messageIv)
  })

  it('should correctly unmarsal messageDocument', () => {
    unmarshalledMessageDocument = utils.unmarshalDocument(messageDocument)
    unmarshalledMessageDocument.should.have.keys(['type', 'nonce', 'noncedThreadKeyHash', 'iv', 'ciphertext'])
    unmarshalledMessageDocument.type.should.equal('message')
    unmarshalledMessageDocument.nonce.should.amorphEqual(messageNonce)
    unmarshalledMessageDocument.noncedThreadKeyHash.should.amorphEqual(noncedThreadKeyHash)
    unmarshalledMessageDocument.iv.should.amorphEqual(messageIv)
  })

  it('testThreadKey should return true for right threadKey', () => {
    utils.testThreadKey(
      threadKey,
      unmarshalledMessageDocument.nonce,
      unmarshalledMessageDocument.noncedThreadKeyHash
    ).should.equal(true)
  })

  it('testThreadKey should return false for a random threadKey', () => {
    utils.testThreadKey(
      random(16),
      unmarshalledMessageDocument.nonce,
      unmarshalledMessageDocument.noncedThreadKeyHash
    ).should.equal(false)
  })

  it('should be able to decrypt ciphertext with threadKey', () => {
    utils.decryptMessageDocumentCiphertext(
      unmarshalledMessageDocument.ciphertext,
      threadKey,
      unmarshalledMessageDocument.iv
    ).should.amorphEqual(message)
  })

  describe('edgecase message lengths:', () => {
    [
      [0, 256],
      [1, 256],
      [253, 256],
      [254, 256],
      [255, 256 * 2],
      [256, 256 * 2],
      [utils.maxMessageLength - 1, 256 * 256],
      [utils.maxMessageLength, 256 * 256]
    ].forEach((args) => {
      const messageLength = args[0]
      const expectedCiphertextLength = args[1]
      it(`${messageLength} bytes`, () => {
        const message = random(messageLength)
        const nonce = random(16)
        const threadKey = random(16)
        const iv = random(16)
        const messageDocument = utils.marshalMessageDocument(message, nonce, threadKey, iv)
        const unmarshalledMessageDocument = utils.unmarshalDocument(messageDocument)
        unmarshalledMessageDocument.nonce.should.amorphEqual(nonce)
        unmarshalledMessageDocument.iv.should.amorphEqual(iv)
        unmarshalledMessageDocument.ciphertext.to('array').should.have.length(expectedCiphertextLength)
        utils.decryptMessageDocumentCiphertext(
          unmarshalledMessageDocument.ciphertext,
          threadKey,
          iv
        ).should.amorphEqual(message)
      })
    })
  })

  describe('errors', () => {
    it('should trigger TypeByte error when unmarshalling unkown TypeByte', () => {
      ;(() => {
        utils.unmarshalDocument(random(100).as('array', (array) => {
          return [1].concat(array)
        }))
      }).should.throw(TypeByteError)
    })
    it('should trigger MessageTooLongError error when message > maxMessageLength', () => {
      const nonce = random(16)
      const threadKey = random(16)
      const iv = random(16)
      utils.marshalMessageDocument(random(utils.maxMessageLength), nonce, threadKey, iv)
      ;(() => {
        utils.marshalMessageDocument(random(utils.maxMessageLength + 1), nonce, threadKey, iv)
      }).should.throw(MessageTooLongError)
    })
  })
})
