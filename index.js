const arguguard = require('arguguard')
const Amorph = require('amorph')
const EC = require('elliptic').ec
const rlp = require('rlp')
const BytesLengthError = require('./errors/BytesLength')
const TypeByteError = require('./errors/TypeByte')
const MessageTooLongError = require('./errors/MessageTooLong')
const CouldNotDecryptError = require('./errors/CouldNotDecrypt')
const amorphBufferPlugin = require('amorph-buffer')
const aes = require('aes-128-cbc-amorph')
const keccak256 = require('keccak256-amorph')

Amorph.loadPlugin(amorphBufferPlugin)
Amorph.ready()

const ec = new EC('secp256k1')

const typeBytes = {
  'thread': 0x00,
  'message': 0x10
}

const types = {
  0x00: 'thread',
  0x10: 'message'
}

const maxMessageLength = Math.pow(2, 16) - 1 - 2

function checkLength(amorph, expectedLength) {
  const length = amorph.to('array').length
  if (length !== expectedLength) {
    throw new BytesLengthError(`Expected ${expectedLength} bytes, received ${length}`)
  }
}

function deriveBilateralKey(privateKey, publicKey) {
  arguguard('getBilateralKey', [Amorph, Amorph], arguments)
  const derived = privateKey.as('buffer', (privateKeyBuffer) => {
    const ecKeypair = ec.keyFromPrivate(privateKeyBuffer)
    const ecPublicKey = ec.keyFromPublic(publicKey.to('buffer')).getPublic()
    const derived = ecKeypair.derive(ecPublicKey)
    return derived.toBuffer()
  })

  return keccak256(derived).as('array', (bilateralKeyArray) => {
    return bilateralKeyArray.slice(16)
  })
}

function marshalThreadDocument(threadKey, iv, myPrivateKey, myPublicKey, recipientPublicKey) {
  arguguard('marshalThreadDocument', [Amorph, Amorph, Amorph, Amorph, Amorph], arguments)
  checkLength(threadKey, 16)
  checkLength(iv, 16)
  checkLength(myPrivateKey, 32)
  checkLength(myPublicKey, 33)
  checkLength(recipientPublicKey, 33)
  const bilateralKey = deriveBilateralKey(myPrivateKey, recipientPublicKey)
  const threadKeyHash = keccak256(threadKey)
  const plaintextBuffer = Buffer.concat([
    threadKey.to('buffer'),
    threadKeyHash.to('buffer')
  ])
  const plaintext = new Amorph(plaintextBuffer, 'buffer')
  const ciphertext = aes.encrypt(plaintext, bilateralKey, iv)
  const threadDocumentBuffer = Buffer.concat([
    Buffer.from([typeBytes.thread]),
    myPublicKey.to('buffer'),
    iv.to('buffer'),
    ciphertext.to('buffer')
  ])
  return new Amorph(threadDocumentBuffer, 'buffer')
}

function marshalMessageDocument(message, nonce, threadKey, iv) {
  arguguard('marshalMessageDocument', [Amorph, Amorph, Amorph, Amorph], arguments)
  checkLength(nonce, 16)
  checkLength(threadKey, 16)
  checkLength(iv, 16)
  const noncedThreadKeyHash = keccak256(threadKey.as('array', (array) => {
    return array.concat(nonce.to('array'))
  }))
  const messageLength = message.to('array').length

  if (messageLength > maxMessageLength) {
    throw new MessageTooLongError(`Messages can be at most ${maxMessageLength} bytes, received ${messageLength}`)
  }

  // round up to nearest block of 256
  const plaintextLength = Math.ceil((messageLength + 2) / 256) * 256
  const paddedMessageLength = plaintextLength - 2
  const paddingLength = paddedMessageLength - messageLength
  const paddedMessage = message.as('array', (array) => {
    return array.concat(Array(paddingLength).fill(0))
  })

  const size = new Amorph([
    Math.floor(messageLength / 256),
    messageLength % 256
  ], 'array')

  const plaintext = new Amorph(Buffer.concat([
    size.to('buffer'),
    paddedMessage.to('buffer')
  ]), 'buffer')
  const ciphertext = aes.encrypt(plaintext, threadKey, iv)
  const messageDocumentBuffer = Buffer.concat([
    Buffer.from([typeBytes.message]),
    nonce.to('buffer'),
    noncedThreadKeyHash.to('buffer'),
    iv.to('buffer'),
    ciphertext.to('buffer')
  ])
  return new Amorph(messageDocumentBuffer, 'buffer')
}

function unmarshalDocument(document) {
  arguguard('unmarshalDocument', [Amorph], arguments)
  const typeByte = document.to('array')[0]
  const type = types[typeByte]

  if (type === 'thread') {
    return unmarshalThreadDocument(document)
  }

  if (type === 'message') {
    return unmarshalMessageDocument(document)
  }

  throw new TypeByteError(`Unknown type byte ${typeByte}`)
}

function unmarshalThreadDocument(threadDocument) {
  arguguard('unmarshalThreadDocument', [Amorph], arguments)
  checkLength(threadDocument, 98)
  return {
    type: 'thread',
    publicKey: threadDocument.as('array', (array) => {
      return array.slice(1, 34)
    }),
    iv: threadDocument.as('array', (array) => {
      return array.slice(34, 50)
    }),
    ciphertext: threadDocument.as('array', (array) => {
      return array.slice(50, 98)
    })
  }
}

function decryptThreadDocumentCiphertext(ciphertext, privateKey, publicKey, iv) {
  arguguard('decryptThreadDocumentCiphertext', [Amorph, Amorph, Amorph, Amorph], arguments)
  const bilateralKey = deriveBilateralKey(privateKey, publicKey)
  const plaintext = aes.decrypt(ciphertext, bilateralKey, iv)
  const threadKey = plaintext.as('array', (array) => {
    return array.slice(0, 16)
  })
  const threadKeyHash = plaintext.as('array', (array) => {
    return array.slice(16, 48)
  })
  if (!keccak256(threadKey).equals(threadKeyHash)) {
    throw new CouldNotDecryptError('Could not decrypt thread document')
  }
  return threadKey
}

function unmarshalMessageDocument(messageDocument) {
  arguguard('unmarshalMessageDocument', [Amorph], arguments)
  return {
    type: 'message',
    nonce: messageDocument.as('array', (array) => {
      return array.slice(1, 17)
    }),
    noncedThreadKeyHash: messageDocument.as('array', (array) => {
      return array.slice(17, 49)
    }),
    iv: messageDocument.as('array', (array) => {
      return array.slice(49, 65)
    }),
    ciphertext: messageDocument.as('array', (array) => {
      return array.slice(65)
    })
  }
}

function decryptMessageDocumentCiphertext(ciphertext, threadKey, iv) {
  arguguard('decryptMessageDocumentCiphertext', [Amorph, Amorph, Amorph], arguments)
  const plaintext = aes.decrypt(ciphertext, threadKey, iv)
  const sizeArray = plaintext.to('array').slice(0, 2)
  const messageLength = (sizeArray[0] * 256) + sizeArray[1]
  return plaintext.as('array', (array) => {
    return array.slice(2, 2 + messageLength)
  })
}

function testThreadKey(threadKey, nonce, noncedThreadKeyHash) {
  arguguard('arguguard', [Amorph, Amorph, Amorph], arguments)
  checkLength(threadKey, 16)
  checkLength(nonce, 16)
  checkLength(noncedThreadKeyHash, 32)
  return keccak256(threadKey.as('array', (array) => {
    return array.concat(nonce.to('array'))
  })).equals(noncedThreadKeyHash)
}

module.exports = {
  types,
  maxMessageLength,
  marshalThreadDocument,
  marshalMessageDocument,
  unmarshalDocument,
  unmarshalThreadDocument,
  decryptThreadDocumentCiphertext,
  decryptMessageDocumentCiphertext,
  deriveBilateralKey,
  testThreadKey
}
