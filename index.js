const secp = require('secp256k1-native')
const sodium = require('sodium-universal')
const assert = require('nanoassert')

const DHLEN = secp.secp256k1_SECKEYBYTES
const PKLEN = secp.secp256k1_PUBKEYBYTES
const SKLEN = secp.secp256k1_SECKEYBYTES
const ALG = 'secp256k1'

module.exports = {
  DHLEN,
  PKLEN,
  SKLEN,
  ALG,
  name: ALG,
  generateKeypair,
  dh
}

function generateKeypair (privKey) {
  const ctx = secp.secp256k1_context_create(secp.secp256k1_context_SIGN)

  if (privKey) assert(secp.secp256k1_ec_seckey_verify(ctx, privKey))

  const keyPair = {}
  keyPair.secretKey = privKey || Buffer.alloc(SKLEN)
  keyPair.publicKey = Buffer.alloc(PKLEN)

  while (!secp.secp256k1_ec_seckey_verify(ctx, keyPair.secretKey)) {
    sodium.randombytes_buf(keyPair.secretKey)
  }
  secp.secp256k1_ec_pubkey_create(ctx, keyPair.publicKey, keyPair.secretKey)

  return keyPair
}

function dh (pk, lsk) {
  assert(lsk.byteLength === SKLEN)
  assert(pk.byteLength === PKLEN)

  const ctx = secp.secp256k1_context_create(secp.secp256k1_context_SIGN)

  const output = Buffer.alloc(DHLEN)

  secp.secp256k1_ecdh(
    ctx,
    output,
    pk,
    lsk,
    Buffer.alloc(0)
  )

  return output
}
