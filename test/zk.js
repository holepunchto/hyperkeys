const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-native')
const Keychain = require('../')

// Function to generate a real ZK proof using Schnorr protocol
function generateZKSchnorrProof(scalar, publicKey) {
  console.log('\n===== Starting ZK Schnorr Proof Generation =====\n')

  console.time('Proof Generation Time')

  // Step 1: Generate a random nonce (r)
  const r = b4a.alloc(32)
  sodium.randombytes_buf(r)
  console.log('🎲 Generated Random Nonce (r):', r.toString('hex'))

  // Step 2: Compute R = r * G (where G is the base point, in this case, the Ed25519 base point)
  const R = b4a.alloc(32)
  sodium.crypto_scalarmult_ed25519_base_noclamp(R, r)
  console.log('📍 Computed R (R = r * G):', R.toString('hex'))

  // Step 3: Compute challenge c = H(R || publicKey)
  const c = b4a.alloc(32)
  const hashInput = b4a.concat([R, publicKey])
  sodium.crypto_generichash(c, hashInput)
  console.log('🔑 Computed Challenge (c = H(R || publicKey)):', c.toString('hex'))

  // Step 4: Compute response s = r + c * scalar
  const s = b4a.alloc(32)
  const temp = b4a.alloc(32)
  sodium.crypto_core_ed25519_scalar_mul(temp, c, scalar)  // c * scalar
  sodium.crypto_core_ed25519_scalar_add(s, r, temp)      // s = r + c * scalar
  console.log('🔐 Computed Response (s = r + c * scalar):', s.toString('hex'))

  console.timeEnd('Proof Generation Time')
  console.log('\n===== ZK Schnorr Proof Generation Completed =====\n')

  return { R, s, publicKey }
}

// Function to verify the ZK proof using Schnorr protocol
function verifyZKSchnorrProof(proof) {
  console.log('\n===== Starting ZK Schnorr Proof Verification =====\n')

  console.time('Proof Verification Time')

  const { R, s, publicKey } = proof

  // Step 1: Recompute the challenge c = H(R || publicKey)
  const c = b4a.alloc(32)
  const hashInput = b4a.concat([R, publicKey])
  sodium.crypto_generichash(c, hashInput)
  console.log('🔄 Recomputed Challenge (c = H(R || publicKey)):', c.toString('hex'))

  // Step 2: Verify that s * G = R + c * publicKey
  const sG = b4a.alloc(32)
  const cPK = b4a.alloc(32)
  const rPlusCpk = b4a.alloc(32)  // Updated to follow camelCase

  sodium.crypto_scalarmult_ed25519_base_noclamp(sG, s)       // s * G
  sodium.crypto_scalarmult_ed25519_noclamp(cPK, c, publicKey) // c * publicKey
  sodium.crypto_core_ed25519_add(rPlusCpk, R, cPK)         // R + c * publicKey

  const isValid = b4a.equals(sG, rPlusCpk)
  console.log(isValid ? '✅ Proof is Valid' : '❌ Proof is Invalid')

  console.timeEnd('Proof Verification Time')
  console.log('\n===== ZK Schnorr Proof Verification Completed =====\n')

  return isValid
}

test('ZK Schnorr proof generation and verification', function (t) {
  console.log('\n🌟🌟🌟 Test: ZK Schnorr Proof Generation and Verification 🌟🌟🌟\n')

  const keys = new Keychain()
  const signer = keys.get()

  // Use the getProofComponents method to retrieve public key and scalar
  const { publicKey, scalar } = signer.getProofComponents()
  console.log('🔑 Public Key:', publicKey.toString('hex'))
  console.log('🔐 Scalar (Private Key Component):', scalar.toString('hex'))

  // Generate ZK proof using the Schnorr protocol
  const zkProof = generateZKSchnorrProof(scalar, publicKey)

  t.ok(zkProof, 'ZK Schnorr proof should be generated')

  // Verify the ZK proof
  const isValid = verifyZKSchnorrProof(zkProof)
  t.ok(isValid, 'ZK Schnorr proof should be valid')

  console.log('\n🎉 Test Completed 🎉\n')
})
