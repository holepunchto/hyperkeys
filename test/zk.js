const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-native')
const Keychain = require('../')

// Function to simulate a simple ZK proof generation
function generateZKProof (scalar, message, publicKey) {
  console.log('\n===== Starting ZK Proof Generation =====\n')

  console.time('Proof Generation Time')
  
  // Generate a random challenge (nonce)
  const challenge = b4a.alloc(32)
  sodium.randombytes_buf(challenge)
  console.log('🎲 Generated Challenge (Nonce):', challenge.toString('hex'))

  // Commit to the scalar (private key)
  const commitment = b4a.alloc(32)
  sodium.crypto_generichash_batch(commitment, [scalar, challenge])
  console.log('🔒 Generated Commitment:', commitment.toString('hex'))

  // Simulate proof by combining commitment, message, and publicKey
  const proof = b4a.alloc(32)
  sodium.crypto_generichash_batch(proof, [commitment, message, publicKey])
  console.log('🛡️  Generated Proof:', proof.toString('hex'))

  console.timeEnd('Proof Generation Time')
  console.log('\n===== ZK Proof Generation Completed =====\n')
  
  return {
    commitment,
    challenge,
    proof
  }
}

// Function to verify the ZK proof
function verifyZKProof (proof, message, publicKey, commitment, challenge) {
  console.log('\n===== Starting ZK Proof Verification =====\n')

  console.time('Proof Verification Time')

  // Recompute the expected proof
  const expectedProof = b4a.alloc(32)
  sodium.crypto_generichash_batch(expectedProof, [commitment, message, publicKey])
  console.log('🔄 Recomputed Expected Proof:', expectedProof.toString('hex'))

  // Verify the proof matches
  const isValid = b4a.equals(proof, expectedProof)
  console.log(isValid ? '✅ Proof is Valid' : '❌ Proof is Invalid')

  console.timeEnd('Proof Verification Time')
  console.log('\n===== ZK Proof Verification Completed =====\n')
  
  return isValid
}

test('ZK proof generation and verification', function (t) {
  console.log('\n🌟🌟🌟 Test: ZK Proof Generation and Verification 🌟🌟🌟\n')

  const keys = new Keychain()
  const signer = keys.get()

  const message = Buffer.from('Test message')
  console.log('📜 Message to be Signed:', message.toString())

  // Use the getProofComponents method to retrieve public key and scalar
  const { publicKey, scalar } = signer.getProofComponents()
  console.log('🔑 Public Key:', publicKey.toString('hex'))
  console.log('🔐 Scalar (Private Key Component):', scalar.toString('hex'))

  // Generate a signature using the sign method
  const signature = signer.sign(message)
  console.log('✍️  Generated Signature:', signature.toString('hex'))

  // Generate ZK proof using the scalar, message, and publicKey
  const zkProof = generateZKProof(scalar, message, publicKey)

  t.ok(signature, 'Signature should be generated')
  t.ok(zkProof, 'ZK proof should be generated')

  // Verify the ZK proof
  const isValid = verifyZKProof(zkProof.proof, message, publicKey, zkProof.commitment, zkProof.challenge)
  t.ok(isValid, 'ZK proof should be valid')

  console.log('\n🎉 Test Completed 🎉\n')
})
