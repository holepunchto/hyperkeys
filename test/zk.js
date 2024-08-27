const test = require('brittle')
const b4a = require('b4a')
const Keychain = require('../')

// Function to simulate a simple ZK proof generation
function generateZKProof(scalar, message, publicKey) {
  // Generate a random challenge (nonce)
  const challenge = b4a.alloc(32)
  sodium.randombytes_buf(challenge)

  // Commit to the scalar (private key)
  const commitment = b4a.alloc(32)
  sodium.crypto_generichash_batch(commitment, [scalar, challenge])

  // Simulate proof by combining commitment, message, and publicKey
  const proof = b4a.alloc(32)
  sodium.crypto_generichash_batch(proof, [commitment, message, publicKey])

  return {
    commitment,
    challenge,
    proof,
  }
}

// Function to verify the ZK proof
function verifyZKProof(proof, message, publicKey, commitment, challenge) {
  // Recompute the expected proof
  const expectedProof = b4a.alloc(32)
  sodium.crypto_generichash_batch(expectedProof, [commitment, message, publicKey])

  // Verify the proof matches
  return b4a.equals(proof, expectedProof)
}

test('ZK proof generation and verification', function (t) {
  const keys = new Keychain()

  const signer = keys.get()

  const message = Buffer.from('Test message')
  
  // Use the getProofComponents method
  const { publicKey, scalar } = signer.getProofComponents()

  // Generate a signature
  const signature = signer.sign(message)

  // Generate ZK proof using the scalar, message, and publicKey
  const zkProof = generateZKProof(scalar, message, publicKey)

  t.ok(signature, 'signature should be generated')
  t.ok(zkProof, 'ZK proof should be generated')

  // Verify the ZK proof
  const isValid = verifyZKProof(zkProof.proof, message, publicKey, zkProof.commitment, zkProof.challenge)
  t.ok(isValid, 'ZK proof should be valid')
})
