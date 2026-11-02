import type { SignedPackage, VerificationResult } from './packageTypes'
import { digestDocument, importPublicKey, verifyDigest } from '../crypto/signing'
import { crc32 } from '../integrity/crc32'
import { stableJson } from '../crypto/encoding'

export async function verifyPackage(
  packageData: SignedPackage,
  receivedDocument: string,
  receivedPublicKeyText: string,
): Promise<VerificationResult> {
  let publicKey: JsonWebKey
  try {
    publicKey = JSON.parse(receivedPublicKeyText) as JsonWebKey
  } catch {
    return {
      signatureValid: false,
      documentCrcMatches: false,
      publicKeyCrcMatches: false,
      diagnosis: 'Verification stopped: the received public key is not valid JSON.',
      error: 'Malformed public key JSON',
    }
  }

  const documentCrcMatches = crc32(receivedDocument) === packageData.documentCrc
  const publicKeyCrcMatches = crc32(stableJson(publicKey)) === packageData.publicKeyCrc
  try {
    const { bytes } = await digestDocument(receivedDocument)
    const signatureValid = await verifyDigest(await importPublicKey(publicKey), bytes, packageData.signature)
    let diagnosis = 'Authentic and intact: the signature is valid and both CRCs match.'
    if (!signatureValid) {
      diagnosis = !documentCrcMatches && !publicKeyCrcMatches
        ? 'Both the document and public key changed. The signature correctly rejects the package.'
        : !documentCrcMatches
          ? 'The document changed. Its CRC mismatch and invalid signature expose the tampering.'
          : !publicKeyCrcMatches
            ? 'The public key changed. Its CRC mismatch and invalid signature expose the tampering.'
            : 'Both CRCs match, but the signature is invalid: it may be corrupted or forged.'
    }
    return { signatureValid, documentCrcMatches, publicKeyCrcMatches, diagnosis }
  } catch {
    return {
      signatureValid: false,
      documentCrcMatches,
      publicKeyCrcMatches,
      diagnosis: 'Verification stopped: the received public key cannot be imported.',
      error: 'Invalid RSA public key',
    }
  }
}
