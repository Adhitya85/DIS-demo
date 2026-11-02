export type SignedPackage = {
  document: string
  fileName?: string
  mimeType?: string
  fileSize?: number
  payloadBase64?: string
  signature: string
  publicKey: JsonWebKey
  documentCrc: string
  publicKeyCrc: string
  digest: string
}

export type VerificationResult = {
  signatureValid: boolean
  documentCrcMatches: boolean
  publicKeyCrcMatches: boolean
  diagnosis: string
  error?: string
}
