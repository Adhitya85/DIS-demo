import { base64ToBytes, bytesToBase64, bytesToHex } from './encoding'

const algorithm = { name: 'RSA-PSS', saltLength: 32 } as const

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  ) as Promise<CryptoKeyPair>
}

export async function digestBytes(bytes: Uint8Array): Promise<{ bytes: Uint8Array; hex: string }> {
  const safeBytes = new Uint8Array(new ArrayBuffer(bytes.byteLength))
  safeBytes.set(bytes)
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', safeBytes))
  return { bytes: digest, hex: bytesToHex(digest) }
}

export async function digestDocument(document: string): Promise<{ bytes: Uint8Array; hex: string }> {
  return digestBytes(new TextEncoder().encode(document))
}

export async function signDigest(privateKey: CryptoKey, digest: Uint8Array): Promise<string> {
  const safeDigest = new Uint8Array(new ArrayBuffer(digest.byteLength))
  safeDigest.set(digest)
  const signature = await crypto.subtle.sign(algorithm, privateKey, safeDigest)
  return bytesToBase64(new Uint8Array(signature))
}

export async function verifyDigest(publicKey: CryptoKey, digest: Uint8Array, signature: string): Promise<boolean> {
  const safeDigest = new Uint8Array(new ArrayBuffer(digest.byteLength))
  safeDigest.set(digest)
  const signatureBytes = base64ToBytes(signature)
  const safeSignature = new Uint8Array(new ArrayBuffer(signatureBytes.byteLength))
  safeSignature.set(signatureBytes)
  return crypto.subtle.verify(algorithm, publicKey, safeSignature, safeDigest)
}

export async function exportPublicKey(publicKey: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', publicKey)
}

export async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['verify'],
  )
}
