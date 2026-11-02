export function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary)
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(new ArrayBuffer(binary.length))
  binary.split('').forEach((character, index) => {
    bytes[index] = character.charCodeAt(0)
  })
  return bytes
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function stableJson(value: JsonWebKey): string {
  return JSON.stringify({
    alg: value.alg,
    e: value.e,
    ext: value.ext,
    key_ops: value.key_ops,
    kty: value.kty,
    n: value.n,
  })
}
