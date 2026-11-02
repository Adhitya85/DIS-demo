import { useRef, useState } from 'react'
import './App.css'
import { exportPublicKey, generateKeyPair, digestBytes, signDigest } from './crypto/signing'
import { base64ToBytes, bytesToBase64, stableJson, stringToBytes } from './crypto/encoding'
import { crc32, crc32Bytes } from './integrity/crc32'
import type { SignedPackage, VerificationResult } from './domain/packageTypes'
import { verifyPackage } from './domain/verification'

const initialDocument = 'Quarterly access review — approved for distribution.'
const maxFileSize = 25 * 1024 * 1024

function App() {
  const [document, setDocument] = useState(initialDocument)
  const [documentBytes, setDocumentBytes] = useState<Uint8Array>(() => stringToBytes(initialDocument))
  const [fileName, setFileName] = useState('document.txt')
  const [mimeType, setMimeType] = useState('text/plain')
  const [keyPair, setKeyPair] = useState<CryptoKeyPair>()
  const [publicKey, setPublicKey] = useState<JsonWebKey>()
  const [signedPackage, setSignedPackage] = useState<SignedPackage>()
  const [receiverDocument, setReceiverDocument] = useState('')
  const [receiverKey, setReceiverKey] = useState('')
  const [receiverBytes, setReceiverBytes] = useState<Uint8Array>(() => stringToBytes(initialDocument))
  const [receiverFileName, setReceiverFileName] = useState('document.txt')
  const [receiverMimeType, setReceiverMimeType] = useState('text/plain')
  const [result, setResult] = useState<VerificationResult>()
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('Generate a key pair to begin.')
  const packageInput = useRef<HTMLInputElement>(null)
  const signerFileInput = useRef<HTMLInputElement>(null)
  const receiverFileInput = useRef<HTMLInputElement>(null)

  const readFile = async (file: File, receiver = false) => {
    if (file.size > maxFileSize) {
      setMessage('Files must be 25 MB or smaller for browser-based processing.')
      return
    }
    const bytes = new Uint8Array(await file.arrayBuffer())
    if (receiver) {
      setReceiverBytes(bytes)
      setReceiverFileName(file.name)
      setReceiverMimeType(file.type || 'application/octet-stream')
      setReceiverDocument(file.type.startsWith('text/') ? new TextDecoder().decode(bytes) : `[Binary file: ${file.name}]`)
    } else {
      setDocumentBytes(bytes)
      setFileName(file.name)
      setMimeType(file.type || 'application/octet-stream')
      setDocument(file.type.startsWith('text/') ? new TextDecoder().decode(bytes) : `[Binary file: ${file.name}]`)
    }
    setResult(undefined)
  }

  const createPackage = async () => {
    setBusy(true)
    setMessage('')
    try {
      const pair = keyPair ?? await generateKeyPair()
      const exported = publicKey ?? await exportPublicKey(pair.publicKey)
      const { bytes, hex } = await digestBytes(documentBytes)
      const serializedKey = stableJson(exported)
      const nextPackage: SignedPackage = {
        document,
        fileName,
        mimeType,
        fileSize: documentBytes.byteLength,
        payloadBase64: bytesToBase64(documentBytes),
        signature: await signDigest(pair.privateKey, bytes),
        publicKey: exported,
        documentCrc: crc32Bytes(documentBytes),
        publicKeyCrc: crc32(serializedKey),
        digest: hex,
      }
      setKeyPair(pair)
      setPublicKey(exported)
      setSignedPackage(nextPackage)
      setReceiverDocument(document)
      setReceiverBytes(documentBytes)
      setReceiverFileName(fileName)
      setReceiverMimeType(mimeType)
      setReceiverKey(JSON.stringify(exported, null, 2))
      setResult(undefined)
      setMessage('Package created. The private key remains in signer memory and is not included.')
    } catch {
      setMessage('Unable to create the package in this browser.')
    } finally {
      setBusy(false)
    }
  }

  const verify = async () => {
    if (!signedPackage) return
    setBusy(true)
    setResult(await verifyPackage(signedPackage, receiverBytes, receiverKey))
    setBusy(false)
  }

  const downloadPackage = (packageToDownload: SignedPackage, filename: string, notice: string) => {
    const blob = new Blob([JSON.stringify(packageToDownload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = globalThis.document.createElement('a')
    link.href = url
    link.download = filename
    link.click()
    URL.revokeObjectURL(url)
    setMessage(notice)
  }

  const downloadCurrentPackage = () => {
    if (!signedPackage) return
    try {
      const currentPublicKey = JSON.parse(receiverKey) as JsonWebKey
      downloadPackage(
        {
          ...signedPackage,
          document: receiverDocument,
          fileName: receiverFileName,
          mimeType: receiverMimeType,
          fileSize: receiverBytes.byteLength,
          payloadBase64: bytesToBase64(receiverBytes),
          publicKey: currentPublicKey,
        },
        'signed-package-current.json',
        'Current package downloaded with the receiver values, including any injected changes.',
      )
    } catch {
      setMessage('The public key must contain valid JSON before downloading the package.')
    }
  }

  const downloadReceiverFile = () => {
    const safeBytes = new Uint8Array(new ArrayBuffer(receiverBytes.byteLength))
    safeBytes.set(receiverBytes)
    const blob = new Blob([safeBytes], { type: receiverMimeType || 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const link = globalThis.document.createElement('a')
    link.href = url
    link.download = receiverFileName || 'received-file'
    link.click()
    URL.revokeObjectURL(url)
    setMessage('Receiver file downloaded without the signed package wrapper.')
  }

  const importPackage = async (file: File) => {
    try {
      const imported = JSON.parse(await file.text()) as Partial<SignedPackage>
      if (
        typeof imported.document !== 'string' ||
        typeof imported.signature !== 'string' ||
        typeof imported.digest !== 'string' ||
        typeof imported.documentCrc !== 'string' ||
        typeof imported.publicKeyCrc !== 'string' ||
        !imported.publicKey ||
        typeof imported.publicKey !== 'object'
      ) {
        throw new Error('incomplete package')
      }
      const packageData = imported as SignedPackage
      setSignedPackage(packageData)
      setDocument(packageData.document)
      const importedBytes = packageData.payloadBase64 ? base64ToBytes(packageData.payloadBase64) : stringToBytes(packageData.document)
      setDocumentBytes(importedBytes)
      setFileName(packageData.fileName ?? 'document.txt')
      setMimeType(packageData.mimeType ?? 'text/plain')
      setPublicKey(packageData.publicKey)
      setReceiverDocument(packageData.document)
      setReceiverBytes(importedBytes)
      setReceiverFileName(packageData.fileName ?? 'document.txt')
      setReceiverMimeType(packageData.mimeType ?? 'text/plain')
      setReceiverKey(JSON.stringify(packageData.publicKey, null, 2))
      setResult(undefined)
      setMessage('Package loaded. It is ready to verify on this PC.')
    } catch {
      setMessage('Could not load this file. Select a valid signed package JSON file.')
    }
  }

  const scenario = (kind: 'original' | 'document' | 'key' | 'both') => {
    if (!signedPackage) return
    const changedDocument = kind === 'document' || kind === 'both'
    const changedKey = kind === 'key' || kind === 'both'
    const originalBytes = signedPackage.payloadBase64 ? base64ToBytes(signedPackage.payloadBase64) : stringToBytes(signedPackage.document)
    const tamperedBytes = changedDocument ? new Uint8Array([...originalBytes, 0]) : originalBytes
    setReceiverBytes(tamperedBytes)
    setReceiverDocument(changedDocument ? `${signedPackage.document} [tampered]` : signedPackage.document)
    const tamperedKey = { ...signedPackage.publicKey, alg: 'PS256-TAMPERED' }
    setReceiverKey(changedKey ? JSON.stringify(tamperedKey, null, 2) : JSON.stringify(signedPackage.publicKey, null, 2))
    setResult(undefined)
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand"><span>Document Verification</span></div>
        <span className="mode"><span className="live-dot" /> secure verification</span>
      </header>
      <section className="hero">
        <p className="eyebrow">PUBLIC KEY CRYPTOGRAPHY / RSA-PSS + SHA-256</p>
        <h1>Trust, made <em>visible.</em></h1>
        <p className="subtitle">Create a signed document, verify its integrity, and identify changes to the document or public key.</p>
        <div className="pipeline">{['Input', 'Hash', 'CRC', 'Sign', 'Package', 'Tamper', 'Verify', 'Diagnose'].map((step, index) => <span className={index < (signedPackage ? 5 : 1) ? 'complete' : ''} key={step}><b>{String(index + 1).padStart(2, '0')}</b>{step}{index < 7 && <i>→</i>}</span>)}</div>
      </section>
      <div className="workspace">
        <section className="panel signer">
          <div className="panel-heading"><div><span className="kicker">01 / SIGNER</span><h2>Create a signed package</h2></div><span className="status-pill">{keyPair ? 'KEY READY' : 'WAITING'}</span></div>
          <label>Document or file<textarea value={document} onChange={(event) => { const value = event.target.value; setDocument(value); setDocumentBytes(stringToBytes(value)); setFileName('document.txt'); setMimeType('text/plain'); setResult(undefined) }} /></label>
          <div className="file-picker"><button className="load-package" onClick={() => signerFileInput.current?.click()}>Choose file</button><span>{fileName} · {formatBytes(documentBytes.byteLength)}</span></div>
          <input ref={signerFileInput} className="file-input" type="file" accept=".pdf,.txt,.csv,.json,.xml,.html,.md,.doc,.docx,.xls,.xlsx,.ppt,.pptx,image/*,application/pdf,application/zip" onChange={(event) => { const file = event.target.files?.[0]; if (file) void readFile(file); event.target.value = '' }} />
          <div className="key-row"><span className="key-icon">⌁</span><div><strong>RSA-PSS 2048</strong><small>SHA-256 digest · 32 byte salt</small></div><button className="secondary" onClick={async () => { const pair = await generateKeyPair(); setKeyPair(pair); setPublicKey(await exportPublicKey(pair.publicKey)); setMessage('New key pair generated.'); }}>Generate new key</button></div>
          <button className="primary full" disabled={busy} onClick={createPackage}>{busy ? 'Working…' : 'Create signed package'} <span>→</span></button>
          {publicKey && <div className="value-grid"><Value label="SHA-256 digest" value={signedPackage?.digest ?? '—'} /><Value label="Document CRC-32" value={signedPackage?.documentCrc ?? '—'} /><Value label="Public key CRC-32" value={signedPackage?.publicKeyCrc ?? '—'} /><Value label="Private key" value="EXCLUDED" accent /></div>}
          {signedPackage && <button className="download" onClick={() => downloadPackage(signedPackage, 'signed-package.json', 'Original signed package downloaded. You can attach it to an email or transfer it to another PC.')}>Download signed package <span>↓</span></button>}
          {publicKey && <details><summary>View public key (JWK)</summary><pre>{JSON.stringify(publicKey, null, 2)}</pre></details>}
        </section>
        <section className="panel receiver">
          <div className="panel-heading"><div><span className="kicker">02 / RECEIVER</span><h2>Inspect and verify</h2></div><div className="receiver-actions"><button className="load-top" onClick={() => packageInput.current?.click()}>Load package</button><span className="status-pill receiver-pill">RECEIVER</span></div></div>
          {signedPackage ? <><div className="scenario-bar"><span>Verification options</span><button onClick={() => scenario('original')}>Original</button><button onClick={() => scenario('document')}>Tamper document</button><button onClick={() => scenario('key')}>Tamper key</button><button onClick={() => scenario('both')}>Tamper both</button></div><label>Received document or file<textarea value={receiverDocument} onChange={(event) => { const value = event.target.value; setReceiverDocument(value); setReceiverBytes(stringToBytes(value)); setReceiverFileName('document.txt'); setReceiverMimeType('text/plain'); setResult(undefined) }} /></label><div className="file-picker"><button className="load-package" onClick={() => receiverFileInput.current?.click()}>Replace file</button><span>{receiverFileName} · {formatBytes(receiverBytes.byteLength)}</span></div><input ref={receiverFileInput} className="file-input" type="file" accept=".pdf,.txt,.csv,.json,.xml,.html,.md,.doc,.docx,.xls,.xlsx,.ppt,.pptx,image/*,application/pdf,application/zip" onChange={(event) => { const file = event.target.files?.[0]; if (file) void readFile(file, true); event.target.value = '' }} /><label>Received public key<textarea className="key-textarea" value={receiverKey} onChange={(event) => { setReceiverKey(event.target.value); setResult(undefined) }} /></label><button className="verify" disabled={busy} onClick={verify}>Verify package <span>↗</span></button><button className="download" onClick={downloadReceiverFile}>Download file only <span>↓</span></button><button className="download" onClick={downloadCurrentPackage}>Download current values <span>↓</span></button>{result && <Result result={result} />}</> : <div className="empty"><span>◎</span><p>Load a signed package to verify it here<br /><button className="load-package" onClick={() => packageInput.current?.click()}>Choose package file</button></p></div>}
          <input ref={packageInput} className="file-input" type="file" accept=".json,application/json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importPackage(file); event.target.value = '' }} />
        </section>
      </div>
      <footer><span><b>INTEGRITY</b> CRC helps identify changes; it is not a security control.</span><span>Authenticity is provided by the digital signature.</span></footer>
      {message && <div className="toast">{message}</div>}
    </main>
  )
}

function Value({ label, value, accent = false }: { label: string; value: string; accent?: boolean }) {
  return <div className="value"><span>{label}</span><strong className={accent ? 'accent' : ''}>{value}</strong></div>
}

function Result({ result }: { result: VerificationResult }) {
  const good = result.signatureValid && result.documentCrcMatches && result.publicKeyCrcMatches
  return <div className={`result ${good ? 'good' : 'bad'}`}><div className="result-top"><span className="result-icon">{good ? '✓' : '!'}</span><div><span className="kicker">VERIFICATION RESULT</span><h3>{good ? 'Authentic & intact' : 'Verification failed'}</h3></div></div><div className="checks"><Check label="Digital signature" value={result.signatureValid} /><Check label="Document CRC-32" value={result.documentCrcMatches} /><Check label="Public key CRC-32" value={result.publicKeyCrcMatches} /></div><p>{result.diagnosis}</p></div>
}

function Check({ label, value }: { label: string; value: boolean }) {
  return <span><i className={value ? 'yes' : 'no'}>{value ? '✓' : '×'}</i>{label}</span>
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export default App
