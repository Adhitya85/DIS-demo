import { createServer } from 'node:http'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const port = Number(process.env.KEY_SERVER_PORT || 8787)
const dataDirectory = join(process.cwd(), 'data')
const keyPath = join(dataDirectory, 'private-key.json')

function send(response, status, body) {
  response.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': 'http://localhost:5173',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  })
  response.end(JSON.stringify(body))
}

const server = createServer(async (request, response) => {
  if (request.method === 'OPTIONS') {
    send(response, 204, {})
    return
  }
  if (request.url !== '/api/private-key') {
    send(response, 404, { error: 'Not found' })
    return
  }
  try {
    if (request.method === 'GET') {
      try {
        send(response, 200, { key: JSON.parse(await readFile(keyPath, 'utf8')) })
      } catch (error) {
        if (error?.code === 'ENOENT') {
          send(response, 200, { key: null })
          return
        }
        throw error
      }
      return
    }
    if (request.method === 'POST') {
      let body = ''
      for await (const chunk of request) body += chunk
      const payload = JSON.parse(body)
      if (!payload.key || payload.key.kty !== 'RSA' || typeof payload.key.d !== 'string') {
        send(response, 400, { error: 'Invalid RSA private JWK' })
        return
      }
      await mkdir(dataDirectory, { recursive: true })
      await writeFile(keyPath, `${JSON.stringify(payload.key, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
      send(response, 200, { saved: true })
      return
    }
    send(response, 405, { error: 'Method not allowed' })
  } catch {
    send(response, 500, { error: 'Unable to access the private-key store' })
  }
})

server.listen(port, 'localhost', () => {
  console.log(`Private-key store listening on http://localhost:${port}`)
})
