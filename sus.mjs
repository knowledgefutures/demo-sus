// =============================================================================
// SUS: the Simplest Underlay Server
// =============================================================================
//
// A complete, dependency-free Underlay node in one file. Run it with:
//
//     node sus.mjs
//
// No npm install, no build step, no database, no cloud services. Records,
// schemas, and versions are stored as content-addressed files on disk under
// ./sus-data (override with SUS_DATA). Open http://localhost:8080 for a plain
// HTML console; the same endpoints are a real HTTP API you can curl.
//
// WHAT THIS IS FAITHFUL ABOUT
//   The content-addressing core below (canonicalize / hashRecord / hashSchema
//   / computeVersionHash / computePublicHash / the privacy filters / semver
//   derivation) is copied VERBATIM from the production server's src/lib/core/.
//   That code IS the protocol's wire contract: two implementations that agree
//   on canonicalization produce byte-identical version hashes and can exchange
//   collections. A version pushed here hashes the same as on the real server.
//
// WHAT THIS LEAVES OUT (on purpose, to stay "simplest")
//   - Auth / orgs / API keys     -> everything is open; ownership is just a slug
//   - Postgres + S3              -> the filesystem is the store (hash = filename)
//   - The negotiate handshake    -> the real server has a two-phase
//                                   negotiate -> upload-missing -> commit flow so
//                                   clients never re-upload content the server
//                                   already has. SUS pushes everything in one
//                                   shot and reports what it deduplicated, which
//                                   shows the same content-addressing behavior.
//   - ajv JSON-Schema validation -> replaced by a ~30-line structural check
//   - ARK identifiers, mirror sync, SQL query console, discussion threads
//
// =============================================================================

import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { createServer } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// =============================================================================
// PROTOCOL CORE. Copied verbatim from src/lib/core/ (TS types stripped).
// Do not "improve" this. Byte-for-byte fidelity here is what makes the hashes
// interoperable with the real server.
// =============================================================================

// --- hash.ts ---------------------------------------------------------------

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(canonicalize)
  const sorted = {}
  for (const key of Object.keys(value).sort()) {
    sorted[key] = canonicalize(value[key])
  }
  return sorted
}

function hashSchema(schemaBody) {
  return createHash('sha256')
    .update(JSON.stringify(canonicalize(schemaBody)))
    .digest('hex')
}

function hashRecord(record) {
  const canonical = JSON.stringify({
    id: record.id,
    type: record.type,
    data: canonicalize(record.data),
  })
  const hash = createHash('sha256').update(canonical).digest('hex')
  return { hash, canonical }
}

// --- semver.ts -------------------------------------------------------------

function parseSemver(semver) {
  const parts = semver.replace(/^v/, '').split('.').map(Number)
  const [major, minor, patch] = [parts[0] ?? 1, parts[1] ?? 0, parts[2] ?? 0]
  return { semver: `v${major}.${minor}.${patch}`, major, minor, patch }
}

function compareSemver(a, b) {
  const pa = parseSemver(a)
  const pb = parseSemver(b)
  return pa.major - pb.major || pa.minor - pb.minor || pa.patch - pb.patch
}

function deriveSemver(prevSemver, schemaChanged, recordsChanged) {
  if (!prevSemver) return { semver: 'v1.0.0', major: 1, minor: 0, patch: 0 }
  const { major, minor, patch } = parseSemver(prevSemver)
  if (schemaChanged) return { semver: `v${major + 1}.0.0`, major: major + 1, minor: 0, patch: 0 }
  if (recordsChanged)
    return { semver: `v${major}.${minor + 1}.0`, major, minor: minor + 1, patch: 0 }
  return { semver: `v${major}.${minor}.${patch + 1}`, major, minor, patch: patch + 1 }
}

// --- privacy.ts ------------------------------------------------------------

function getPrivateTypes(schemaEntries) {
  const types = new Set()
  for (const entry of schemaEntries) {
    if (entry.schema?.private === true) types.add(entry.slug)
  }
  return types
}

function getPrivateFields(typeSchema) {
  const fields = new Set()
  const props = typeSchema?.properties
  if (!props) return fields
  for (const [fieldName, fieldDef] of Object.entries(props)) {
    if (fieldDef?.private === true) fields.add(fieldName)
  }
  return fields
}

function filterRecordData(data, privateFields) {
  if (privateFields.size === 0 || typeof data !== 'object' || data === null) return data
  const filtered = {}
  for (const [key, value] of Object.entries(data)) {
    if (!privateFields.has(key)) filtered[key] = value
  }
  return filtered
}

function filterTypeSchema(typeSchema) {
  const props = typeSchema?.properties
  if (!props) return typeSchema
  const publicProps = {}
  for (const [fieldName, fieldDef] of Object.entries(props)) {
    if (fieldDef?.private === true) continue
    publicProps[fieldName] = fieldDef
  }
  const required = typeSchema.required?.filter((f) => !(props[f]?.private === true))
  return { ...typeSchema, properties: publicProps, required }
}

// --- version-hash.ts -------------------------------------------------------

function computeVersionHash(schemaSet, recordHashes, fileHashes, metadata) {
  const canonical = JSON.stringify({
    schemas: Object.fromEntries(
      [...schemaSet]
        .sort((a, b) => a.slug.localeCompare(b.slug))
        .map((s) => [s.slug, s.schemaHash]),
    ),
    records: [...recordHashes].sort(),
    files: [...fileHashes].sort(),
    metadata: metadata ? canonicalize(metadata) : null,
  })
  return 'private:' + createHash('sha256').update(canonical).digest('hex')
}

function computePublicHash(schemaEntries, recordRows, fileHashes, metadata) {
  const privateTypes = getPrivateTypes(schemaEntries)

  const publicSchemaSet = []
  for (const entry of schemaEntries) {
    if (privateTypes.has(entry.slug)) continue
    const filtered = filterTypeSchema(entry.schema)
    publicSchemaSet.push({ slug: entry.slug, schemaHash: hashSchema(filtered) })
  }

  const publicRecordHashes = recordRows
    .filter((r) => !r.private && !privateTypes.has(r.type))
    .map((r) => {
      const entry = schemaEntries.find((e) => e.slug === r.type)
      const privateFields = entry ? getPrivateFields(entry.schema) : new Set()
      const data = privateFields.size > 0 ? filterRecordData(r.data, privateFields) : r.data
      return hashRecord({ id: r.recordId, type: r.type, data }).hash
    })

  return computeVersionHash(publicSchemaSet, publicRecordHashes, fileHashes, metadata).replace(
    'private:',
    'public:',
  )
}

// =============================================================================
// MINIMAL VALIDATION. Stands in for ajv. Structural only: required fields
// present, and declared primitive types match. The real server runs full
// JSON Schema. Good enough to keep a demo honest without a dependency.
// =============================================================================

function matchesType(value, type) {
  switch (type) {
    case 'string':
      return typeof value === 'string'
    case 'number':
      return typeof value === 'number'
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value)
    case 'boolean':
      return typeof value === 'boolean'
    case 'object':
      return typeof value === 'object' && value !== null && !Array.isArray(value)
    case 'array':
      return Array.isArray(value)
    case 'null':
      return value === null
    default:
      return true // unknown/union types pass (minimal checker)
  }
}

function validateRecord(record, schema) {
  const errors = []
  if (typeof record.data !== 'object' || record.data === null || Array.isArray(record.data)) {
    return ['data must be an object']
  }
  const props = schema?.properties ?? {}
  for (const req of schema?.required ?? []) {
    if (!(req in record.data)) errors.push(`missing required field "${req}"`)
  }
  for (const [key, value] of Object.entries(record.data)) {
    const def = props[key]
    if (!def || !def.type) continue
    if (!matchesType(value, def.type)) errors.push(`field "${key}" should be ${def.type}`)
  }
  return errors
}

// =============================================================================
// CONTENT-ADDRESSED STORE. The filesystem is the database.
//
//   sus-data/
//     records/<sha256>.json   one record object { id, type, data }
//     schemas/<sha256>.json   one schema body
//     collections/<owner>/<slug>/
//       meta.json             { name, public, createdAt }
//       v1.0.0.json           a version manifest (lists the hashes above)
//
// Deduplication is just "does this file already exist?". A version is a small
// manifest that points at shared, content-addressed records and schemas.
// =============================================================================

const HERE = dirname(fileURLToPath(import.meta.url))
const DATA = process.env.SUS_DATA || join(HERE, 'sus-data')
const RECORDS = join(DATA, 'records')
const SCHEMAS = join(DATA, 'schemas')
const COLLECTIONS = join(DATA, 'collections')

// Hard cap on the on-disk store. This is a shared demo box, so the server
// refuses pushes once the store reaches this size. Default 1 GiB.
const MAX_BYTES = Number(process.env.SUS_MAX_BYTES) || 1024 * 1024 * 1024

function ensureDirs() {
  for (const d of [RECORDS, SCHEMAS, COLLECTIONS]) mkdirSync(d, { recursive: true })
}

function dirSize(dir) {
  if (!existsSync(dir)) return 0
  let total = 0
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name)
    total += entry.isDirectory() ? dirSize(p) : statSync(p).size
  }
  return total
}

function storageInfo() {
  const used = dirSize(DATA)
  return {
    usedBytes: used,
    maxBytes: MAX_BYTES,
    usedMB: +(used / 1048576).toFixed(1),
    maxMB: Math.round(MAX_BYTES / 1048576),
    full: used >= MAX_BYTES,
  }
}

// Delete a collection and sweep any records/schemas no other version still
// references. Content addressing means the same record can be shared across
// collections, so we only remove what has become unreferenced.
function deleteCollection(owner, slug) {
  const dir = collDir(owner, slug)
  if (!existsSync(join(dir, 'meta.json'))) {
    return { status: 404, json: { error: 'collection not found' } }
  }
  rmSync(dir, { recursive: true, force: true })
  const ownerDir = join(COLLECTIONS, owner)
  if (existsSync(ownerDir) && readdirSync(ownerDir).length === 0) {
    rmSync(ownerDir, { recursive: true, force: true })
  }

  const usedRecords = new Set()
  const usedSchemas = new Set()
  for (const c of listCollections()) {
    for (const v of listVersions(c.owner, c.slug)) {
      for (const h of v.records ?? []) usedRecords.add(h)
      for (const h of Object.values(v.schemas ?? {})) usedSchemas.add(h)
    }
  }
  let recordsRemoved = 0
  let schemasRemoved = 0
  for (const f of existsSync(RECORDS) ? readdirSync(RECORDS) : []) {
    if (!usedRecords.has(f.replace(/\.json$/, ''))) {
      rmSync(join(RECORDS, f))
      recordsRemoved++
    }
  }
  for (const f of existsSync(SCHEMAS) ? readdirSync(SCHEMAS) : []) {
    if (!usedSchemas.has(f.replace(/\.json$/, ''))) {
      rmSync(join(SCHEMAS, f))
      schemasRemoved++
    }
  }
  return {
    status: 200,
    json: {
      deleted: `${owner}/${slug}`,
      gc: { recordsRemoved, schemasRemoved },
      storage: storageInfo(),
    },
  }
}

// Write content under its hash. Returns true if it was already there (a dedup hit).
function putContent(dir, hash, body) {
  const path = join(dir, `${hash}.json`)
  const existed = existsSync(path)
  if (!existed) writeFileSync(path, JSON.stringify(body))
  return existed
}

function getContent(dir, hash) {
  const path = join(dir, `${hash}.json`)
  if (!existsSync(path)) return null
  return JSON.parse(readFileSync(path, 'utf-8'))
}

function validSlug(s) {
  return typeof s === 'string' && /^[a-z0-9][a-z0-9-]*$/.test(s)
}

function collDir(owner, slug) {
  return join(COLLECTIONS, owner, slug)
}

function getMeta(owner, slug) {
  const path = join(collDir(owner, slug), 'meta.json')
  if (!existsSync(path)) return null
  return JSON.parse(readFileSync(path, 'utf-8'))
}

function listVersions(owner, slug) {
  const dir = collDir(owner, slug)
  if (!existsSync(dir)) return []
  const files = readdirSync(dir).filter((f) => f.endsWith('.json') && f !== 'meta.json')
  const versions = files.map((f) => JSON.parse(readFileSync(join(dir, f), 'utf-8')))
  versions.sort((a, b) => compareSemver(a.semver, b.semver))
  return versions
}

function writeVersion(owner, slug, manifest) {
  writeFileSync(
    join(collDir(owner, slug), `${manifest.semver}.json`),
    JSON.stringify(manifest, null, 2),
  )
}

function listCollections() {
  const out = []
  if (!existsSync(COLLECTIONS)) return out
  for (const owner of readdirSync(COLLECTIONS)) {
    const ownerDir = join(COLLECTIONS, owner)
    if (!readdirSync(ownerDir)) continue
    for (const slug of readdirSync(ownerDir)) {
      const meta = getMeta(owner, slug)
      if (meta) out.push({ owner, slug, ...meta, versionCount: listVersions(owner, slug).length })
    }
  }
  return out
}

function findVersion(owner, slug, semver) {
  const versions = listVersions(owner, slug)
  if (!versions.length) return null
  if (semver === 'latest') return versions[versions.length - 1]
  const norm = parseSemver(semver).semver
  return versions.find((v) => v.semver === norm) ?? null
}

function versionSummary(v) {
  return {
    semver: v.semver,
    hash: v.hash,
    publicHash: v.publicHash,
    baseSemver: v.baseSemver,
    message: v.message,
    recordCount: v.recordCount,
    createdAt: v.createdAt,
  }
}

// =============================================================================
// OPERATIONS
// =============================================================================

function createCollection(body) {
  const { owner, slug } = body ?? {}
  if (!validSlug(owner) || !validSlug(slug)) {
    return { status: 422, json: { error: 'owner and slug must match /^[a-z0-9][a-z0-9-]*$/' } }
  }
  const dir = collDir(owner, slug)
  if (existsSync(join(dir, 'meta.json'))) {
    return { status: 409, json: { error: `collection ${owner}/${slug} already exists` } }
  }
  mkdirSync(dir, { recursive: true })
  const meta = {
    name: body.name || slug,
    public: body.public !== false,
    createdAt: new Date().toISOString(),
  }
  writeFileSync(join(dir, 'meta.json'), JSON.stringify(meta, null, 2))
  return { status: 200, json: { owner, slug, ...meta } }
}

function sameSchemas(prevMap, schemaSet) {
  const keys = Object.keys(prevMap ?? {})
  if (keys.length !== schemaSet.length) return false
  for (const s of schemaSet) if (prevMap[s.slug] !== s.schemaHash) return false
  return true
}

function sameSet(a, b) {
  if (a.length !== b.length) return false
  const set = new Set(a)
  for (const x of b) if (!set.has(x)) return false
  return true
}

// One-shot push. The real server splits this into negotiate/upload/commit so
// clients skip re-uploading content the server already has; here we accept it
// all and report what was deduplicated. The version hash is identical either way.
function pushVersion(owner, slug, body) {
  if (!getMeta(owner, slug)) {
    return { status: 404, json: { error: `collection ${owner}/${slug} not found` } }
  }
  const storage = storageInfo()
  if (storage.full) {
    return {
      status: 507,
      json: {
        error: `storage full. This demo is capped at ${storage.maxMB} MB. Delete an old collection to free space.`,
        storage,
      },
    }
  }
  const schemasIn = body?.schemas ?? {} // { typeSlug: schemaBody }
  const recordsIn = body?.records ?? [] // [{ id, type, data, private? }]
  const metadata = body?.metadata ?? null
  const message = body?.message ?? null

  if (!recordsIn.length && !Object.keys(schemasIn).length) {
    return { status: 422, json: { error: 'push must include at least one schema or record' } }
  }

  // 1. Validate every record against its declared type schema.
  const errors = []
  for (const rec of recordsIn) {
    if (!rec.id || !rec.type) {
      errors.push('every record needs an "id" and a "type"')
      continue
    }
    const schema = schemasIn[rec.type]
    if (!schema) {
      errors.push(`record "${rec.id}" has type "${rec.type}" but no schema was provided for it`)
      continue
    }
    for (const e of validateRecord(rec, schema)) errors.push(`${rec.id}: ${e}`)
  }
  if (errors.length) return { status: 422, json: { error: 'validation failed', errors } }

  // 2. Store schemas content-addressed (dedup).
  const schemaSet = [] // [{ slug, schemaHash }]
  const schemaEntries = [] // [{ slug, schema }], for the public-hash computation
  let schemasNew = 0
  for (const [typeSlug, schemaBody] of Object.entries(schemasIn)) {
    const h = hashSchema(schemaBody)
    if (!putContent(SCHEMAS, h, schemaBody)) schemasNew++
    schemaSet.push({ slug: typeSlug, schemaHash: h })
    schemaEntries.push({ slug: typeSlug, schema: schemaBody })
  }

  // 3. Store records content-addressed (dedup).
  const recordHashes = []
  const recordRows = []
  let recordsNew = 0
  for (const rec of recordsIn) {
    const { hash } = hashRecord({ id: rec.id, type: rec.type, data: rec.data })
    if (!putContent(RECORDS, hash, { id: rec.id, type: rec.type, data: rec.data })) recordsNew++
    recordHashes.push(hash)
    recordRows.push({
      recordId: rec.id,
      type: rec.type,
      data: rec.data,
      private: rec.private === true,
    })
  }
  const uniqueRecordHashes = [...new Set(recordHashes)]

  // 4. Compare against the previous version to decide the semver bump.
  const versions = listVersions(owner, slug)
  const prev = versions.length ? versions[versions.length - 1] : null
  const schemaChanged = !prev || !sameSchemas(prev.schemas, schemaSet)
  const recordsChanged = !prev || !sameSet(prev.records ?? [], uniqueRecordHashes)

  // 5. The content-address of the whole version.
  const fileHashes = [] // files are out of scope for SUS
  const versionHash = computeVersionHash(schemaSet, uniqueRecordHashes, fileHashes, metadata)
  if (prev && prev.hash === versionHash) {
    return {
      status: 409,
      json: { error: `no changes. Identical content to ${prev.semver}`, hash: versionHash },
    }
  }

  const next = deriveSemver(prev?.semver ?? null, schemaChanged, recordsChanged)
  const publicHash = computePublicHash(schemaEntries, recordRows, fileHashes, metadata)

  const manifest = {
    semver: next.semver,
    major: next.major,
    minor: next.minor,
    patch: next.patch,
    hash: versionHash,
    publicHash,
    baseSemver: prev?.semver ?? null,
    message,
    metadata,
    schemas: Object.fromEntries(schemaSet.map((s) => [s.slug, s.schemaHash])),
    records: uniqueRecordHashes,
    files: fileHashes,
    recordCount: uniqueRecordHashes.length,
    fileCount: 0,
    createdAt: new Date().toISOString(),
  }
  writeVersion(owner, slug, manifest)

  return {
    status: 200,
    json: {
      version: versionSummary(manifest),
      bump: schemaChanged
        ? 'major (schema changed)'
        : recordsChanged
          ? 'minor (records changed)'
          : 'patch',
      dedup: {
        recordsReceived: recordsIn.length,
        recordsStored: recordsNew,
        recordsDeduped: recordsIn.length - recordsNew,
        schemasStored: schemasNew,
      },
    },
  }
}

// =============================================================================
// HTTP. Raw node:http, a tiny router, no framework.
// =============================================================================

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = ''
    req.on('data', (c) => {
      data += c
      if (data.length > 50_000_000) reject(new Error('request body too large'))
    })
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {})
      } catch {
        reject(new Error('invalid JSON body'))
      }
    })
    req.on('error', reject)
  })
}

function sendJson(res, status, obj) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
  })
  res.end(JSON.stringify(obj, null, 2))
}

function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(html)
}

// Match "/api/collections/:owner/:slug" against a path, returning params or null.
function match(pattern, pathname) {
  const pp = pattern.split('/').filter(Boolean)
  const ph = pathname.split('/').filter(Boolean)
  if (pp.length !== ph.length) return null
  const params = {}
  for (let i = 0; i < pp.length; i++) {
    if (pp[i].startsWith(':')) params[pp[i].slice(1)] = decodeURIComponent(ph[i])
    else if (pp[i] !== ph[i]) return null
  }
  return params
}

const routes = [
  [
    'GET',
    '/api/health',
    () => ({ status: 200, json: { ok: true, service: 'sus', storage: storageInfo() } }),
  ],

  ['GET', '/api/collections', () => ({ status: 200, json: { collections: listCollections() } })],

  ['POST', '/api/collections', (_p, body) => createCollection(body)],

  ['DELETE', '/api/collections/:owner/:slug', ({ owner, slug }) => deleteCollection(owner, slug)],

  [
    'GET',
    '/api/collections/:owner/:slug',
    ({ owner, slug }) => {
      const meta = getMeta(owner, slug)
      if (!meta) return { status: 404, json: { error: 'collection not found' } }
      return {
        status: 200,
        json: { owner, slug, ...meta, versions: listVersions(owner, slug).map(versionSummary) },
      }
    },
  ],

  [
    'POST',
    '/api/collections/:owner/:slug/push',
    ({ owner, slug }, body) => pushVersion(owner, slug, body),
  ],

  [
    'GET',
    '/api/collections/:owner/:slug/versions/:semver',
    ({ owner, slug, semver }) => {
      const v = findVersion(owner, slug, semver)
      if (!v) return { status: 404, json: { error: 'version not found' } }
      return { status: 200, json: v }
    },
  ],

  [
    'GET',
    '/api/collections/:owner/:slug/versions/:semver/records',
    ({ owner, slug, semver }) => {
      const v = findVersion(owner, slug, semver)
      if (!v) return { status: 404, json: { error: 'version not found' } }
      const records = v.records.map((h) => getContent(RECORDS, h)).filter(Boolean)
      return { status: 200, json: { semver: v.semver, records } }
    },
  ],

  [
    'GET',
    '/api/records/:hash',
    ({ hash }) => {
      const rec = getContent(RECORDS, hash)
      return rec ? { status: 200, json: rec } : { status: 404, json: { error: 'record not found' } }
    },
  ],

  [
    'GET',
    '/api/schemas/:hash',
    ({ hash }) => {
      const schema = getContent(SCHEMAS, hash)
      return schema
        ? { status: 200, json: schema }
        : { status: 404, json: { error: 'schema not found' } }
    },
  ],
]

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost')

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    })
    return res.end()
  }

  // Server-rendered HTML pages (real URLs, no SPA). Returns null for /api/*,
  // which then falls through to the JSON API below.
  if (req.method === 'GET') {
    const page = renderHtml(url.pathname)
    if (page) return sendHtml(res, page.status, page.html)
  }

  for (const [method, pattern, handler] of routes) {
    if (method !== req.method) continue
    const params = match(pattern, url.pathname)
    if (!params) continue
    let body = null
    if (req.method === 'POST') {
      try {
        body = await readJson(req)
      } catch (e) {
        return sendJson(res, 400, { error: e.message })
      }
    }
    try {
      const { status, json } = handler(params, body, url)
      return sendJson(res, status, json)
    } catch (e) {
      return sendJson(res, 500, { error: String(e?.message ?? e) })
    }
  }

  return sendJson(res, 404, { error: 'not found' })
})

// =============================================================================
// THE HTML CONSOLE. Server-rendered pages, one per route. No SPA, no client
// router: real URLs and <a> links. Reads need no JavaScript; only the three
// mutations (create / push / delete) use a few lines of fetch.
// =============================================================================

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function layout(title, body) {
  return `<!doctype html>
<title>${esc(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
${body}`
}

function homePage() {
  const s = storageInfo()
  const cols = listCollections()
  const list = cols.length
    ? '<ul>' +
      cols
        .map(
          (c) =>
            `<li><a href="/c/${esc(c.owner)}/${esc(c.slug)}">${esc(c.owner)}/${esc(c.slug)}</a>` +
            `, ${esc(c.name)} (${c.versionCount} version${c.versionCount === 1 ? '' : 's'})</li>`,
        )
        .join('') +
      '</ul>'
    : '<p><i>No collections yet.</i></p>'

  return {
    status: 200,
    html: layout(
      'SUS · Simplest Underlay Server',
      `<h1>SUS · the Simplest Underlay Server</h1>
<p><b>Suspiciously simple, yet full-featured. A complete Underlay server in a
<a href="https://github.com/knowledgefutures/demo-sus/blob/main/sus.mjs">single file</a> with zero dependencies.</b></p>
<p>
  <a href="https://underlay.org">underlay.org</a> ·
  <a href="https://underlay.org/protocol">protocol</a> ·
  <a href="https://underlay.org/docs">docs</a> ·
  <a href="https://github.com/knowledgefutures/demo-sus">github</a>
  
</p>

<p><b>What is Underlay?</b> A protocol for giving structured data a permanent
address: you push JSON records and a JSON Schema, and get back a versioned,
content-addressed snapshot you can point to forever. Every record, schema, and
file is identified by its SHA-256 hash; versions are manifests of those hashes;
storage is deduplicated globally and provenance is built in. The canonical
documentation and the reference servers live at
<a href="https://underlay.org">underlay.org</a>, maintained by
<a href="https://www.knowledgefutures.org">Knowledge Futures</a>.</p>

<h2 id="notice">⚠️ This is a demo server. Read this first.</h2>
<ul>
  <li><b>No authentication.</b> Everything here is public and world-readable.
  <b>Do not push anything private, sensitive, or personal.</b></li>
  <li><b>Anyone can delete anything.</b> As a courtesy, please don't delete
  collections less than 24 hours old. Only reach for delete if space is short.</li>
  <li><b>Storage is capped.</b> ${s.usedMB} MB of ${s.maxMB} MB used${
    s.full ? ' (FULL, pushes refused)' : ''
  }. When it fills, pushes are refused until someone frees space.</li>
</ul>

<hr>

<h2>Collections</h2>
${list}
<p><a href="/new">＋ new collection</a></p>

<hr>

<h2>Point an agent at it</h2>
<p>Hand your agent this and let it push a collection:</p>
<pre id="agentprompt">The server at https://sus.knowledgefutures.org is an Underlay node.
Read https://sus.knowledgefutures.org for its API, then create a collection and
push some JSON records with a JSON Schema. It needs no authentication. Do not
include any private or sensitive data. Everything you push is public.</pre>
<button onclick="navigator.clipboard.writeText(document.getElementById('agentprompt').textContent)">copy prompt</button>

<hr>
<p><small>This page is server-rendered HTML; the same data is available as JSON
under <code>/api</code> (start at <code>/api/collections</code>). The whole
server is one file you can
<a href="https://github.com/knowledgefutures/demo-sus">read on GitHub</a>.</small></p>`,
    ),
  }
}

function newPage() {
  return {
    status: 200,
    html: layout(
      'New collection · SUS',
      `<h1>Create a collection</h1>
<p>owner <input id="owner" value="demo"></p>
<p>slug &nbsp;<input id="slug" value="people"></p>
<p>name <input id="name" value="People"></p>
<button onclick="create()">create</button>
<p><a href="/">← all collections</a></p>
<pre id="out"></pre>
<script>
async function create() {
  var owner = document.getElementById('owner').value;
  var slug = document.getElementById('slug').value;
  var body = { owner: owner, slug: slug, name: document.getElementById('name').value };
  var r = await fetch('/api/collections', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  if (r.ok) { location.href = '/c/' + owner + '/' + slug; return; }
  document.getElementById('out').textContent = JSON.stringify(await r.json(), null, 2);
}
</script>`,
    ),
  }
}

function collectionPage(owner, slug) {
  const meta = getMeta(owner, slug)
  if (!meta) return notFoundPage(`No collection ${owner}/${slug}.`)

  const versions = listVersions(owner, slug)
  let versionsHtml
  let recordsHtml = ''
  if (!versions.length) {
    versionsHtml = '<p><i>No versions yet.</i></p>'
  } else {
    versionsHtml =
      '<ul>' +
      versions
        .map(
          (v) =>
            `<li><b>${esc(v.semver)}</b>${v.message ? ': ' + esc(v.message) : ''}<br>
        <small>hash: <code>${esc(v.hash)}</code><br>
        publicHash: <code>${esc(v.publicHash)}</code><br>
        ${v.recordCount} record${v.recordCount === 1 ? '' : 's'}</small></li>`,
        )
        .join('') +
      '</ul>'
    const latest = versions[versions.length - 1]
    const records = latest.records.map((h) => getContent(RECORDS, h)).filter(Boolean)
    recordsHtml = `<h2>Records in ${esc(latest.semver)}</h2>
<pre>${esc(JSON.stringify(records, null, 2))}</pre>`
  }

  return {
    status: 200,
    html: layout(
      `${owner}/${slug} · SUS`,
      `<h1>${esc(owner)}/${esc(slug)}</h1>
<p>${esc(meta.name)}</p>
<p><a href="/c/${esc(owner)}/${esc(slug)}/push">push a version →</a></p>

<h2>Versions</h2>
${versionsHtml}
${recordsHtml}

<hr>
<p>
  <a href="/">← all collections</a> &nbsp;·&nbsp;
  <button onclick="del()">delete this collection</button>
</p>
<pre id="out"></pre>
<script>
async function del() {
  if (!confirm('Delete ${esc(owner)}/${esc(slug)}?\\n\\nThere is no auth, so this affects everyone. Please avoid deleting collections newer than 24 hours unless space is short.')) return;
  var r = await fetch('/api/collections/${esc(owner)}/${esc(slug)}', { method: 'DELETE' });
  if (r.ok) { location.href = '/'; return; }
  document.getElementById('out').textContent = JSON.stringify(await r.json(), null, 2);
}
</script>`,
    ),
  }
}

function pushPage(owner, slug) {
  const meta = getMeta(owner, slug)
  if (!meta) return notFoundPage(`No collection ${owner}/${slug}.`)

  return {
    status: 200,
    html: layout(
      `Push to ${owner}/${slug} · SUS`,
      `<h1>Push a version</h1>
<p>to <a href="/c/${esc(owner)}/${esc(slug)}">${esc(owner)}/${esc(slug)}</a></p>
<p>Body: a JSON Schema per type, plus records. A field or whole type marked
<code>"private": true</code> is stripped from the public hash. Watch
<code>publicHash</code> differ from <code>hash</code> in the result.</p>
<textarea id="body" rows="22" cols="90"></textarea>
<br>
<button onclick="push()">push</button>
<p><a href="/c/${esc(owner)}/${esc(slug)}">← back to collection</a></p>
<h2>Result</h2>
<pre id="out">(push to see the result)</pre>
<script>
var EXAMPLE = {
  message: 'initial import',
  schemas: { person: { type: 'object', properties: {
    name: { type: 'string' }, age: { type: 'integer' }, email: { type: 'string', private: true }
  }, required: ['name'] } },
  records: [
    { id: 'alice', type: 'person', data: { name: 'Alice', age: 30, email: 'alice@example.com' } },
    { id: 'bob', type: 'person', data: { name: 'Bob', age: 25, email: 'bob@example.com' } }
  ]
};
document.getElementById('body').value = JSON.stringify(EXAMPLE, null, 2);
async function push() {
  var body;
  try { body = JSON.parse(document.getElementById('body').value); }
  catch (e) { document.getElementById('out').textContent = 'Body is not valid JSON: ' + e.message; return; }
  var r = await fetch('/api/collections/${esc(owner)}/${esc(slug)}/push', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
  });
  document.getElementById('out').textContent = JSON.stringify(await r.json(), null, 2);
}
</script>`,
    ),
  }
}

function notFoundPage(message) {
  return {
    status: 404,
    html: layout(
      'Not found · SUS',
      `<h1>Not found</h1><p>${esc(message || 'No such page.')}</p><p><a href="/">← home</a></p>`,
    ),
  }
}

// GET dispatcher for HTML pages. Returns null for /api/* so the JSON API runs.
function renderHtml(pathname) {
  if (pathname === '/api' || pathname.startsWith('/api/')) return null
  if (pathname === '/') return homePage()
  if (pathname === '/new') return newPage()
  const push = match('/c/:owner/:slug/push', pathname)
  if (push) return pushPage(push.owner, push.slug)
  const coll = match('/c/:owner/:slug', pathname)
  if (coll) return collectionPage(coll.owner, coll.slug)
  return notFoundPage('No such page: ' + pathname)
}

// =============================================================================
// BOOT
// =============================================================================

ensureDirs()
const PORT = Number(process.env.PORT) || 8080
server.listen(PORT, () => {
  console.log('SUS · Simplest Underlay Server')
  console.log(`  console : http://localhost:${PORT}`)
  console.log(`  api     : http://localhost:${PORT}/api/collections`)
  console.log(`  store   : ${DATA}`)
  console.log(`  cap     : ${Math.round(MAX_BYTES / 1048576)} MB (SUS_MAX_BYTES)`)
})
