// =============================================================================
// SUS: the Simplest Underlay Server
// =============================================================================
//
// A complete, dependency-free Underlay server in one file. Run it with:
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
// WHAT THIS IMPLEMENTS
//   The full Underlay protocol (underlay.org/protocol): the four primitives
//   (records, schemas, versions, files); record and version identity including
//   public-hash addressing; the negotiate push (negotiate -> send records ->
//   commit); pull (manifest, delta, /records/batch); schema semantics with
//   unknown-field rejection / strip_unknown_fields; files; provenance; and
//   collaboration (optimistic locking, diff, fork).
//
// WHAT THIS LEAVES OUT (platform, not protocol)
//   - Auth / orgs / API keys / rate limits -> everything is open; ownership is
//     just a slug. Since anyone can already read, write, and delete, SUS treats
//     every caller as the owner and serves the full view (private types,
//     records, and fields included). Public hashes are still computed and the
//     filtered public documents are still stored, so a record resolves by
//     either its private or its public hash.
//   - Postgres + S3            -> the filesystem is the store (hash = filename)
//   - Full ajv JSON Schema     -> a ~30-line structural validator
//   - ARK identifiers, mirror sync, SQL query console, discussion threads
//
// =============================================================================

import { createHash, randomUUID } from 'node:crypto'
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
// RESPONSE HELPERS. Operations return { status, json }; the dispatcher sends it.
// =============================================================================

const ok = (json, status = 200) => ({ status, json })
const err = (status, error, extra) => ({ status, json: { error, ...extra } })

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

// Fields present in the record but not declared in the schema's properties.
// The protocol rejects these (422) unless strip_unknown_fields is set.
function findExtraFields(data, schema) {
  const props = schema?.properties
  if (!props || typeof data !== 'object' || data === null || Array.isArray(data)) return []
  return Object.keys(data).filter((k) => !(k in props))
}

function stripToSchema(data, schema) {
  const props = schema?.properties ?? {}
  const out = {}
  for (const k of Object.keys(data)) if (k in props) out[k] = data[k]
  return out
}

// =============================================================================
// CONTENT-ADDRESSED STORE. The filesystem is the database.
//
//   sus-data/
//     records/<sha256>.json   one record object { id, type, data }
//     schemas/<sha256>.json   one schema body
//     files/<sha256>          one binary blob   (+ <sha256>.type = content type)
//     collections/<owner>/<slug>/
//       meta.json             { name, public, createdAt }
//       v1.0.0.json           a version manifest (lists the hashes above)
//
// Deduplication is just "does this file already exist?". A version is a small
// manifest that points at shared, content-addressed records, schemas, and files.
// =============================================================================

const HERE = dirname(fileURLToPath(import.meta.url))
const DATA = process.env.SUS_DATA || join(HERE, 'sus-data')
const RECORDS = join(DATA, 'records')
const SCHEMAS = join(DATA, 'schemas')
const FILES = join(DATA, 'files')
const COLLECTIONS = join(DATA, 'collections')

// Hard cap on the on-disk store. This is a shared demo box, so the server
// refuses pushes once the store reaches this size. Default 1 GiB.
const MAX_BYTES = Number(process.env.SUS_MAX_BYTES) || 1024 * 1024 * 1024

function ensureDirs() {
  for (const d of [RECORDS, SCHEMAS, FILES, COLLECTIONS]) mkdirSync(d, { recursive: true })
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

// Returns a 507 response when the store is at capacity, otherwise null.
function storageFull() {
  const storage = storageInfo()
  if (!storage.full) return null
  return err(
    507,
    `storage full. This demo is capped at ${storage.maxMB} MB. Delete a collection to free space.`,
    { storage },
  )
}

// Delete a collection and sweep any records/schemas no other version still
// references. Content addressing means the same record can be shared across
// collections, so we only remove what has become unreferenced.
function deleteCollection(owner, slug) {
  const dir = collDir(owner, slug)
  if (!existsSync(join(dir, 'meta.json'))) return err(404, 'collection not found')
  rmSync(dir, { recursive: true, force: true })
  const ownerDir = join(COLLECTIONS, owner)
  if (existsSync(ownerDir) && readdirSync(ownerDir).length === 0) {
    rmSync(ownerDir, { recursive: true, force: true })
  }

  const usedRecords = new Set()
  const usedSchemas = new Set()
  const usedFiles = new Set()
  for (const c of listCollections()) {
    for (const v of listVersions(c.owner, c.slug)) {
      for (const r of v.records ?? []) {
        if (r.hash) usedRecords.add(r.hash)
        if (r.publicHash) usedRecords.add(r.publicHash)
      }
      for (const h of Object.values(v.schemas ?? {})) usedSchemas.add(h)
      for (const h of Object.values(v.publicSchemas ?? {})) usedSchemas.add(h)
      for (const h of v.files ?? []) usedFiles.add(h)
    }
  }
  let recordsRemoved = 0
  let schemasRemoved = 0
  let filesRemoved = 0
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
  for (const f of existsSync(FILES) ? readdirSync(FILES) : []) {
    if (!usedFiles.has(f.replace(/\.type$/, ''))) {
      rmSync(join(FILES, f))
      if (!f.endsWith('.type')) filesRemoved++
    }
  }
  return ok({
    deleted: `${owner}/${slug}`,
    gc: { recordsRemoved, schemasRemoved, filesRemoved },
    storage: storageInfo(),
  })
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

function recordExists(hash) {
  return existsSync(join(RECORDS, `${hash}.json`))
}

// --- Files (content-addressed binary blobs) ---

function hashBytes(buf) {
  return createHash('sha256').update(buf).digest('hex')
}

// File hashes may travel with a "sha256:" prefix; storage keys never do.
function normalizeFileHash(h) {
  return String(h).replace(/^sha256:/, '')
}

function fileExists(hash) {
  return existsSync(join(FILES, normalizeFileHash(hash)))
}

function putFile(hash, buf, mimeType) {
  const h = normalizeFileHash(hash)
  const existed = fileExists(h)
  if (!existed) {
    writeFileSync(join(FILES, h), buf)
    writeFileSync(join(FILES, `${h}.type`), mimeType || 'application/octet-stream')
  }
  return existed
}

function getFile(hash) {
  const h = normalizeFileHash(hash)
  const path = join(FILES, h)
  if (!existsSync(path)) return null
  const buf = readFileSync(path)
  const typePath = join(FILES, `${h}.type`)
  const mimeType = existsSync(typePath)
    ? readFileSync(typePath, 'utf-8')
    : 'application/octet-stream'
  return { buf, mimeType, size: buf.length }
}

// Collect every {"$file":"sha256:..."} reference reachable in a record's data.
function extractFileRefs(value, out = new Set()) {
  if (value === null || typeof value !== 'object') return out
  if (Array.isArray(value)) {
    for (const v of value) extractFileRefs(v, out)
    return out
  }
  if (typeof value.$file === 'string') out.add(normalizeFileHash(value.$file))
  for (const v of Object.values(value)) extractFileRefs(v, out)
  return out
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
    return err(422, 'owner and slug must match /^[a-z0-9][a-z0-9-]*$/')
  }
  const dir = collDir(owner, slug)
  if (existsSync(join(dir, 'meta.json'))) {
    return err(409, `collection ${owner}/${slug} already exists`)
  }
  mkdirSync(dir, { recursive: true })
  const meta = {
    name: body.name || slug,
    public: body.public !== false,
    createdAt: new Date().toISOString(),
  }
  writeFileSync(join(dir, 'meta.json'), JSON.stringify(meta, null, 2))
  return ok({ owner, slug, ...meta })
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

// --- Read views (owner) ---
//
// SUS has no authentication and lets anyone read, write, and delete, so it
// treats every caller as the collection owner: reads return the full view,
// including private types, private records, and private fields. The public
// hashes are still computed (they are part of a version's identity) and the
// filtered public documents are still stored, so a record resolves by either
// its private or its public hash — but nothing is hidden on read.

function manifestRecords(version) {
  return (version.records ?? []).map((r) => ({ id: r.id, type: r.type, hash: r.hash }))
}

function versionView(v) {
  return {
    semver: v.semver,
    hash: v.hash,
    publicHash: v.publicHash,
    baseSemver: v.baseSemver,
    message: v.message,
    metadata: v.metadata ?? null,
    schemas: v.schemas ?? {},
    recordCount: (v.records ?? []).length,
    fileCount: (v.files ?? []).length,
    createdAt: v.createdAt,
  }
}

function diffManifests(fromRecords, toRecords) {
  const fromById = new Map(fromRecords.map((r) => [r.id, r]))
  const toById = new Map(toRecords.map((r) => [r.id, r]))
  const added = []
  const updated = []
  const removed = []
  for (const r of toRecords) {
    const f = fromById.get(r.id)
    if (!f) added.push(r)
    else if (f.hash !== r.hash) updated.push({ ...r, previousHash: f.hash })
  }
  for (const r of fromRecords) if (!toById.has(r.id)) removed.push(r)
  return { added, updated, removed }
}

// Shared commit path. Validates, stores content-addressed schemas/records/files
// (plus public projections), enforces optimistic locking on base_version,
// derives the semver, and writes the immutable version manifest. Both the
// one-shot /push and the negotiate /commit funnel through here, so they produce
// byte-identical version hashes.
function commitVersion(opts) {
  const {
    owner,
    slug,
    schemas: schemasIn = {},
    records: recordsIn = [],
    fileHashes = [],
    baseSemver = null,
    message = null,
    metadata = null,
    appId = null,
    actorId = null,
    stripUnknownFields = false,
  } = opts

  if (!getMeta(owner, slug)) return err(404, `collection ${owner}/${slug} not found`)
  const full = storageFull()
  if (full) return full
  if (!recordsIn.length && !Object.keys(schemasIn).length) {
    return err(422, 'push must include at least one schema or record')
  }

  // Optimistic locking: base_version must match the current latest version.
  const versions = listVersions(owner, slug)
  const prev = versions.length ? versions[versions.length - 1] : null
  const currentSemver = prev?.semver ?? null
  if ((baseSemver ?? null) !== currentSemver) {
    return err(409, 'Version conflict', { currentVersion: currentSemver, statusCode: 409 })
  }

  // Validate against schemas; collect extra fields (reject, or strip on request).
  const errors = []
  const extraByRecord = []
  const cleaned = [] // { id, type, data, private }
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
    let data = rec.data
    const extra = findExtraFields(rec.data, schema)
    if (extra.length) {
      if (stripUnknownFields) data = stripToSchema(rec.data, schema)
      else extraByRecord.push({ recordId: rec.id, type: rec.type, fields: extra })
    }
    cleaned.push({ id: rec.id, type: rec.type, data, private: rec.private === true })
  }
  if (errors.length) return err(422, 'validation failed', { errors })
  if (extraByRecord.length) {
    return err(422, 'Records contain fields not defined in schema', {
      extraFields: extraByRecord,
      statusCode: 422,
    })
  }

  // Every referenced file ($file refs + declared file list) must already exist.
  const referenced = new Set(fileHashes.map(normalizeFileHash))
  for (const rec of cleaned) for (const h of extractFileRefs(rec.data)) referenced.add(h)
  const missingFiles = [...referenced].filter((h) => !fileExists(h))
  if (missingFiles.length) {
    return err(422, 'Missing files', {
      filesNeeded: missingFiles.map((h) => `sha256:${h}`),
      statusCode: 422,
    })
  }
  const allFiles = [...referenced]

  // Store schemas (full) and their public projections.
  const schemaSet = []
  const schemaEntries = []
  let schemasNew = 0
  for (const [typeSlug, schemaBody] of Object.entries(schemasIn)) {
    const h = hashSchema(schemaBody)
    if (!putContent(SCHEMAS, h, schemaBody)) schemasNew++
    schemaSet.push({ slug: typeSlug, schemaHash: h })
    schemaEntries.push({ slug: typeSlug, schema: schemaBody })
  }
  const privateTypes = getPrivateTypes(schemaEntries)
  const publicSchemas = {}
  for (const entry of schemaEntries) {
    if (privateTypes.has(entry.slug)) continue
    const filtered = filterTypeSchema(entry.schema)
    const ph = hashSchema(filtered)
    putContent(SCHEMAS, ph, filtered)
    publicSchemas[entry.slug] = ph
  }

  // Store records (full) and, when a type has private fields, the public
  // projection under its public hash so public readers can resolve it.
  const recordHashes = []
  const recordRows = []
  const manifestRecords = []
  let recordsNew = 0
  for (const rec of cleaned) {
    const { hash } = hashRecord({ id: rec.id, type: rec.type, data: rec.data })
    if (!putContent(RECORDS, hash, { id: rec.id, type: rec.type, data: rec.data })) recordsNew++
    recordHashes.push(hash)
    recordRows.push({ recordId: rec.id, type: rec.type, data: rec.data, private: rec.private })

    const privFields = getPrivateFields(schemasIn[rec.type] ?? {})
    const pubData = privFields.size ? filterRecordData(rec.data, privFields) : rec.data
    const publicHash = privFields.size
      ? hashRecord({ id: rec.id, type: rec.type, data: pubData }).hash
      : hash
    if (publicHash !== hash) {
      putContent(RECORDS, publicHash, { id: rec.id, type: rec.type, data: pubData })
    }
    manifestRecords.push({ id: rec.id, type: rec.type, hash, publicHash, private: rec.private })
  }
  const uniqueRecordHashes = [...new Set(recordHashes)]

  const versionHash = computeVersionHash(schemaSet, uniqueRecordHashes, allFiles, metadata)
  if (prev && prev.hash === versionHash) {
    return err(409, `no changes. Identical content to ${prev.semver}`, { hash: versionHash })
  }
  const publicHash = computePublicHash(schemaEntries, recordRows, allFiles, metadata)

  const schemaChanged = !prev || !sameSchemas(prev.schemas, schemaSet)
  const recordsChanged =
    !prev ||
    !sameSet(
      (prev.records ?? []).map((r) => r.hash),
      uniqueRecordHashes,
    ) ||
    !sameSet(prev.files ?? [], allFiles)
  const next = deriveSemver(prev?.semver ?? null, schemaChanged, recordsChanged)

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
    appId,
    actorId,
    schemas: Object.fromEntries(schemaSet.map((s) => [s.slug, s.schemaHash])),
    publicSchemas,
    records: manifestRecords,
    files: allFiles,
    recordCount: manifestRecords.length,
    fileCount: allFiles.length,
    createdAt: new Date().toISOString(),
  }
  writeVersion(owner, slug, manifest)

  return ok({
    manifest,
    bump: schemaChanged ? 'major' : recordsChanged ? 'minor' : 'patch',
    dedup: {
      recordsReceived: recordsIn.length,
      recordsStored: recordsNew,
      recordsDeduped: recordsIn.length - recordsNew,
      schemasStored: schemasNew,
    },
  })
}

// One-shot push (convenience, used by the web console). Defaults base_version to
// the current latest so the simple path never conflicts; a real client uses the
// negotiate flow below. Both share commitVersion, so hashes are identical.
function pushVersion(owner, slug, body) {
  const latest = listVersions(owner, slug).slice(-1)[0]?.semver ?? null
  const result = commitVersion({
    owner,
    slug,
    schemas: body?.schemas ?? {},
    records: body?.records ?? [],
    fileHashes: body?.files ?? [],
    baseSemver: body?.base_version ?? body?.baseSemver ?? latest,
    message: body?.message ?? null,
    metadata: body?.metadata ?? null,
    appId: body?.app_id ?? null,
    actorId: body?.actor_id ?? null,
    stripUnknownFields: body?.strip_unknown_fields === true,
  })
  if (result.status !== 200) return result
  const { manifest, bump, dedup } = result.json
  return ok({ version: versionSummary(manifest), bump, dedup })
}

// =============================================================================
// PUSH: the negotiate protocol (negotiate -> send records -> commit).
// Sessions are in-memory and expire after 10 minutes, per the spec.
// =============================================================================

const SESSION_TTL_MS = 10 * 60 * 1000
const sessions = new Map()

function pruneSessions() {
  const now = Date.now()
  for (const [id, s] of sessions) if (s.expiresAt <= now) sessions.delete(id)
}

function getSession(owner, slug, sessionId) {
  pruneSessions()
  const s = sessions.get(sessionId)
  if (!s || s.owner !== owner || s.slug !== slug) return null
  return s
}

function negotiate(owner, slug, body) {
  if (!getMeta(owner, slug)) return err(404, `collection ${owner}/${slug} not found`)
  pruneSessions()
  const manifest = body?.manifest ?? [] // [{ id, type, hash, private? }]
  const files = (body?.files ?? []).map(normalizeFileHash)
  const neededRecords = manifest.filter((m) => !recordExists(m.hash)).map((m) => m.hash)
  const neededFiles = files.filter((h) => !fileExists(h))

  const id = randomUUID()
  sessions.set(id, {
    owner,
    slug,
    baseSemver: body?.base_version ?? null,
    schemas: body?.schemas ?? {},
    manifest,
    files,
    message: body?.message ?? null,
    metadata: body?.metadata ?? null,
    appId: body?.app_id ?? null,
    actorId: body?.actor_id ?? null,
    stripUnknownFields: body?.strip_unknown_fields === true,
    needed: new Set(neededRecords),
    expiresAt: Date.now() + SESSION_TTL_MS,
  })
  return ok({
    session_id: id,
    needed_records: neededRecords,
    needed_files: neededFiles.map((h) => `sha256:${h}`),
    total_records: manifest.length,
    total_files: files.length,
    already_have_records: manifest.length - neededRecords.length,
    already_have_files: files.length - neededFiles.length,
  })
}

function negotiateRecords(owner, slug, sessionId, ndjson) {
  const s = getSession(owner, slug, sessionId)
  if (!s) return err(404, 'session not found or expired')
  const lines = ndjson
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
  let received = 0
  for (const line of lines) {
    let rec
    try {
      rec = JSON.parse(line)
    } catch {
      return err(400, 'invalid JSONL line')
    }
    if (!rec || !rec.id || !rec.type) return err(400, 'record missing id/type')
    const { hash } = hashRecord({ id: rec.id, type: rec.type, data: rec.data })
    if (s.needed.has(hash)) {
      putContent(RECORDS, hash, { id: rec.id, type: rec.type, data: rec.data })
      s.needed.delete(hash)
      received++
    } else if (!s.manifest.some((m) => m.hash === hash)) {
      return err(400, 'Unexpected record hash', { hash, statusCode: 400 })
    }
  }
  return ok({ received, remaining: s.needed.size })
}

function negotiateCommit(owner, slug, sessionId) {
  const s = getSession(owner, slug, sessionId)
  if (!s) return err(404, 'session not found or expired')
  if (s.needed.size) {
    return err(400, 'Missing records', { missing_hashes: [...s.needed], statusCode: 400 })
  }
  // Rebuild the full record set from the content store (everything is present now).
  const records = []
  for (const m of s.manifest) {
    const doc = getContent(RECORDS, m.hash)
    if (!doc) return err(400, 'Missing records', { missing_hashes: [m.hash], statusCode: 400 })
    records.push({ id: doc.id, type: doc.type, data: doc.data, private: m.private === true })
  }
  const result = commitVersion({
    owner,
    slug,
    schemas: s.schemas,
    records,
    fileHashes: s.files,
    baseSemver: s.baseSemver,
    message: s.message,
    metadata: s.metadata,
    appId: s.appId,
    actorId: s.actorId,
    stripUnknownFields: s.stripUnknownFields,
  })
  if (result.status !== 200) return result
  sessions.delete(sessionId)
  const m = result.json.manifest
  return ok(
    { semver: m.semver, hash: m.hash, recordCount: m.recordCount, fileCount: m.fileCount },
    201,
  )
}

function sessionStatus(owner, slug, sessionId) {
  const s = getSession(owner, slug, sessionId)
  if (!s) return err(404, 'session not found or expired')
  return ok({
    session_id: sessionId,
    total_records: s.manifest.length,
    needed_records: [...s.needed],
    remaining: s.needed.size,
    expiresAt: new Date(s.expiresAt).toISOString(),
  })
}

function cancelSession(owner, slug, sessionId) {
  const s = getSession(owner, slug, sessionId)
  if (!s) return err(404, 'session not found or expired')
  sessions.delete(sessionId)
  return ok(null, 204)
}

// =============================================================================
// FILES, PULL, PROVENANCE, FORK
// =============================================================================

function uploadFile(owner, slug, hashParam, buf, mimeType) {
  if (!getMeta(owner, slug)) return err(404, `collection ${owner}/${slug} not found`)
  const full = storageFull()
  if (full) return full
  const want = normalizeFileHash(hashParam)
  const got = hashBytes(buf)
  if (got !== want)
    return err(400, 'hash mismatch', { expected: want, actual: got, statusCode: 400 })
  const existed = putFile(got, buf, mimeType)
  return ok({ hash: `sha256:${got}`, size: buf.length, deduplicated: existed }, existed ? 200 : 201)
}

function listVersionFiles(owner, slug, semver) {
  const v = findVersion(owner, slug, semver)
  if (!v) return err(404, 'version not found')
  const files = (v.files ?? []).map((h) => {
    const f = getFile(h)
    return { hash: `sha256:${h}`, size: f?.size ?? null, contentType: f?.mimeType ?? null }
  })
  return ok({ semver: v.semver, files })
}

function getManifest(owner, slug, semver, since) {
  const v = findVersion(owner, slug, semver)
  if (!v) return err(404, 'version not found')
  const records = manifestRecords(v)
  if (since) {
    const from = findVersion(owner, slug, since)
    if (!from) return err(404, `since version ${since} not found`)
    return ok({
      version: v.semver,
      since: from.semver,
      delta: diffManifests(manifestRecords(from), records),
    })
  }
  return ok({
    semver: v.semver,
    hash: v.hash,
    schemas: v.schemas ?? {},
    records,
    files: (v.files ?? []).map((h) => `sha256:${h}`),
  })
}

function getDiff(owner, slug, semver, from) {
  const to = findVersion(owner, slug, semver)
  if (!to) return err(404, 'version not found')
  const fromV = findVersion(owner, slug, from)
  if (!fromV) return err(404, `from version ${from} not found`)
  const d = diffManifests(manifestRecords(fromV), manifestRecords(to))
  return ok({ from: fromV.semver, to: to.semver, ...d })
}

function provenance(hash) {
  const references = []
  let recordId = null
  let type = null
  let firstSeen = null
  for (const c of listCollections()) {
    for (const v of listVersions(c.owner, c.slug)) {
      for (const r of v.records ?? []) {
        if (r.hash !== hash && r.publicHash !== hash) continue
        references.push({ owner: c.owner, collection: c.slug, version: v.semver })
        recordId = r.id
        type = r.type
        if (!firstSeen || v.createdAt < firstSeen) firstSeen = v.createdAt
      }
    }
  }
  if (!references.length) return err(404, 'record not found')
  return ok({ hash, recordId, type, firstSeen, references })
}

// Fork copies only the manifest (records/schemas/files are referenced, not
// duplicated). Without orgs, targetOrg is just the new owner slug.
function forkCollection(owner, slug, body) {
  const meta = getMeta(owner, slug)
  if (!meta) return err(404, 'collection not found')
  const targetOwner = body?.targetOrg ?? owner
  const targetSlug = body?.slug ?? slug
  if (!validSlug(targetOwner) || !validSlug(targetSlug)) {
    return err(422, 'targetOrg and slug must match /^[a-z0-9][a-z0-9-]*$/')
  }
  if (getMeta(targetOwner, targetSlug)) {
    return err(409, `collection ${targetOwner}/${targetSlug} already exists`)
  }
  const latest = listVersions(owner, slug).slice(-1)[0] ?? null
  const dir = collDir(targetOwner, targetSlug)
  mkdirSync(dir, { recursive: true })
  const forkedFrom = { owner, slug, version: latest?.semver ?? null }
  writeFileSync(
    join(dir, 'meta.json'),
    JSON.stringify(
      {
        name: body?.name || meta.name,
        public: true,
        createdAt: new Date().toISOString(),
        forkedFrom,
      },
      null,
      2,
    ),
  )
  if (latest) writeVersion(targetOwner, targetSlug, { ...latest })
  return ok({ owner: targetOwner, slug: targetSlug, forkedFrom })
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

function readBytes(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let len = 0
    req.on('data', (c) => {
      chunks.push(c)
      len += c.length
      if (len > 200_000_000) reject(new Error('request body too large'))
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

function readText(req) {
  return new Promise((resolve, reject) => {
    let data = ''
    req.on('data', (c) => {
      data += c
      if (data.length > 200_000_000) reject(new Error('request body too large'))
    })
    req.on('end', () => resolve(data))
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

// JSON routes (GET / POST / DELETE). Binary and NDJSON routes (file
// upload/download, negotiate record batches, /records/batch) are handled
// explicitly in the dispatcher below. Negotiate routes are listed before the
// generic /versions/:semver routes so a literal "negotiate" segment wins.
const routes = [
  ['GET', '/api/health', () => ok({ ok: true, service: 'sus', storage: storageInfo() })],

  ['GET', '/api/collections', () => ok({ collections: listCollections() })],
  ['POST', '/api/collections', (_p, body) => createCollection(body)],
  ['DELETE', '/api/collections/:owner/:slug', ({ owner, slug }) => deleteCollection(owner, slug)],
  [
    'GET',
    '/api/collections/:owner/:slug',
    ({ owner, slug }) => {
      const meta = getMeta(owner, slug)
      if (!meta) return err(404, 'collection not found')
      return ok({ owner, slug, ...meta, versions: listVersions(owner, slug).map(versionSummary) })
    },
  ],

  [
    'POST',
    '/api/collections/:owner/:slug/push',
    ({ owner, slug }, body) => pushVersion(owner, slug, body),
  ],
  [
    'POST',
    '/api/collections/:owner/:slug/fork',
    ({ owner, slug }, body) => forkCollection(owner, slug, body),
  ],

  // Push: negotiate protocol
  [
    'POST',
    '/api/collections/:owner/:slug/versions/negotiate',
    ({ owner, slug }, body) => negotiate(owner, slug, body),
  ],
  [
    'POST',
    '/api/collections/:owner/:slug/versions/negotiate/:sessionId/commit',
    ({ owner, slug, sessionId }) => negotiateCommit(owner, slug, sessionId),
  ],
  [
    'GET',
    '/api/collections/:owner/:slug/versions/negotiate/:sessionId',
    ({ owner, slug, sessionId }) => sessionStatus(owner, slug, sessionId),
  ],
  [
    'DELETE',
    '/api/collections/:owner/:slug/versions/negotiate/:sessionId',
    ({ owner, slug, sessionId }) => cancelSession(owner, slug, sessionId),
  ],

  // Pull
  [
    'GET',
    '/api/collections/:owner/:slug/versions/:semver/manifest',
    ({ owner, slug, semver }, _b, url) =>
      getManifest(owner, slug, semver, url.searchParams.get('since')),
  ],
  [
    'GET',
    '/api/collections/:owner/:slug/versions/:semver/diff',
    ({ owner, slug, semver }, _b, url) =>
      getDiff(owner, slug, semver, url.searchParams.get('from')),
  ],
  [
    'GET',
    '/api/collections/:owner/:slug/versions/:semver/files',
    ({ owner, slug, semver }) => listVersionFiles(owner, slug, semver),
  ],
  [
    'GET',
    '/api/collections/:owner/:slug/versions/:semver/records',
    ({ owner, slug, semver }) => {
      const v = findVersion(owner, slug, semver)
      if (!v) return err(404, 'version not found')
      const records = manifestRecords(v)
        .map((r) => getContent(RECORDS, r.hash))
        .filter(Boolean)
      return ok({ semver: v.semver, records })
    },
  ],
  [
    'GET',
    '/api/collections/:owner/:slug/versions/:semver',
    ({ owner, slug, semver }) => {
      const v = findVersion(owner, slug, semver)
      return v ? ok(versionView(v)) : err(404, 'version not found')
    },
  ],

  // Global content-addressed reads. Any stored hash resolves (everyone is owner).
  ['GET', '/api/records/:hash/provenance', ({ hash }) => provenance(normalizeFileHash(hash))],
  [
    'GET',
    '/api/records/:hash',
    ({ hash }) => {
      const rec = getContent(RECORDS, hash)
      return rec ? ok(rec) : err(404, 'record not found')
    },
  ],
  [
    'GET',
    '/api/schemas/:hash',
    ({ hash }) => {
      const schema = getContent(SCHEMAS, hash)
      return schema ? ok(schema) : err(404, 'schema not found')
    },
  ],
]

const CORS = { 'Access-Control-Allow-Origin': '*' }

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost')

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      ...CORS,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, HEAD, OPTIONS',
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

  try {
    // --- Files: binary upload/download (content-addressed) ---
    const fileMatch = match('/api/collections/:owner/:slug/files/:hash', url.pathname)
    if (fileMatch && (req.method === 'PUT' || req.method === 'GET' || req.method === 'HEAD')) {
      const { owner, slug, hash } = fileMatch
      if (req.method === 'PUT') {
        const buf = await readBytes(req)
        const r = uploadFile(owner, slug, hash, buf, req.headers['content-type'])
        return sendJson(res, r.status, r.json)
      }
      const f = getFile(hash)
      if (!f) {
        if (req.method === 'HEAD') {
          res.writeHead(404, CORS)
          return res.end()
        }
        return sendJson(res, 404, { error: 'file not found' })
      }
      res.writeHead(200, { ...CORS, 'Content-Type': f.mimeType, 'Content-Length': f.size })
      return res.end(req.method === 'HEAD' ? undefined : f.buf)
    }

    // --- Negotiate: receive records as NDJSON ---
    const recMatch = match(
      '/api/collections/:owner/:slug/versions/negotiate/:sessionId/records',
      url.pathname,
    )
    if (recMatch && req.method === 'POST') {
      const text = await readText(req)
      const r = negotiateRecords(recMatch.owner, recMatch.slug, recMatch.sessionId, text)
      return sendJson(res, r.status, r.json)
    }

    // --- Batch record fetch -> NDJSON stream ---
    if (url.pathname === '/api/records/batch' && req.method === 'POST') {
      const body = await readJson(req)
      const lines = (body?.hashes ?? [])
        .map(normalizeFileHash)
        .map((h) => getContent(RECORDS, h))
        .filter(Boolean)
        .map((rec) => JSON.stringify(rec))
      res.writeHead(200, { ...CORS, 'Content-Type': 'application/x-ndjson; charset=utf-8' })
      return res.end(lines.length ? lines.join('\n') + '\n' : '')
    }

    // --- Generic JSON routes ---
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
      const { status, json } = handler(params, body, url)
      if (json === null || status === 204) {
        res.writeHead(status, CORS)
        return res.end()
      }
      return sendJson(res, status, json)
    }
  } catch (e) {
    return sendJson(res, 500, { error: String(e?.message ?? e) })
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

// A black dot centered on white, inlined as an SVG data URI (no asset file).
const FAVICON =
  "data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2032%2032'%3E%3Crect%20width='32'%20height='32'%20fill='white'/%3E%3Ccircle%20cx='16'%20cy='16'%20r='5'%20fill='black'/%3E%3C/svg%3E"

function layout(title, body) {
  return `<!doctype html>
<title>${esc(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="${FAVICON}">
${body}`
}

// Shown at the top of every page except the home page.
const BACK_HOME = '<p><a href="/">← Back to Home</a></p>'

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

<h2 id="notice">⚠️ This is a demo server.</h2>
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
<pre id="agentprompt">The server at https://sus.knowledgefutures.org is an Underlay server.
Read https://sus.knowledgefutures.org for its API, then create a collection and
push some JSON records with a JSON Schema. It needs no authentication. Do not
include any private or sensitive data. Everything you push is public.</pre>
<button onclick="navigator.clipboard.writeText(document.getElementById('agentprompt').textContent)">copy prompt</button>

<hr>
<p><small>This page is server-rendered HTML; the same data is available as JSON
under <code>/api</code> (start at <code>/api/collections</code>). The whole
server is one file you can
<a href="https://github.com/knowledgefutures/demo-sus/blob/main/sus.mjs">read on GitHub</a>.</small></p>`,
    ),
  }
}

function newPage() {
  return {
    status: 200,
    html: layout(
      'New collection · SUS',
      `${BACK_HOME}
<h1>Create a collection</h1>
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
    const records = manifestRecords(latest)
      .map((r) => getContent(RECORDS, r.hash))
      .filter(Boolean)
    recordsHtml = `<h2>Records in ${esc(latest.semver)}</h2>
<pre>${esc(JSON.stringify(records, null, 2))}</pre>`
  }

  return {
    status: 200,
    html: layout(
      `${owner}/${slug} · SUS`,
      `${BACK_HOME}
<h1>${esc(owner)}/${esc(slug)}</h1>
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
      `${BACK_HOME}
<h1>Push a version</h1>
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
      `${BACK_HOME}
<h1>Not found</h1><p>${esc(message || 'No such page.')}</p>`,
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
